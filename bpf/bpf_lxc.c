#include <node_config.h>
#include <lxc_config.h>

#define EVENT_SOURCE LXC_ID

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include <linux/icmpv6.h>
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/arp.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/lxc.h"
#include "lib/nat46.h"
#include "lib/policy.h"
#include "lib/drop.h"
#include "lib/dbg.h"

__BPF_MAP(CT_MAP6, BPF_MAP_TYPE_HASH, 0, sizeof(struct ipv6_ct_tuple),
	  sizeof(struct ct_entry), PIN_GLOBAL_NS, CT_MAP_SIZE);
__BPF_MAP(CT_MAP4, BPF_MAP_TYPE_HASH, 0, sizeof(struct ipv4_ct_tuple),
	  sizeof(struct ct_entry), PIN_GLOBAL_NS, CT_MAP_SIZE);

#ifndef DISABLE_PORT_MAP
static inline void map_lxc_out(struct __sk_buff *skb, int l4_off, __u8 nexthdr)
{
	int i;
	struct portmap local_map[] = {
#ifdef LXC_PORT_MAPPINGS
		LXC_PORT_MAPPINGS
#endif
	};

#define NR_PORTMAPS (sizeof(local_map) / sizeof(local_map[0]))

#pragma unroll
	for (i = 0; i < NR_PORTMAPS; i++)
		do_port_map_out(skb, l4_off, &local_map[i], nexthdr);
}
#else
static inline void map_lxc_out(struct __sk_buff *skb, int l4_off, __u8 nexthdr)
{
}
#endif /* DISABLE_PORT_MAP */

#ifdef ENCAP_IFINDEX
static inline int __inline__ lxc_encap(struct __sk_buff *skb, __u32 node_id)
{
#ifdef ENCAP_GENEVE
	uint8_t buf[] = GENEVE_OPTS;
#else
	uint8_t buf[] = {};
#endif
	return do_encapsulation(skb, node_id, SECLABEL_NB, buf, sizeof(buf));
}
#endif

static inline int ipv6_l3_from_lxc(struct __sk_buff *skb,
				   struct ipv6_ct_tuple *tuple, int nh_off,
				   struct ethhdr *eth, struct ipv6hdr *ip6)
{
	union macaddr router_mac = NODE_MAC;
	union v6addr host_ip = HOST_IP;
	union v6addr *dst = (union v6addr *) &ip6->daddr;
	int do_nat46 = 0, ret;

	if (unlikely(!valid_src_mac(eth)))
		return DROP_INVALID_SMAC;
	else if (unlikely(!valid_dst_mac(eth)))
		return DROP_INVALID_DMAC;
	else if (unlikely(!valid_src_ip(ip6)))
		return DROP_INVALID_SIP;

	/* The tuple is created in reverse order initially to find a
	 * potential reverse flow. This is required because the RELATED
	 * or REPLY state takes precedence over ESTABLISHED due to
	 * policy requirements.
	 *
	 * Depending on direction, either source or destination address
	 * is assumed to be the address of the container. Therefore,
	 * the source address for incoming respectively the destination
	 * address for outgoing packets is stored in a single field in
	 * the tuple. The TUPLE_F_OUT and TUPLE_F_IN flags indicate which
	 * address the field currently represents.
	 */
	ipv6_addr_copy(&tuple->addr, (union v6addr *) &ip6->daddr);

	/* FIXME: Handle extensions header size */
	map_lxc_out(skb, nh_off + sizeof(*ip6), ip6->nexthdr);

	/* Pass all outgoing packets through conntrack. This will create an
	 * entry to allow reverse packets and return set cb[CB_POLICY] to
	 * POLICY_SKIP if the packet is a reply packet to an existing
	 * incoming connection. */
	ret = ct_lookup6(&CT_MAP6, tuple, skb, ETH_HLEN, SECLABEL, 0);
	if (ret < 0)
		return ret;

	switch (ret) {
	case CT_NEW:
		ct_create6(&CT_MAP6, tuple, skb, 0);
		break;

	case CT_ESTABLISHED:
		break;

	case CT_RELATED:
	case CT_REPLY:
		skb->cb[CB_POLICY] = POLICY_SKIP;
		break;

	default:
		return DROP_POLICY;
	}

	/* Check if destination is within our cluster prefix */
	if (ipv6_match_subnet_96(dst, &host_ip)) {
		__u32 node_id = ipv6_derive_node_id(dst);

		if (node_id != NODE_ID) {
#ifdef ENCAP_IFINDEX
			return lxc_encap(skb, node_id);
#else
			/* Packets to other nodes are always allowed, the remote
			 * node will enforce the policy.
			 */
			policy_mark_skip(skb);
			goto pass_to_stack;
#endif
		}

#ifdef HOST_IFINDEX
		if (dst->addr[14] == host_ip.addr[14] &&
		    dst->addr[15] == host_ip.addr[15])
			goto to_host;
#endif

		return ipv6_local_delivery(skb, nh_off, dst, SECLABEL, ip6);
	} else {
#ifdef ENABLE_NAT46
		/* FIXME: Derive from prefix constant */
		if (unlikely((dst->p1 & 0xffff) == 0xadde)) {
			do_nat46 = 1;
			goto to_host;
		}
#endif

#ifdef ALLOW_TO_WORLD
		policy_mark_skip(skb);
#endif
		goto pass_to_stack;
	}

to_host:
	if (1) {
		union macaddr host_mac = HOST_IFINDEX_MAC;
		int ret;

		ret = ipv6_l3(skb, nh_off, (__u8 *) &router_mac.addr, (__u8 *) &host_mac.addr);
		if (ret != TC_ACT_OK)
			return ret;

		if (do_nat46) {
			union v6addr dp = NAT46_DST_PREFIX;

			ret = ipv6_to_ipv4(skb, 14, &dp, IPV4_RANGE | (LXC_ID_NB <<16));
			if (IS_ERR(ret))
				return ret;
		}

#ifndef POLICY_ENFORCEMENT
		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return redirect(HOST_IFINDEX, 0);
#else
		skb->cb[CB_SRC_LABEL] = SECLABEL;
		skb->cb[CB_IFINDEX] = HOST_IFINDEX;

#ifdef ALLOW_TO_HOST
		policy_mark_skip(skb);
#endif

		tail_call(skb, &cilium_policy, HOST_ID);
		return DROP_MISSED_TAIL_CALL;
#endif
	}

pass_to_stack:
	if (1) {
		int ret;

		ret = ipv6_l3(skb, nh_off, NULL, (__u8 *) &router_mac.addr);
		if (unlikely(ret != TC_ACT_OK))
			return ret;

		ipv6_store_flowlabel(skb, nh_off, SECLABEL_NB);
	}

#ifndef POLICY_ENFORCEMENT
	/* No policy, pass directly down to stack */
	cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, 0);
	return TC_ACT_OK;
#else
	skb->cb[CB_SRC_LABEL] = SECLABEL;
	skb->cb[CB_IFINDEX] = 0; /* Indicate passing to stack */

	tail_call(skb, &cilium_policy, WORLD_ID);
	return DROP_MISSED_TAIL_CALL;
#endif
}

static inline int handle_ipv6(struct __sk_buff *skb)
{
	struct ipv6_ct_tuple tuple = {};
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	struct ethhdr *eth = data;
	int ret;

	if (data + sizeof(struct ipv6hdr) + ETH_HLEN > data_end)
		return DROP_INVALID;

	/* Handle special ICMPv6 messages. This includes echo requests to the
	 * logical router address, neighbour advertisements to the router.
	 * All remaining packets are subjected to forwarding into the container.
	 */
	if (unlikely(ip6->nexthdr == IPPROTO_ICMPV6)) {
		if (data + sizeof(*ip6) + ETH_HLEN + sizeof(struct icmp6hdr) > data_end) {
			return DROP_INVALID;
		}

		ret = icmp6_handle(skb, ETH_HLEN, ip6);
		if (IS_ERR(ret))
			return ret;
	}

	/* Perform L3 action on the frame */
	tuple.nexthdr = ip6->nexthdr;
	return ipv6_l3_from_lxc(skb, &tuple, ETH_HLEN, eth, ip6);
}

static inline int handle_ipv4(struct __sk_buff *skb)
{
	struct ipv4_ct_tuple tuple = {};
	union macaddr router_mac = NODE_MAC;
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct iphdr *ip4 = data + ETH_HLEN;
	struct ethhdr *eth = data;
	int ret, l3_off = ETH_HLEN, l4_off;

	if (data + sizeof(*ip4) + ETH_HLEN > data_end)
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;

	if (unlikely(!valid_src_mac(eth)))
		return DROP_INVALID_SMAC;
	else if (unlikely(!valid_dst_mac(eth)))
		return DROP_INVALID_DMAC;
	else if (unlikely(!valid_src_ipv4(ip4)))
		return DROP_INVALID_SIP;

	/* The tuple is created in reverse order initially to find a
	 * potential reverse flow. This is required because the RELATED
	 * or REPLY state takes precedence over ESTABLISHED due to
	 * policy requirements.
	 *
	 * Depending on direction, either source or destination address
	 * is assumed to be the address of the container. Therefore,
	 * the source address for incoming respectively the destination
	 * address for outgoing packets is stored in a single field in
	 * the tuple. The TUPLE_F_OUT and TUPLE_F_IN flags indicate which
	 * address the field currently represents.
	 */
	tuple.addr = ip4->daddr;
	l4_off = l3_off + ipv4_hdrlen(ip4);
	map_lxc_out(skb, l4_off, ip4->protocol);

	/* Pass all outgoing packets through conntrack. This will create an
	 * entry to allow reverse packets and return set cb[CB_POLICY] to
	 * POLICY_SKIP if the packet is a reply packet to an existing
	 * incoming connection. */
	ret = ct_lookup4(&CT_MAP4, &tuple, skb, l4_off, SECLABEL, 0);
	if (ret < 0)
		return ret;

	switch (ret) {
	case CT_NEW:
		ct_create4(&CT_MAP4, &tuple, skb, 0);
		break;

	case CT_ESTABLISHED:
		break;

	case CT_RELATED:
	case CT_REPLY:
		skb->cb[CB_POLICY] = POLICY_SKIP;
		break;

	default:
		return DROP_POLICY;
	}

	/* Check if destination is within our cluster prefix */
	if ((tuple.addr & IPV4_CLUSTER_MASK) == IPV4_CLUSTER_RANGE) {
		__u32 node_id = tuple.addr & IPV4_MASK;

		if (node_id != IPV4_RANGE) {
#ifdef ENCAP_IFINDEX
			/* 10.X.0.0 => 10.X.0.1 */
			node_id |= 1;
			return lxc_encap(skb, node_id);
#else
			/* Packets to other nodes are always allowed, the remote
			 * node will enforce the policy.
			 */
			policy_mark_skip(skb);
			goto pass_to_stack;
#endif
		}

		cilium_trace(skb, DBG_GENERIC, tuple.addr, IPV4_GATEWAY);
#ifdef HOST_IFINDEX
		if (tuple.addr == IPV4_GATEWAY)
			goto to_host;
#endif

		return ipv4_local_delivery(skb, l3_off, l4_off, SECLABEL, ip4);
	} else {
#ifdef ALLOW_TO_WORLD
		policy_mark_skip(skb);
#endif
		goto pass_to_stack;
	}

to_host:
	if (1) {
		union macaddr host_mac = HOST_IFINDEX_MAC;
		int ret;

		ret = ipv4_l3(skb, l4_off, (__u8 *) &router_mac.addr, (__u8 *) &host_mac.addr, ip4);
		if (ret != TC_ACT_OK)
			return ret;

#ifndef POLICY_ENFORCEMENT
		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return redirect(HOST_IFINDEX, 0);
#else
		skb->cb[CB_SRC_LABEL] = SECLABEL;
		skb->cb[CB_IFINDEX] = HOST_IFINDEX;

#ifdef ALLOW_TO_HOST
		policy_mark_skip(skb);
#endif

		tail_call(skb, &cilium_policy, HOST_ID);
		return DROP_MISSED_TAIL_CALL;
#endif
	}

pass_to_stack:
	if (1) {
		int ret;

		ret = ipv4_l3(skb, l3_off, NULL, (__u8 *) &router_mac.addr, ip4);
		if (unlikely(ret != TC_ACT_OK))
			return ret;

		ipv6_store_flowlabel(skb, l3_off, SECLABEL_NB);
	}

#ifndef POLICY_ENFORCEMENT
	/* No policy, pass directly down to stack */
	cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, 0);
	return TC_ACT_OK;
#else
	skb->cb[CB_SRC_LABEL] = SECLABEL;
	skb->cb[CB_IFINDEX] = 0; /* Indicate passing to stack */

	tail_call(skb, &cilium_policy, WORLD_ID);
	return DROP_MISSED_TAIL_CALL;
#endif
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4) int tail_handle_ipv4(struct __sk_buff *skb)
{
	int ret = handle_ipv4(skb);

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);

	return ret;
}

/*
 * ARP responder for ARP requests from container
 * Respond to IPV4_GATEWAY with NODE_MAC
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_ARP) int tail_handle_arp(struct __sk_buff *skb)
{
	union macaddr mac = NODE_MAC;
	return arp_respond(skb, &mac, IPV4_GATEWAY);
}

__section("from-container")
int handle_ingress(struct __sk_buff *skb)
{
	int ret;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_LXC, skb->ingress_ifindex);

	switch (skb->protocol) {
	case __constant_htons(ETH_P_IPV6):
		/* This is considered the fast path, no tail call */
		ret = handle_ipv6(skb);
		break;

	case __constant_htons(ETH_P_IP):
		tail_call(skb, &cilium_calls, CILIUM_CALL_IPV4);
		ret = DROP_MISSED_TAIL_CALL;
		break;

	case __constant_htons(ETH_P_ARP):
		tail_call(skb, &cilium_calls, CILIUM_CALL_ARP);
		ret = DROP_MISSED_TAIL_CALL;
		break;

	default:
		ret = DROP_UNKNOWN_L3;
	}

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);
	else
		return ret;
}

__BPF_MAP(POLICY_MAP, BPF_MAP_TYPE_HASH, 0, sizeof(__u32),
	  sizeof(struct policy_entry), PIN_GLOBAL_NS, 1024);

static inline int __inline__ ipv6_policy(struct __sk_buff *skb, int ifindex, __u32 src_label)
{
	struct ipv6_ct_tuple tuple = {};
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	int ret;

	if (data + sizeof(struct ipv6hdr) + ETH_HLEN > data_end)
		return TC_ACT_SHOT;

	skb->cb[CB_POLICY] = 0;
	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.addr, (union v6addr *) &ip6->saddr);

	ret = ct_lookup6(&CT_MAP6, &tuple, skb, ETH_HLEN, SECLABEL, 1);
	if (ret < 0)
		return ret;

	if (policy_can_access(&POLICY_MAP, skb, src_label) != TC_ACT_OK) {
		if (ret != CT_ESTABLISHED && ret != CT_REPLY && ret != CT_RELATED)
			return send_drop_notify(skb, src_label, SECLABEL, LXC_ID,
						ifindex, TC_ACT_SHOT);
	} else if (ret == CT_NEW)
		ct_create6(&CT_MAP6, &tuple, skb, 1);

	return 0;
}

static inline int __inline__ ipv4_policy(struct __sk_buff *skb, int ifindex, __u32 src_label)
{
	struct ipv4_ct_tuple tuple = {};
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct iphdr *ip4 = data + ETH_HLEN;
	int ret;

	if (data + sizeof(*ip4) + ETH_HLEN > data_end)
		return TC_ACT_SHOT;

	skb->cb[CB_POLICY] = 0;
	tuple.nexthdr = ip4->protocol;
	tuple.addr = ip4->saddr;

	ret = ct_lookup4(&CT_MAP4, &tuple, skb, ETH_HLEN + ipv4_hdrlen(ip4), SECLABEL, 1);
	if (ret < 0)
		return ret;

	if (policy_can_access(&POLICY_MAP, skb, src_label) != TC_ACT_OK) {
		if (ret != CT_ESTABLISHED && ret != CT_REPLY && ret != CT_RELATED)
			return send_drop_notify(skb, src_label, SECLABEL, LXC_ID,
						ifindex, TC_ACT_SHOT);
	} else if (ret == CT_NEW)
		ct_create4(&CT_MAP4, &tuple, skb, 1);

	return 0;
}

__section_tail(CILIUM_MAP_POLICY, SECLABEL) int handle_policy(struct __sk_buff *skb)
{
	int ret, ifindex = skb->cb[CB_IFINDEX];
	__u32 src_label = skb->cb[CB_SRC_LABEL];

	switch (skb->protocol) {
	case __constant_htons(ETH_P_IPV6):
		ret = ipv6_policy(skb, ifindex, src_label);
		break;

	case __constant_htons(ETH_P_IP):
		ret = ipv4_policy(skb, ifindex, src_label);
		break;

	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);

	cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, ifindex);
	return redirect(ifindex, 0);
}

BPF_LICENSE("GPL");
