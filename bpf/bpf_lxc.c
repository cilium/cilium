#include <node_config.h>
#include <lxc_config.h>

#include <iproute2/bpf_api.h>

#include <linux/icmpv6.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/lxc.h"
#include "lib/nat46.h"
#include "lib/policy.h"
#include "lib/drop.h"
#include "lib/dbg.h"

__BPF_MAP(CT_MAP, BPF_MAP_TYPE_HASH, 0, sizeof(struct ipv6_ct_tuple),
	  sizeof(struct ipv6_ct_entry), PIN_GLOBAL_NS, CT_MAP_SIZE);

#ifndef DISABLE_PORT_MAP
static inline void map_lxc_out(struct __sk_buff *skb, int off)
{
	int i;
	__u8 nexthdr;
	struct portmap local_map[] = {
#ifdef LXC_PORT_MAPPINGS
		LXC_PORT_MAPPINGS
#endif
	};

	if (ipv6_load_nexthdr(skb, off, &nexthdr) < 0)
		return;

	off += sizeof(struct ipv6hdr);

#define NR_PORTMAPS (sizeof(local_map) / sizeof(local_map[0]))

#pragma unroll
	for (i = 0; i < NR_PORTMAPS; i++)
		do_port_map_out(skb, off, nexthdr, &local_map[i]);
}
#else
static inline void map_lxc_out(struct __sk_buff *skb, int off)
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

static inline int __inline__ do_l3_from_lxc(struct __sk_buff *skb,
					    struct ipv6_ct_tuple *tuple, int nh_off)
{
	union macaddr router_mac = NODE_MAC;
	union v6addr host_ip = HOST_IP;
	int do_nat46 = 0, ret;

	if (unlikely(invalid_src_mac(skb)))
		return DROP_INVALID_SMAC;
	else if (unlikely(invalid_src_ip(skb, nh_off)))
		return DROP_INVALID_SIP;
	else if (unlikely(invalid_dst_mac(skb)))
		return DROP_INVALID_DMAC;

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
	if (ipv6_load_daddr(skb, nh_off, &tuple->addr) < 0)
		return DROP_INVALID;

	map_lxc_out(skb, nh_off);

	/* Pass all outgoing packets through conntrack. This will create an
	 * entry to allow reverse packets and return set cb[CB_POLICY] to
	 * POLICY_SKIP if the packet is a reply packet to an existing
	 * incoming connection. */
	ret = ct_lookup6(&CT_MAP, tuple, skb, ETH_HLEN, SECLABEL, 0);
	switch (ret) {
	case CT_NEW:
		ct_create6(&CT_MAP, tuple, skb, 0);
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
	if (ipv6_match_subnet_96(&tuple->addr, &host_ip)) {
		__u32 node_id = ipv6_derive_node_id(&tuple->addr);

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
		if (tuple->addr.addr[14] == host_ip.addr[14] &&
		    tuple->addr.addr[15] == host_ip.addr[15])
			goto to_host;
#endif

		return local_delivery(skb, nh_off, &tuple->addr, SECLABEL);
	} else {
#ifdef ENABLE_NAT46
		/* FIXME: Derive from prefix constant */
		if (unlikely((tuple->addr.p1 & 0xffff) == 0xadde)) {
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

		ret = __do_l3(skb, nh_off, (__u8 *) &router_mac.addr, (__u8 *) &host_mac.addr);
		if (ret != TC_ACT_OK)
			return ret;

		if (do_nat46) {
			union v6addr dp = NAT46_DST_PREFIX;

			if (ipv6_to_ipv4(skb, 14, &dp, IPV4_RANGE | (LXC_ID_NB <<16)) < 0)
				return TC_ACT_SHOT;
		}

#ifdef DISABLE_POLICY_ENFORCEMENT
		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return redirect(HOST_IFINDEX, 0);
#else
		skb->cb[CB_SRC_LABEL] = SECLABEL;
		skb->cb[CB_IFINDEX] = HOST_IFINDEX;

#ifdef ALLOW_TO_HOST
		policy_mark_skip(skb);
#endif

		tail_call(skb, &cilium_jmp, HOST_ID);
		cilium_trace(skb, DBG_NO_POLICY, HOST_ID, 0);
		return TC_ACT_SHOT;
#endif
	}

pass_to_stack:
	if (1) {
		int ret;

		ret = __do_l3(skb, nh_off, NULL, (__u8 *) &router_mac.addr);
		if (unlikely(ret != TC_ACT_OK))
			return ret;

		ipv6_store_flowlabel(skb, nh_off, SECLABEL_NB);
	}

#ifdef DISABLE_POLICY_ENFORCEMENT
	/* No policy, pass directly down to stack */
	cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, 0);
	return TC_ACT_OK;
#else
	skb->cb[CB_SRC_LABEL] = SECLABEL;
	skb->cb[CB_IFINDEX] = 0; /* Indicate passing to stack */

	tail_call(skb, &cilium_jmp, WORLD_ID);
	cilium_trace(skb, DBG_NO_POLICY, HOST_ID, 0);
	return TC_ACT_SHOT;
#endif
}

__section("from-container")
int handle_ingress(struct __sk_buff *skb)
{
	struct ipv6_ct_tuple tuple = {};
	int ret;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_LXC, skb->ingress_ifindex);

	/* Drop all non IPv6 traffic */
	if (unlikely(skb->protocol != __constant_htons(ETH_P_IPV6)))
		return TC_ACT_SHOT;

	/* Handle special ICMPv6 messages. This includes echo requests to the
	 * logical router address, neighbour advertisements to the router.
	 * All remaining packets are subjected to forwarding into the container.
	 */
	tuple.nexthdr = load_byte(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr));
	if (unlikely(tuple.nexthdr == IPPROTO_ICMPV6)) {
		ret = icmp6_handle(skb, ETH_HLEN);
		if (ret != 0)
			goto error;
	}

	/* Perform L3 action on the frame */
	ret = do_l3_from_lxc(skb, &tuple, ETH_HLEN);
error:
	if (likely(ret == TC_ACT_OK || ret == TC_ACT_REDIRECT))
		return ret;
	else if (ret < 0 || ret == TC_ACT_SHOT) {
		if (ret < 0)
			ret = -ret;
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);
	} else {
		return ret;
	}
}

__BPF_MAP(POLICY_MAP, BPF_MAP_TYPE_HASH, 0, sizeof(__u32),
	  sizeof(struct policy_entry), PIN_GLOBAL_NS, 1024);

__section_tail(CILIUM_MAP_JMP, SECLABEL) int handle_policy(struct __sk_buff *skb)
{
	struct ipv6_ct_tuple tuple = {};
	__u32 src_label = skb->cb[CB_SRC_LABEL];
	int ret, ifindex = skb->cb[CB_IFINDEX];

	skb->cb[CB_POLICY] = 0;
	tuple.nexthdr = load_byte(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr));
	if (ipv6_load_saddr(skb, ETH_HLEN, &tuple.addr) < 0) {
		ret = DROP_INVALID;
		goto drop;
	}

	ret = ct_lookup6(&CT_MAP, &tuple, skb, ETH_HLEN, SECLABEL, 1);
	if (unlikely(ret == CT_INVALID)) {
		ret = DROP_INVALID;
		goto drop;
	}

	if (policy_can_access(&POLICY_MAP, skb, src_label) != TC_ACT_OK) {
		if (ret != CT_ESTABLISHED && ret != CT_REPLY && ret != CT_RELATED) {
			return send_drop_notify(skb, src_label, SECLABEL, LXC_ID,
						ifindex, TC_ACT_SHOT);
		}
	} else if (ret == CT_NEW) {
		ct_create6(&CT_MAP, &tuple, skb, 1);
	}

	cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, ifindex);
	return redirect(ifindex, 0);

drop:
	return send_drop_notify_error(skb, ret, TC_ACT_SHOT);
}

BPF_LICENSE("GPL");
