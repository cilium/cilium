/*
 *  Copyright (C) 2016-2018 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <node_config.h>
#include <lxc_config.h>

#define EVENT_SOURCE LXC_ID

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include <linux/icmpv6.h>

#include "lib/utils.h"
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
#include "lib/lb.h"
#include "lib/drop.h"
#include "lib/dbg.h"
#include "lib/trace.h"
#include "lib/csum.h"
#include "lib/conntrack.h"
#include "lib/encap.h"

#define POLICY_ID ((LXC_ID << 16) | SECLABEL)

struct bpf_elf_map __section_maps CT_MAP6 = {
#ifdef HAVE_LRU_MAP_TYPE
	.type		= BPF_MAP_TYPE_LRU_HASH,
#else
	.type		= BPF_MAP_TYPE_HASH,
#endif
	.size_key	= sizeof(struct ipv6_ct_tuple),
	.size_value	= sizeof(struct ct_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CT_MAP_SIZE,
};

struct bpf_elf_map __section_maps CT_MAP4 = {
#ifdef HAVE_LRU_MAP_TYPE
	.type		= BPF_MAP_TYPE_LRU_HASH,
#else
	.type		= BPF_MAP_TYPE_HASH,
#endif
	.size_key	= sizeof(struct ipv4_ct_tuple),
	.size_value	= sizeof(struct ct_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CT_MAP_SIZE,
};

static inline bool redirect_to_proxy(int verdict)
{
	return verdict > 0;
}

static inline int ipv6_l3_from_lxc(struct __sk_buff *skb,
				   struct ipv6_ct_tuple *tuple, int l3_off,
				   struct ethhdr *eth, struct ipv6hdr *ip6)
{
	union macaddr router_mac = NODE_MAC;
	union v6addr router_ip = {};
	int ret, verdict, l4_off, forwarding_reason, hdrlen;
	struct csum_offset csum_off = {};
	struct endpoint_info *ep;
	struct lb6_service *svc;
	struct lb6_key key = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	void *data, *data_end;
	union v6addr *daddr, orig_dip;
	uint16_t dstID = WORLD_ID;

	if (unlikely(!is_valid_lxc_src_mac(eth)))
		return DROP_INVALID_SMAC;
	else if (unlikely(!is_valid_gw_dst_mac(eth)))
		return DROP_INVALID_DMAC;
	else if (unlikely(!is_valid_lxc_src_ip(ip6)))
		return DROP_INVALID_SIP;

	ipv6_addr_copy(&tuple->daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple->saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(skb, l3_off, &tuple->nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = l3_off + hdrlen;

	ret = lb6_extract_key(skb, tuple, l4_off, &key, &csum_off, CT_EGRESS);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNKNOWN_L4)
			goto skip_service_lookup;
		else
			return ret;
	}

	ct_state_new.orig_dport = key.dport;

	/*
	 * Check if the destination address is among the address that should be
	 * load balanced. This operation is performed before we go through the
	 * connection tracker to allow storing the reverse nat index in the CT
	 * entry for destination endpoints where we can't encode the state in the
	 * address.
	 */
	if ((svc = lb6_lookup_service(skb, &key)) != NULL) {
		ret = lb6_local(skb, l3_off, l4_off, &csum_off, &key, tuple, svc,
				&ct_state_new);
		if (IS_ERR(ret))
			return ret;
	}

skip_service_lookup:
	/* The verifier wants to see this assignment here in case the above goto
	 * skip_service_lookup is hit. However, in the case the packet
	 * is _not_ TCP or UDP we should not be using proxy logic anyways. For
	 * correctness it must be below the service handler in case the service
	 * logic re-writes the tuple daddr. In "theory" however the assignment
	 * should be OK to move above goto label.
	 */
	ipv6_addr_copy(&orig_dip, (union v6addr *) &tuple->daddr);


	/* WARNING: eth and ip6 offset check invalidated, revalidate before use */

	/* Pass all outgoing packets through conntrack. This will create an
	 * entry to allow reverse packets and return set cb[CB_POLICY] to
	 * POLICY_SKIP if the packet is a reply packet to an existing
	 * incoming connection. */
	ret = ct_lookup6(&CT_MAP6, tuple, skb, l4_off, SECLABEL, CT_EGRESS,
			 &ct_state);
	if (ret < 0)
		return ret;

	forwarding_reason = ret;

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;
	daddr = (union v6addr *)&ip6->daddr;

	/* Determine the destination category for policy fallback. */
	BPF_V6(router_ip, ROUTER_IP);
	if (ipv6_match_prefix_64(daddr, &router_ip))
		dstID = CLUSTER_ID;

	/* If the packet is in the establishing direction and it's destined
	 * within the cluster, it must match policy or be dropped. If it's
	 * bound for the host/outside, perform the CIDR policy check. */
	verdict = policy_can_egress6(skb, tuple, dstID,
				     ipv6_ct_tuple_get_daddr(tuple));
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		/* If the connection was previously known and packet is now
		 * denied, remove the connection tracking entry */
		if (ret == CT_ESTABLISHED)
			ct_delete6(&CT_MAP6, tuple, skb);

		return verdict;
	}

	switch (ret) {
	case CT_NEW:
		/* New connection implies that rev_nat_index remains untouched
		 * to the index provided by the loadbalancer (if it applied).
		 * Create a CT entry which allows to track replies and to
		 * reverse NAT.
		 */
		ct_state_new.src_sec_id = SECLABEL;
		ret = ct_create6(&CT_MAP6, tuple, skb, CT_EGRESS, &ct_state_new);
		if (IS_ERR(ret))
			return ret;
		break;

	case CT_ESTABLISHED:
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(skb);

		if (ct_state.rev_nat_index) {
			ret = lb6_rev_nat(skb, l4_off, &csum_off,
					  ct_state.rev_nat_index, tuple, 0);
			if (IS_ERR(ret))
				return ret;

			/* A reverse translate packet is always allowed except for delivery
			 * on the local node in which case this marking is cleared again. */
			policy_mark_skip(skb);
		}
		break;

	default:
		return DROP_POLICY;
	}

	if (redirect_to_proxy(verdict)) {
		union macaddr host_mac = HOST_IFINDEX_MAC;
		union v6addr host_ip = {};

		BPF_V6(host_ip, HOST_IP);

		ret = ipv6_redirect_to_host_port(skb, &csum_off, l4_off,
						 verdict, tuple->dport,
						 orig_dip, tuple, &host_ip, SECLABEL,
						 forwarding_reason);
		if (IS_ERR(ret))
			return ret;

		cilium_dbg(skb, DBG_TO_HOST, skb->cb[CB_POLICY], 0);

		ret = ipv6_l3(skb, l3_off, (__u8 *) &router_mac.addr, (__u8 *) &host_mac.addr, METRIC_EGRESS);
		if (ret != TC_ACT_OK)
			return ret;

		cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return redirect(HOST_IFINDEX, 0);
	}

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	daddr = (union v6addr *)&ip6->daddr;

	/* Lookup IPv6 address, this will return a match if:
	 *  - The destination IP address belongs to a local endpoint managed by
	 *    cilium
	 *  - The destination IP address is an IP address associated with the
	 *    host itself.
	 */
	if ((ep = lookup_ip6_endpoint(ip6)) != NULL) {
		if (ep->flags & ENDPOINT_F_HOST) {
#ifdef HOST_IFINDEX
			goto to_host;
#else
			return DROP_NO_LXC;
#endif
		}

		policy_clear_mark(skb);
		return ipv6_local_delivery(skb, l3_off, l4_off, SECLABEL, ip6, tuple->nexthdr, ep, METRIC_EGRESS);
	}

	/* The packet goes to a peer not managed by this agent instance */
#ifdef ENCAP_IFINDEX
	if (1) {
		/* FIXME GH-1391: Get rid of the initializer */
		struct endpoint_key key = {};

		/* Lookup the destination prefix in the list of known
		 * destination prefixes. If there is a match, the packet will
		 * be encapsulated to that node and then routed by the agent on
		 * the remote node.
		 *
		 * IPv6 lookup key: daddr/96
		 */
		key.ip6.p1 = daddr->p1;
		key.ip6.p2 = daddr->p2;
		key.ip6.p3 = daddr->p3;
		key.ip6.p4 = 0;
		key.family = ENDPOINT_KEY_IPV6;

		ret = encap_and_redirect(skb, &key, SECLABEL);

		/* Fall through if remote prefix was not found
		 * (DROP_NO_TUNNEL_ENDPOINT) */
		if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif

	if (dstID == CLUSTER_ID) {
		/* Packet is going to peer inside the cluster prefix. This can
		 * happen if encapsulation has been disabled and all remote
		 * peer packets are routed or the destination is part of a
		 * local prefix on another local network (e.g. local bridge).
		 *
		 * FIXME GH-1392: Differentiate between local / remote prefixes
		 */
		policy_mark_skip(skb);
		goto pass_to_stack;
	} else {
#ifdef LXC_NAT46
		if (unlikely(ipv6_addr_is_mapped(daddr))) {
			ep_tail_call(skb, CILIUM_CALL_NAT64);
			return DROP_MISSED_TAIL_CALL;
                }
#endif
		goto pass_to_stack;
	}

to_host:
	if (1) {
		union macaddr host_mac = HOST_IFINDEX_MAC;

		cilium_dbg(skb, DBG_TO_HOST, is_policy_skip(skb), 0);

		ret = ipv6_l3(skb, l3_off, (__u8 *) &router_mac.addr, (__u8 *) &host_mac.addr, METRIC_EGRESS);
		if (ret != TC_ACT_OK)
			return ret;

		send_trace_notify(skb, TRACE_TO_HOST, SECLABEL, HOST_ID, 0, HOST_IFINDEX,
				  forwarding_reason);

		cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return redirect(HOST_IFINDEX, 0);
	}

pass_to_stack:
	cilium_dbg(skb, DBG_TO_STACK, is_policy_skip(skb), 0);

	ret = ipv6_l3(skb, l3_off, NULL, (__u8 *) &router_mac.addr, METRIC_EGRESS);
	if (unlikely(ret != TC_ACT_OK))
		return ret;

	if (ipv6_store_flowlabel(skb, l3_off, SECLABEL_NB) < 0)
		return DROP_WRITE_ERROR;

	send_trace_notify(skb, TRACE_TO_STACK, SECLABEL, dstID, 0, 0,
			  forwarding_reason);

	cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, 0);
	return TC_ACT_OK;
}

static inline int __inline__ handle_ipv6(struct __sk_buff *skb)
{
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret;

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* Handle special ICMPv6 messages. This includes echo requests to the
	 * logical router address, neighbour advertisements to the router.
	 * All remaining packets are subjected to forwarding into the container.
	 */
	if (unlikely(ip6->nexthdr == IPPROTO_ICMPV6)) {
		if (data + sizeof(*ip6) + ETH_HLEN + sizeof(struct icmp6hdr) > data_end) {
			return DROP_INVALID;
		}

		ret = icmp6_handle(skb, ETH_HLEN, ip6, METRIC_EGRESS);
		if (IS_ERR(ret))
			return ret;
	}

	/* Perform L3 action on the frame */
	tuple.nexthdr = ip6->nexthdr;
	return ipv6_l3_from_lxc(skb, &tuple, ETH_HLEN, data, ip6);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6) int tail_handle_ipv6(struct __sk_buff *skb)
{
	int ret = handle_ipv6(skb);

	if (IS_ERR(ret))
		return send_drop_notify(skb, SECLABEL, 0, 0, 0, ret, TC_ACT_SHOT,
		                        METRIC_EGRESS);

	return ret;
}

#ifdef LXC_IPV4

static inline int handle_ipv4_from_lxc(struct __sk_buff *skb)
{
	struct ipv4_ct_tuple tuple = {};
	union macaddr router_mac = NODE_MAC;
	void *data, *data_end;
	struct iphdr *ip4;
	struct ethhdr *eth;
	int ret, verdict, l3_off = ETH_HLEN, l4_off, forwarding_reason;
	struct csum_offset csum_off = {};
	struct endpoint_info *ep;
	struct lb4_service *svc;
	struct lb4_key key = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	__be32 orig_dip;
	uint16_t dstID = WORLD_ID;

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;

	eth = data;
	if (unlikely(!is_valid_lxc_src_mac(eth)))
		return DROP_INVALID_SMAC;
	else if (unlikely(!is_valid_gw_dst_mac(eth)))
		return DROP_INVALID_DMAC;
	else if (unlikely(!is_valid_lxc_src_ipv4(ip4)))
		return DROP_INVALID_SIP;

	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);

	ret = lb4_extract_key(skb, &tuple, l4_off, &key, &csum_off, CT_EGRESS);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNKNOWN_L4)
			goto skip_service_lookup;
		else
			return ret;
	}

	ct_state_new.orig_dport = key.dport;
#ifdef ENABLE_IPV4
	if ((svc = lb4_lookup_service(skb, &key)) != NULL) {
		ret = lb4_local(skb, l3_off, l4_off, &csum_off,
				&key, &tuple, svc, &ct_state_new, ip4->saddr);
		if (IS_ERR(ret))
			return ret;
	}
#endif
skip_service_lookup:
	/* The verifier wants to see this assignment here in case the above goto
	 * skip_service_lookup is hit. However, in the case the packet
	 * is _not_ TCP or UDP we should not be using proxy logic anyways. For
	 * correctness it must be below the service handler in case the service
	 * logic re-writes the tuple daddr. In "theory" however the assignment
	 * should be OK to move above goto label.
	 */
	orig_dip = tuple.daddr;

	/* WARNING: eth and ip4 offset check invalidated, revalidate before use */

	/* Pass all outgoing packets through conntrack. This will create an
	 * entry to allow reverse packets and return set cb[CB_POLICY] to
	 * POLICY_SKIP if the packet is a reply packet to an existing
	 * incoming connection. */
	ret = ct_lookup4(&CT_MAP4, &tuple, skb, l4_off, SECLABEL, CT_EGRESS,
			 &ct_state);
	if (ret < 0)
		return ret;

	forwarding_reason = ret;

	/* Determine the destination category for policy fallback. */
	if ((orig_dip & IPV4_CLUSTER_MASK) == IPV4_CLUSTER_RANGE)
		dstID = CLUSTER_ID;

	/* If the packet is in the establishing direction and it's destined
	 * within the cluster, it must match policy or be dropped. If it's
	 * bound for the host/outside, perform the CIDR policy check. */
	verdict = policy_can_egress4(skb, &tuple, dstID,
				     ipv4_ct_tuple_get_daddr(&tuple));
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		/* If the connection was previously known and packet is now
		 * denied, remove the connection tracking entry */
		if (ret == CT_ESTABLISHED)
			ct_delete4(&CT_MAP4, &tuple, skb);

		return verdict;
	}

	switch (ret) {
	case CT_NEW:
		/* New connection implies that rev_nat_index remains untouched
		 * to the index provided by the loadbalancer (if it applied).
		 * Create a CT entry which allows to track replies and to
		 * reverse NAT.
		 */
		ct_state_new.src_sec_id = SECLABEL;
		ret = ct_create4(&CT_MAP4, &tuple, skb, CT_EGRESS, &ct_state_new);
		if (IS_ERR(ret))
			return ret;
		break;

	case CT_ESTABLISHED:
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(skb);

		if (ct_state.rev_nat_index) {
			ret = lb4_rev_nat(skb, l3_off, l4_off, &csum_off,
					  &ct_state, &tuple, 0);
			if (IS_ERR(ret))
				return ret;
		}
		break;

	default:
		return DROP_POLICY;
	}

	if (redirect_to_proxy(verdict)) {
		union macaddr host_mac = HOST_IFINDEX_MAC;

		ret = ipv4_redirect_to_host_port(skb, &csum_off, l4_off,
						 verdict, tuple.dport,
						 orig_dip, &tuple, SECLABEL, forwarding_reason);
		if (IS_ERR(ret))
			return ret;

		/* After L4 write in port mapping: revalidate for direct packet access */
		if (!revalidate_data(skb, &data, &data_end, &ip4))
			return DROP_INVALID;

		cilium_dbg(skb, DBG_TO_HOST, skb->cb[CB_POLICY], 0);

		ret = ipv4_l3(skb, l3_off, (__u8 *) &router_mac.addr, (__u8 *) &host_mac.addr, ip4);
		if (ret != TC_ACT_OK)
			return ret;

		cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return redirect(HOST_IFINDEX, 0);
	}

	/* After L4 write in port mapping: revalidate for direct packet access */
	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	orig_dip = ip4->daddr;

	/* Lookup IPv4 address, this will return a match if:
	 *  - The destination IP address belongs to a local endpoint managed by
	 *    cilium
	 *  - The destination IP address is an IP address associated with the
	 *    host itself.
	 */
	if ((ep = lookup_ip4_endpoint(ip4)) != NULL) {
		if (ep->flags & ENDPOINT_F_HOST) {
#ifdef HOST_IFINDEX
			goto to_host;
#else
			return DROP_NO_LXC;
#endif
		}
		policy_clear_mark(skb);
		return ipv4_local_delivery(skb, l3_off, l4_off, SECLABEL, ip4, ep, METRIC_EGRESS);
	}

#ifdef ENCAP_IFINDEX
	if (1) {
		/* FIXME GH-1391: Get rid of the initializer */
		struct endpoint_key key = {};

		/* Lookup the destination prefix in the list of known
		 * destination prefixes. If there is a match, the packet will
		 * be encapsulated to that node and then routed by the agent on
		 * the remote node.
		 *
		 * IPv4 lookup key: daddr & IPV4_MASK
		 */
		key.ip4 = orig_dip & IPV4_MASK;
		key.family = ENDPOINT_KEY_IPV4;

		ret = encap_and_redirect(skb, &key, SECLABEL);

		/* Fall through if remote prefix was not found
		 * (DROP_NO_TUNNEL_ENDPOINT) */
		if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif
	if (dstID == CLUSTER_ID) {
		/* Packet is going to peer inside the cluster prefix. This can
		 * happen if encapsulation has been disabled and all remote
		 * peer packets are routed or the destination is part of a
		 * local prefix on another local network (e.g. local bridge).
		 *
		 * FIXME GH-1392: Differentiate between local / remote prefixes
		 */
		policy_mark_skip(skb);
	}
	goto pass_to_stack;

to_host:
	if (1) {
		union macaddr host_mac = HOST_IFINDEX_MAC;

		cilium_dbg(skb, DBG_TO_HOST, is_policy_skip(skb), 0);

		ret = ipv4_l3(skb, l3_off, (__u8 *) &router_mac.addr, (__u8 *) &host_mac.addr, ip4);
		if (ret != TC_ACT_OK)
			return ret;

		send_trace_notify(skb, TRACE_TO_HOST, SECLABEL, HOST_ID, 0, HOST_IFINDEX,
				  forwarding_reason);

		cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return redirect(HOST_IFINDEX, 0);
	}

pass_to_stack:
	cilium_dbg(skb, DBG_TO_STACK, is_policy_skip(skb), 0);

	ret = ipv4_l3(skb, l3_off, NULL, (__u8 *) &router_mac.addr, ip4);
	if (unlikely(ret != TC_ACT_OK))
		return ret;

	/* FIXME: We can't store the security context anywhere here so all
	 * packets to other nodes will look like they come from an outside
	 * network.
	 */

	send_trace_notify(skb, TRACE_TO_STACK, SECLABEL, dstID, 0, 0,
			  forwarding_reason);

	cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, 0);
	return TC_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4) int tail_handle_ipv4(struct __sk_buff *skb)
{
	int ret = handle_ipv4_from_lxc(skb);

	if (IS_ERR(ret))
		return send_drop_notify(skb, SECLABEL, 0, 0, 0, ret, TC_ACT_SHOT,
		                        METRIC_EGRESS);

	return ret;
}

#endif

/*
 * ARP responder for ARP requests from container
 * Respond to IPV4_GATEWAY with NODE_MAC
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_ARP) int tail_handle_arp(struct __sk_buff *skb)
{
	union macaddr mac = NODE_MAC;
	return arp_respond(skb, &mac);
}

__section("from-container")
int handle_ingress(struct __sk_buff *skb)
{
	int ret;

	bpf_clear_cb(skb);

	send_trace_notify(skb, TRACE_FROM_LXC, SECLABEL, 0, 0, 0, 0);

#ifdef DROP_ALL
	if (skb->protocol == bpf_htons(ETH_P_ARP)) {
		ep_tail_call(skb, CILIUM_CALL_ARP);
		ret = DROP_MISSED_TAIL_CALL;
	} else if (1) {
		ret = DROP_POLICY;
	} else {
#endif
	switch (skb->protocol) {
	case bpf_htons(ETH_P_IPV6):
		ep_tail_call(skb, CILIUM_CALL_IPV6);
		ret = DROP_MISSED_TAIL_CALL;
		break;

	case bpf_htons(ETH_P_IP):
		ep_tail_call(skb, CILIUM_CALL_IPV4);
		ret = DROP_MISSED_TAIL_CALL;
		break;

	case bpf_htons(ETH_P_ARP):
		ep_tail_call(skb, CILIUM_CALL_ARP);
		ret = DROP_MISSED_TAIL_CALL;
		break;

	default:
		ret = DROP_UNKNOWN_L3;
	}

#ifdef DROP_ALL
	}
#endif

	if (IS_ERR(ret))
		return send_drop_notify(skb, SECLABEL, 0, 0, 0, ret, TC_ACT_SHOT,
					METRIC_EGRESS);
	return ret;
}

static inline int __inline__ ipv6_policy(struct __sk_buff *skb, int ifindex, __u32 src_label,
					 int *forwarding_reason)
{
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	int ret, l4_off, verdict, hdrlen;
	struct ct_state ct_state = {};
	struct ct_state ct_state_new = {};
	bool skip_proxy;
	union v6addr orig_dip = {};

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	policy_clear_mark(skb);
	tuple.nexthdr = ip6->nexthdr;

	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);
	ipv6_addr_copy(&orig_dip, (union v6addr *) &ip6->daddr);

	/* If packet is coming from the egress proxy we have to skip
	 * redirection to the egress proxy as we would loop forever. */
	skip_proxy = tc_index_skip_proxy(skb);

	hdrlen = ipv6_hdrlen(skb, ETH_HLEN, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = ETH_HLEN + hdrlen;
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	/* derive reverse NAT index and zero it. */
	ct_state_new.rev_nat_index = ip6->daddr.s6_addr32[3] & 0xFFFF;
	if (ct_state_new.rev_nat_index) {
		union v6addr dip;

		ipv6_addr_copy(&dip, (union v6addr *) &ip6->daddr);
		dip.p4 &= ~0xFFFF;
		ret = ipv6_store_daddr(skb, dip.addr, ETH_HLEN);
		if (IS_ERR(ret))
			return DROP_WRITE_ERROR;

		if (csum_off.offset) {
			__u32 zero_nat = 0;
			__be32 sum = csum_diff(&ct_state_new.rev_nat_index, 4, &zero_nat, 4, 0);
			if (csum_l4_replace(skb, l4_off, &csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
				return DROP_CSUM_L4;
		}
	}

	ret = ct_lookup6(&CT_MAP6, &tuple, skb, l4_off, SECLABEL, CT_INGRESS,
			 &ct_state);
	if (ret < 0)
		return ret;

	*forwarding_reason = ret;

	if (unlikely(ct_state.rev_nat_index)) {
		int ret2;

		ret2 = lb6_rev_nat(skb, l4_off, &csum_off,
				   ct_state.rev_nat_index, &tuple, 0);
		if (IS_ERR(ret2))
			return ret2;
	}

	verdict = policy_can_access_ingress(skb, &src_label, tuple.dport,
					    tuple.nexthdr, sizeof(tuple.saddr),
					    &tuple.saddr);

	/* Reply packets and related packets are allowed, all others must be
	 * permitted by policy */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		/* If the connection was previously known and packet is now
		 * denied, remove the connection tracking entry */
		if (ret == CT_ESTABLISHED)
			ct_delete6(&CT_MAP6, &tuple, skb);

		return DROP_POLICY;
	}

	if (skip_proxy)
		verdict = 0;

	if (ret == CT_NEW) {
		ct_state_new.orig_dport = tuple.dport;
		ct_state_new.src_sec_id = src_label;
		ret = ct_create6(&CT_MAP6, &tuple, skb, CT_INGRESS, &ct_state_new);
		if (IS_ERR(ret))
			return ret;

		/* NOTE: tuple has been invalidated after this */
	}

	if (redirect_to_proxy(verdict) && (ret == CT_NEW || ret == CT_ESTABLISHED)) {
		union macaddr host_mac = HOST_IFINDEX_MAC;
		union macaddr router_mac = NODE_MAC;
		union v6addr host_ip = {};

		BPF_V6(host_ip, HOST_IP);

		ret = ipv6_redirect_to_host_port(skb, &csum_off, l4_off,
						 verdict, tuple.dport,
						 orig_dip, &tuple, &host_ip, src_label,
						 *forwarding_reason);
		if (IS_ERR(ret))
			return ret;

		if (eth_store_saddr(skb, (__u8 *) &router_mac.addr, 0) < 0)
			return DROP_WRITE_ERROR;

		if (eth_store_daddr(skb, (__u8 *) &host_mac.addr, 0) < 0)
			return DROP_WRITE_ERROR;

		skb->cb[CB_IFINDEX] = HOST_IFINDEX;
	}

	return 0;
}

#ifdef LXC_IPV4
static inline int __inline__ ipv4_policy(struct __sk_buff *skb, int ifindex, __u32 src_label,
					 int *forwarding_reason)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct csum_offset csum_off = {};
	int ret, verdict, l4_off;
	struct ct_state ct_state = {};
	struct ct_state ct_state_new = {};
	bool skip_proxy;
	__be32 orig_dip, orig_sip;

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	policy_clear_mark(skb);
	tuple.nexthdr = ip4->protocol;

	/* If packet is coming from the egress proxy we have to skip
	 * redirection to the egress proxy as we would loop forever. */
	skip_proxy = tc_index_skip_proxy(skb);

	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;
	orig_dip = ip4->daddr;
	orig_sip = ip4->saddr;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup4(&CT_MAP4, &tuple, skb, l4_off, SECLABEL, CT_INGRESS, &ct_state);
	if (ret < 0)
		return ret;

	*forwarding_reason = ret;

#ifdef LXC_NAT46
	if (skb->cb[CB_NAT46_STATE] == NAT46) {
		ep_tail_call(skb, CILIUM_CALL_NAT46);
		return DROP_MISSED_TAIL_CALL;
	}
#endif

	if (unlikely(ret == CT_REPLY && ct_state.rev_nat_index &&
		     !ct_state.loopback)) {
		int ret2;

		ret2 = lb4_rev_nat(skb, ETH_HLEN, l4_off, &csum_off,
				   &ct_state, &tuple,
				   REV_NAT_F_TUPLE_SADDR);
		if (IS_ERR(ret2))
			return ret2;
	}

	verdict = policy_can_access_ingress(skb, &src_label, tuple.dport,
					    tuple.nexthdr, sizeof(orig_sip),
					    &orig_sip);

	/* Reply packets and related packets are allowed, all others must be
	 * permitted by policy */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		/* If the connection was previously known and packet is now
		 * denied, remove the connection tracking entry */
		if (ret == CT_ESTABLISHED)
			ct_delete4(&CT_MAP4, &tuple, skb);

		return DROP_POLICY;
	}

	if (skip_proxy)
		verdict = 0;

	if (ret == CT_NEW) {
		ct_state_new.orig_dport = tuple.dport;
		ct_state_new.src_sec_id = src_label;
		ret = ct_create4(&CT_MAP4, &tuple, skb, CT_INGRESS, &ct_state_new);
		if (IS_ERR(ret))
			return ret;

		/* NOTE: tuple has been invalidated after this */
	}

	if (redirect_to_proxy(verdict) && (ret == CT_NEW || ret == CT_ESTABLISHED)) {
		union macaddr host_mac = HOST_IFINDEX_MAC;
		union macaddr router_mac = NODE_MAC;

		ret = ipv4_redirect_to_host_port(skb, &csum_off, l4_off,
						 verdict, tuple.dport,
						 orig_dip, &tuple, src_label, *forwarding_reason);
		if (IS_ERR(ret))
			return ret;

		cilium_dbg(skb, DBG_TO_HOST, is_policy_skip(skb), 0);

		if (eth_store_saddr(skb, (__u8 *) &router_mac.addr, 0) < 0)
			return DROP_WRITE_ERROR;

		if (eth_store_daddr(skb, (__u8 *) &host_mac.addr, 0) < 0)
			return DROP_WRITE_ERROR;

		skb->cb[CB_IFINDEX] = HOST_IFINDEX;
	}

	return 0;
}
#endif

/* Handle policy decisions as the packet makes its way towards the endpoint.
 * Previously, the packet may have come from another local endpoint, another
 * endpoint in the cluster, or from the big blue room (as identified by the
 * contents of skb->cb[CB_SRC_LABEL]). Determine whether the traffic may be
 * passed into the endpoint or if it needs further inspection by a userspace
 * proxy.
 */
__section_tail(CILIUM_MAP_POLICY, LXC_ID) int handle_policy(struct __sk_buff *skb)
{
	int ret, ifindex = skb->cb[CB_IFINDEX];
	__u32 src_label = skb->cb[CB_SRC_LABEL];
	int forwarding_reason = 0;

#ifdef DROP_ALL
	ret = DROP_POLICY;
	if (0) {
#endif
	switch (skb->protocol) {
	case bpf_htons(ETH_P_IPV6):
		ret = ipv6_policy(skb, ifindex, src_label, &forwarding_reason);
		break;

#ifdef LXC_IPV4
	case bpf_htons(ETH_P_IP):
		ret = ipv4_policy(skb, ifindex, src_label, &forwarding_reason);
		break;
#endif

	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}
#ifdef DROP_ALL
	}
#endif

	if (IS_ERR(ret))
		return send_drop_notify(skb, src_label, SECLABEL, LXC_ID,
					ifindex, ret, TC_ACT_SHOT, METRIC_INGRESS);

	if (ifindex == skb->cb[CB_IFINDEX]) { // Not redirected to host / proxy.
		send_trace_notify(skb, TRACE_TO_LXC, src_label, SECLABEL, LXC_ID, ifindex,
				  forwarding_reason);
	}

	ifindex = skb->cb[CB_IFINDEX];

	if (ifindex)
		return redirect(ifindex, 0);
	else
		return TC_ACT_OK;
}

#ifdef LXC_NAT46
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_NAT64) int tail_ipv6_to_ipv4(struct __sk_buff *skb)
{
	int ret = ipv6_to_ipv4(skb, 14, LXC_IPV4);
	if (IS_ERR(ret))
		return  send_drop_notify(skb, SECLABEL, 0, 0, 0, ret, TC_ACT_SHOT,
				METRIC_EGRESS);

	cilium_dbg_capture(skb, DBG_CAPTURE_AFTER_V64, skb->ingress_ifindex);

	skb->cb[CB_NAT46_STATE] = NAT64;

	ep_tail_call(skb, CILIUM_CALL_IPV4);
	return DROP_MISSED_TAIL_CALL;
}

static inline int __inline__ handle_ipv4_to_ipv6(struct __sk_buff *skb)
{
	union v6addr dp = {};
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	BPF_V6(dp, LXC_IP);
	return ipv4_to_ipv6(skb, ip4, 14, &dp);

}
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_NAT46) int tail_ipv4_to_ipv6(struct __sk_buff *skb)
{
	int ret = handle_ipv4_to_ipv6(skb);

	if (IS_ERR(ret))
		return send_drop_notify(skb, SECLABEL, 0, 0, 0, ret, TC_ACT_SHOT,
				METRIC_INGRESS);

	cilium_dbg_capture(skb, DBG_CAPTURE_AFTER_V46, skb->ingress_ifindex);

	tail_call(skb, &cilium_policy, LXC_ID);
	return DROP_MISSED_TAIL_CALL;
}
#endif
BPF_LICENSE("GPL");
