/*
 *  Copyright (C) 2016-2019 Authors of Cilium
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
#include <linux/if_packet.h>

#include "lib/tailcall.h"
#include "lib/utils.h"
#include "lib/common.h"
#include "lib/config.h"
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
#include "lib/identity.h"
#include "lib/policy.h"
#include "lib/lb.h"
#include "lib/drop.h"
#include "lib/dbg.h"
#include "lib/trace.h"
#include "lib/csum.h"
#include "lib/encap.h"
#include "lib/nat.h"
#include "lib/nodeport.h"

#if defined ENABLE_ARP_PASSTHROUGH && defined ENABLE_ARP_RESPONDER
#error "Either ENABLE_ARP_PASSTHROUGH or ENABLE_ARP_RESPONDER can be defined"
#endif

#if defined ENABLE_IPV4 || defined ENABLE_IPV6
static inline bool redirect_to_proxy(int verdict, __u8 dir)
{
	return is_defined(ENABLE_HOST_REDIRECT) && verdict > 0 &&
	       (dir == CT_NEW || dir == CT_ESTABLISHED);
}
#endif

#ifdef ENABLE_IPV6
static inline int ipv6_l3_from_lxc(struct __sk_buff *skb,
				   struct ipv6_ct_tuple *tuple, int l3_off,
				   struct ipv6hdr *ip6, __u32 *dstID)
{
#ifdef ENABLE_ROUTING
	union macaddr router_mac = NODE_MAC;
#endif
	int ret, verdict, l4_off, hdrlen;
	struct csum_offset csum_off = {};
	struct lb6_key key = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	void *data, *data_end;
	union v6addr *daddr, orig_dip;
	__u32 tunnel_endpoint = 0;
	__u8 encrypt_key = 0;
	__u32 monitor = 0;
	__u8 reason;
	bool hairpin_flow = false; // endpoint wants to access itself via service IP

	if (unlikely(!is_valid_lxc_src_ip(ip6)))
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
#ifdef ENABLE_SERVICES
# if !defined(ENABLE_HOST_SERVICES_FULL) || defined(ENABLE_EXTERNAL_IP)
	{
		struct lb6_service *svc;

		if ((svc = lb6_lookup_service(&key)) != NULL) {
			ret = lb6_local(get_ct_map6(tuple), skb, l3_off, l4_off,
					&csum_off, &key, tuple, svc, &ct_state_new);
			if (IS_ERR(ret))
				return ret;
			hairpin_flow |= ct_state_new.loopback;
		}
	}
# endif /* !ENABLE_HOST_SERVICES_FULL || ENABLE_EXTERNAL_IP*/
#endif /* ENABLE_SERVICES */

skip_service_lookup:
	/* The verifier wants to see this assignment here in case the above goto
	 * skip_service_lookup is hit. However, in the case the packet
	 * is _not_ TCP or UDP we should not be using proxy logic anyways. For
	 * correctness it must be below the service handler in case the service
	 * logic re-writes the tuple daddr. In "theory" however the assignment
	 * should be OK to move above goto label.
	 */
	ipv6_addr_copy(&orig_dip, (union v6addr *) &tuple->daddr);


	/* WARNING: ip6 offset check invalidated, revalidate before use */

	/* Pass all outgoing packets through conntrack. This will create an
	 * entry to allow reverse packets and return set cb[CB_POLICY] to
	 * POLICY_SKIP if the packet is a reply packet to an existing
	 * incoming connection. */
	ret = ct_lookup6(get_ct_map6(tuple), tuple, skb, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0) {
		return ret;
	}

	reason = ret;

	// Check it this is return traffic to an ingress proxy.
	if ((ret == CT_REPLY || ret == CT_RELATED) && ct_state.proxy_redirect) {
		// Stack will do a socket match and deliver locally
		return skb_redirect_to_proxy(skb, 0);
	}

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* Determine the destination category for policy fallback. */
	if (1) {
		struct remote_endpoint_info *info;

		info = lookup_ip6_remote_endpoint(&orig_dip);
		if (info != NULL && info->sec_label) {
			*dstID = info->sec_label;
			tunnel_endpoint = info->tunnel_endpoint;
			encrypt_key = get_min_encrypt_key(info->key);
		} else {
			*dstID = WORLD_ID;
		}

		cilium_dbg(skb, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   orig_dip.p4, *dstID);
	}

	/* If the packet is in the establishing direction and it's destined
	 * within the cluster, it must match policy or be dropped. If it's
	 * bound for the host/outside, perform the CIDR policy check. */
	verdict = policy_can_egress6(skb, tuple, *dstID);
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0)
		return verdict;

	switch (ret) {
	case CT_NEW:
ct_recreate6:
		/* New connection implies that rev_nat_index remains untouched
		 * to the index provided by the loadbalancer (if it applied).
		 * Create a CT entry which allows to track replies and to
		 * reverse NAT.
		 */
		ct_state_new.src_sec_id = SECLABEL;
		ret = ct_create6(get_ct_map6(tuple), &CT_MAP_ANY6, tuple, skb, CT_EGRESS, &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;
		monitor = TRACE_PAYLOAD_LEN;
		break;

	case CT_ESTABLISHED:
		/* Did we end up at a stale non-service entry? Recreate if so. */
		if (unlikely(ct_state.rev_nat_index != ct_state_new.rev_nat_index)) {
			ct_delete6(get_ct_map6(tuple), tuple, skb);
			goto ct_recreate6;
		}
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(skb);

#ifdef ENABLE_NODEPORT
		/* See comment in handle_ipv4_from_lxc(). */
		if (ct_state.node_port) {
			skb->tc_index |= TC_INDEX_F_SKIP_RECIRCULATION;
			ep_tail_call(skb, CILIUM_CALL_IPV6_NODEPORT_REVNAT);
			return DROP_MISSED_TAIL_CALL;
		}
# ifdef ENABLE_DSR
		if (ct_state.dsr) {
			ret = xlate_dsr_v6(skb, tuple, l4_off);
			if (ret != 0)
				return ret;
		}
# endif /* ENABLE_DSR */
#endif /* ENABLE_NODEPORT */
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
		return DROP_UNKNOWN_CT;
	}

	hairpin_flow |= ct_state.loopback;

	if (redirect_to_proxy(verdict, reason)) {
		// Trace the packet before its forwarded to proxy
		send_trace_notify(skb, TRACE_TO_PROXY, SECLABEL, 0,
				  0, 0, reason, monitor);
		return skb_redirect_to_proxy(skb, verdict);
	}

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	daddr = (union v6addr *)&ip6->daddr;

	/* See handle_ipv4_from_lxc() re hairpin_flow */
	if (is_defined(ENABLE_ROUTING) || hairpin_flow) {
		struct endpoint_info *ep;

		/* Lookup IPv6 address, this will return a match if:
		 *  - The destination IP address belongs to a local endpoint managed by
		 *    cilium
		 *  - The destination IP address is an IP address associated with the
		 *    host itself.
		 */
		if ((ep = lookup_ip6_endpoint(ip6)) != NULL) {
#ifdef ENABLE_ROUTING
			if (ep->flags & ENDPOINT_F_HOST) {
#ifdef HOST_IFINDEX
				goto to_host;
#else
				return DROP_HOST_UNREACHABLE;
#endif
			}
#endif /* ENABLE_ROUTING */
			policy_clear_mark(skb);
			return ipv6_local_delivery(skb, l3_off, l4_off, SECLABEL,
						   ip6, tuple->nexthdr, ep,
						   METRIC_EGRESS);
		}
	}

	/* The packet goes to a peer not managed by this agent instance */
#ifdef ENCAP_IFINDEX
	{
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
		key.family = ENDPOINT_KEY_IPV6;

		/* Three cases exist here either (a) the encap and redirect could
		 * not find the tunnel so fallthrough to nat46 and stack, (b)
		 * the packet needs IPSec encap so push skb to stack for encap, or
		 * (c) packet was redirected to tunnel device so return.
		 */
		ret = encap_and_redirect_lxc(skb, tunnel_endpoint, encrypt_key, &key, SECLABEL, monitor);
		if (ret == IPSEC_ENDPOINT)
			goto pass_to_stack;
		else if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif

#ifdef ENABLE_NAT46
	if (unlikely(ipv6_addr_is_mapped(daddr))) {
		ep_tail_call(skb, CILIUM_CALL_NAT64);
		return DROP_MISSED_TAIL_CALL;
	}
#endif
	goto pass_to_stack;

#ifdef ENABLE_ROUTING
to_host:
	if (is_defined(ENABLE_HOST_REDIRECT)) {
		union macaddr host_mac = HOST_IFINDEX_MAC;

		ret = ipv6_l3(skb, l3_off, (__u8 *) &router_mac.addr, (__u8 *) &host_mac.addr, METRIC_EGRESS);
		if (ret != TC_ACT_OK)
			return ret;

		send_trace_notify(skb, TRACE_TO_HOST, SECLABEL, HOST_ID, 0,
				  HOST_IFINDEX, reason, monitor);

		cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return redirect(HOST_IFINDEX, 0);
	}
#endif

pass_to_stack:
#ifdef ENABLE_ROUTING
	ret = ipv6_l3(skb, l3_off, NULL, (__u8 *) &router_mac.addr, METRIC_EGRESS);
	if (unlikely(ret != TC_ACT_OK))
		return ret;
#endif

	if (ipv6_store_flowlabel(skb, l3_off, SECLABEL_NB) < 0)
		return DROP_WRITE_ERROR;

	send_trace_notify(skb, TRACE_TO_STACK, SECLABEL, *dstID, 0, 0,
			  reason, monitor);

	cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, 0);
#ifndef ENCAP_IFINDEX
#ifdef ENABLE_IPSEC
	if (encrypt_key && tunnel_endpoint) {
		set_encrypt_key(skb, encrypt_key);
#ifdef IP_POOLS
		set_encrypt_dip(skb, tunnel_endpoint);
#else
		set_identity(skb, SECLABEL);
#endif
	}
#endif
#endif
	return TC_ACT_OK;
}

static inline int __inline__ handle_ipv6(struct __sk_buff *skb, __u32 *dstID)
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
	return ipv6_l3_from_lxc(skb, &tuple, ETH_HLEN, ip6, dstID);
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)), CILIUM_CALL_IPV6_FROM_LXC)
int tail_handle_ipv6(struct __sk_buff *skb)
{
	__u32 dstID = 0;
	int ret = handle_ipv6(skb, &dstID);

	if (IS_ERR(ret)) {
		relax_verifier();
		return send_drop_notify(skb, SECLABEL, dstID, 0, ret, TC_ACT_SHOT,
		                        METRIC_EGRESS);
	}

	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static inline int handle_ipv4_from_lxc(struct __sk_buff *skb, __u32 *dstID)
{
	struct ipv4_ct_tuple tuple = {};
#ifdef ENABLE_ROUTING
	union macaddr router_mac = NODE_MAC;
#endif
	void *data, *data_end;
	struct iphdr *ip4;
	int ret, verdict, l3_off = ETH_HLEN, l4_off;
	struct csum_offset csum_off = {};
	struct lb4_key key = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	__be32 orig_dip;
	__u32 tunnel_endpoint = 0;
	__u8 encrypt_key = 0;
	__u32 monitor = 0;
	__u8 reason;
	bool hairpin_flow = false; // endpoint wants to access itself via service IP

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;

	if (unlikely(!is_valid_lxc_src_ipv4(ip4)))
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
#ifdef ENABLE_SERVICES
# if !defined(ENABLE_HOST_SERVICES_FULL) || defined(ENABLE_EXTERNAL_IP)
	{
		struct lb4_service *svc;

		if ((svc = lb4_lookup_service(&key)) != NULL) {
			ret = lb4_local(get_ct_map4(&tuple), skb, l3_off, l4_off, &csum_off,
					&key, &tuple, svc, &ct_state_new, ip4->saddr);
			if (IS_ERR(ret))
				return ret;
			hairpin_flow |= ct_state_new.loopback;
		}
	}
# endif /* !ENABLE_HOST_SERVICES_FULL || ENABLE_EXTERNAL_IP */
#endif /* ENABLE_SERVICES */

skip_service_lookup:
	/* The verifier wants to see this assignment here in case the above goto
	 * skip_service_lookup is hit. However, in the case the packet
	 * is _not_ TCP or UDP we should not be using proxy logic anyways. For
	 * correctness it must be below the service handler in case the service
	 * logic re-writes the tuple daddr. In "theory" however the assignment
	 * should be OK to move above goto label.
	 */
	orig_dip = tuple.daddr;

	/* WARNING: ip4 offset check invalidated, revalidate before use */

	/* Pass all outgoing packets through conntrack. This will create an
	 * entry to allow reverse packets and return set cb[CB_POLICY] to
	 * POLICY_SKIP if the packet is a reply packet to an existing
	 * incoming connection. */
	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, skb, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;

	reason = ret;

	// Check it this is return traffic to an ingress proxy.
	if ((ret == CT_REPLY || ret == CT_RELATED) && ct_state.proxy_redirect) {
		// Stack will do a socket match and deliver locally
		return skb_redirect_to_proxy(skb, 0);
	}

	/* Determine the destination category for policy fallback. */
	if (1) {
		struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(orig_dip);
		if (info != NULL && info->sec_label) {
			*dstID = info->sec_label;
			tunnel_endpoint = info->tunnel_endpoint;
			encrypt_key = get_min_encrypt_key(info->key);
		} else {
			*dstID = WORLD_ID;
		}

		cilium_dbg(skb, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   orig_dip, *dstID);
	}

	/* If the packet is in the establishing direction and it's destined
	 * within the cluster, it must match policy or be dropped. If it's
	 * bound for the host/outside, perform the CIDR policy check. */
	verdict = policy_can_egress4(skb, &tuple, *dstID);
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0)
		return verdict;

	switch (ret) {
	case CT_NEW:
ct_recreate4:
		/* New connection implies that rev_nat_index remains untouched
		 * to the index provided by the loadbalancer (if it applied).
		 * Create a CT entry which allows to track replies and to
		 * reverse NAT.
		 */
		ct_state_new.src_sec_id = SECLABEL;
		/* We could avoid creating related entries for legacy ClusterIP
		 * handling here, but turns out that verifier cannot handle it.
		 */
		ret = ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple, skb,
				 CT_EGRESS, &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;
		break;

	case CT_ESTABLISHED:
		/* Did we end up at a stale non-service entry? Recreate if so. */
		if (unlikely(ct_state.rev_nat_index != ct_state_new.rev_nat_index)) {
			ct_delete4(get_ct_map4(&tuple), &tuple, skb);
			goto ct_recreate4;
		}
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(skb);

#ifdef ENABLE_NODEPORT
		/* This handles reply traffic for the case where the nodeport EP
		 * is local to the node. We'll redirect to bpf_netdev egress to
		 * perform the reverse DNAT.
		 */
		if (ct_state.node_port) {
			skb->tc_index |= TC_INDEX_F_SKIP_RECIRCULATION;
			ep_tail_call(skb, CILIUM_CALL_IPV4_NODEPORT_REVNAT);
			return DROP_MISSED_TAIL_CALL;
		}
# ifdef ENABLE_DSR
		if (ct_state.dsr) {
			ret = xlate_dsr_v4(skb, &tuple, l4_off);
			if (ret != 0)
				return ret;
		}
# endif /* ENABLE_DSR */
#endif /* ENABLE_NODEPORT */

		if (ct_state.rev_nat_index) {
			ret = lb4_rev_nat(skb, l3_off, l4_off, &csum_off,
					  &ct_state, &tuple, 0);
			if (IS_ERR(ret)) {
				relax_verifier();
				return ret;
			}
		}
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	hairpin_flow |= ct_state.loopback;

	if (redirect_to_proxy(verdict, reason)) {
		// Trace the packet before its forwarded to proxy
		send_trace_notify(skb, TRACE_TO_PROXY, SECLABEL, 0,
				  0, 0, reason, monitor);
		return skb_redirect_to_proxy(skb, verdict);
	}

	/* After L4 write in port mapping: revalidate for direct packet access */
	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	orig_dip = ip4->daddr;

	// Allow a hairpin packet to be redirected even if ENABLE_ROUTING is
	// disabled. Otherwise, the packet will be dropped by the kernel if
	// it's going to be routed via an interface it came from after it has
	// been passed to the stack.
	if (is_defined(ENABLE_ROUTING) || hairpin_flow) {
		struct endpoint_info *ep;

		/* Lookup IPv4 address, this will return a match if:
		 *  - The destination IP address belongs to a local endpoint
		 *    managed by cilium
		 *  - The destination IP address is an IP address associated with the
		 *    host itself
		 *  - The destination IP address belongs to endpoint itself.
		 */
		if ((ep = lookup_ip4_endpoint(ip4)) != NULL) {
#ifdef ENABLE_ROUTING
			if (ep->flags & ENDPOINT_F_HOST) {
#ifdef HOST_IFINDEX
				goto to_host;
#else
				return DROP_HOST_UNREACHABLE;
#endif
			}
#endif /* ENABLE_ROUTING */
			policy_clear_mark(skb);
			return ipv4_local_delivery(skb, l3_off, l4_off, SECLABEL,
						   ip4, ep, METRIC_EGRESS);
		}
	}

#ifdef ENCAP_IFINDEX
	{
		struct endpoint_key key = {};

		key.ip4 = orig_dip & IPV4_MASK;
		key.family = ENDPOINT_KEY_IPV4;

		ret = encap_and_redirect_lxc(skb, tunnel_endpoint, encrypt_key, &key, SECLABEL, monitor);
		if (ret == DROP_NO_TUNNEL_ENDPOINT)
			goto pass_to_stack;
		/* If not redirected noteably due to IPSEC then pass up to stack
		 * for further processing.
		 */
		else if (ret == IPSEC_ENDPOINT)
			goto pass_to_stack;
		/* This is either redirect by encap code or an error has occured
		 * either way return and stack will consume skb.
		 */
		else
			return ret;
	}
#else
	goto pass_to_stack;
#endif

#ifdef ENABLE_ROUTING
to_host:
	if (is_defined(ENABLE_HOST_REDIRECT)) {
		union macaddr host_mac = HOST_IFINDEX_MAC;

		ret = ipv4_l3(skb, l3_off, (__u8 *) &router_mac.addr, (__u8 *) &host_mac.addr, ip4);
		if (ret != TC_ACT_OK)
			return ret;

		send_trace_notify(skb, TRACE_TO_HOST, SECLABEL, HOST_ID, 0, HOST_IFINDEX,
				  reason, monitor);

		cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
#ifdef HOST_REDIRECT_TO_INGRESS
		return redirect(HOST_IFINDEX, BPF_F_INGRESS);
#else
		return redirect(HOST_IFINDEX, 0);
#endif
	}
#endif

pass_to_stack:
#ifdef ENABLE_ROUTING
	ret = ipv4_l3(skb, l3_off, NULL, (__u8 *) &router_mac.addr, ip4);
	if (unlikely(ret != TC_ACT_OK))
		return ret;
#endif

	/* FIXME: We can't store the security context anywhere here so all
	 * packets to other nodes will look like they come from an outside
	 * network.
	 */

	send_trace_notify(skb, TRACE_TO_STACK, SECLABEL, *dstID, 0, 0,
			  reason, monitor);
#ifndef ENCAP_IFINDEX
#ifdef ENABLE_IPSEC
	if (encrypt_key && tunnel_endpoint) {
		set_encrypt_key(skb, encrypt_key);
#ifdef IP_POOLS
		set_encrypt_dip(skb, tunnel_endpoint);
#else
		set_identity(skb, SECLABEL);
#endif
	}
#endif
#endif
	cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, 0);
	return TC_ACT_OK;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)), CILIUM_CALL_IPV4_FROM_LXC)
int tail_handle_ipv4(struct __sk_buff *skb)
{
	__u32 dstID = 0;
	int ret = handle_ipv4_from_lxc(skb, &dstID);

	if (IS_ERR(ret))
		return send_drop_notify(skb, SECLABEL, dstID, 0, ret, TC_ACT_SHOT,
		                        METRIC_EGRESS);

	return ret;
}

#ifdef ENABLE_ARP_RESPONDER
/*
 * ARP responder for ARP requests from container
 * Respond to IPV4_GATEWAY with NODE_MAC
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_ARP) int tail_handle_arp(struct __sk_buff *skb)
{
	union macaddr mac = NODE_MAC;
	return arp_respond(skb, &mac, 0);
}
#endif /* ENABLE_ARP_RESPONDER */
#endif /* ENABLE_IPV4 */

/* Attachment/entry point is ingress for veth, egress for ipvlan. */
__section("from-container")
int handle_xgress(struct __sk_buff *skb)
{
	__u16 proto;
	int ret;

	bpf_clear_cb(skb);

	send_trace_notify(skb, TRACE_FROM_LXC, SECLABEL, 0, 0, 0, 0,
			  TRACE_PAYLOAD_LEN);

	if (!validate_ethertype(skb, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV6_FROM_LXC, tail_handle_ipv6);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV4_FROM_LXC, tail_handle_ipv4);
		break;
#ifdef ENABLE_ARP_PASSTHROUGH
	case bpf_htons(ETH_P_ARP):
		ret = TC_ACT_OK;
		break;
#elif defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ep_tail_call(skb, CILIUM_CALL_ARP);
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif /* ENABLE_ARP_RESPONDER */
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify(skb, SECLABEL, 0, 0, ret, TC_ACT_SHOT,
					METRIC_EGRESS);
	return ret;
}

#ifdef ENABLE_IPV6
static inline int __inline__
ipv6_policy(struct __sk_buff *skb, int ifindex, __u32 src_label, __u8 *reason, __u16 *proxy_port)
{
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	int ret, l4_off, verdict, hdrlen;
	struct ct_state ct_state = {};
	struct ct_state ct_state_new = {};
	bool skip_ingress_proxy = false;
	union v6addr orig_dip, orig_sip;
	__u32 monitor = 0;

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	policy_clear_mark(skb);
	tuple.nexthdr = ip6->nexthdr;

	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);
	ipv6_addr_copy(&orig_dip, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&orig_sip, (union v6addr *) &ip6->saddr);

	/* If packet is coming from the ingress proxy we have to skip
	 * redirection to the ingress proxy as we would loop forever. */
	skip_ingress_proxy = tc_index_skip_ingress_proxy(skb);

	hdrlen = ipv6_hdrlen(skb, ETH_HLEN, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = ETH_HLEN + hdrlen;
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup6(get_ct_map6(&tuple), &tuple, skb, l4_off, CT_INGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;

	*reason = ret;

	// Check it this is return traffic to an egress proxy.
	// Do not redirect again if the packet is coming from the egress proxy.
	if ((ret == CT_REPLY || ret == CT_RELATED) && ct_state.proxy_redirect &&
	    !tc_index_skip_egress_proxy(skb)) {
		// This is a reply, the proxy port does not need to be embedded
		// into skb->mark and *proxy_port can be left unset.
		send_trace_notify6(skb, TRACE_TO_PROXY, src_label, SECLABEL, &orig_sip,
				  0, ifindex, 0, monitor);
		return POLICY_ACT_PROXY_REDIRECT;
	}

	if (unlikely(ct_state.rev_nat_index)) {
		int ret2;

		ret2 = lb6_rev_nat(skb, l4_off, &csum_off,
				   ct_state.rev_nat_index, &tuple, 0);
		if (IS_ERR(ret2))
			return ret2;
	}

	verdict = policy_can_access_ingress(skb, src_label, tuple.dport,
			tuple.nexthdr, false);

	/* Reply packets and related packets are allowed, all others must be
	 * permitted by policy */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0)
		return verdict;

	if (skip_ingress_proxy)
		verdict = 0;

	if (ret == CT_NEW) {
#ifdef ENABLE_DSR
		bool dsr = false;

		ret = handle_dsr_v6(skb, &dsr);
		if (ret != 0)
			return ret;

		ct_state_new.dsr = dsr;
#endif /* ENABLE_DSR */

		ct_state_new.orig_dport = tuple.dport;
		ct_state_new.src_sec_id = src_label;
		ct_state_new.node_port = ct_state.node_port;
		ret = ct_create6(get_ct_map6(&tuple), &CT_MAP_ANY6, &tuple, skb, CT_INGRESS,
				 &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;

		/* NOTE: tuple has been invalidated after this */
	}

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	if (redirect_to_proxy(verdict, *reason)) {
		*proxy_port = verdict;
		send_trace_notify6(skb, TRACE_TO_PROXY, src_label, SECLABEL, &orig_sip,
				  0, ifindex, *reason, monitor);
		return POLICY_ACT_PROXY_REDIRECT;
	} else { // Not redirected to host / proxy.
		send_trace_notify6(skb, TRACE_TO_LXC, src_label, SECLABEL, &orig_sip,
				  LXC_ID, ifindex, *reason, monitor);
	}

	ifindex = skb->cb[CB_IFINDEX];
	if (ifindex)
		return redirect_peer(ifindex, 0);

	return TC_ACT_OK;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)), CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY)
int tail_ipv6_policy(struct __sk_buff *skb)
{
	int ret, ifindex = skb->cb[CB_IFINDEX];
	__u32 src_label = skb->cb[CB_SRC_LABEL];
	__u16 proxy_port = 0;
	__u8 reason = 0;


	skb->cb[CB_SRC_LABEL] = 0;
	ret = ipv6_policy(skb, ifindex, src_label, &reason, &proxy_port);

	if (ret == POLICY_ACT_PROXY_REDIRECT)
		ret = skb_redirect_to_proxy(skb, proxy_port);

	if (IS_ERR(ret))
		return send_drop_notify(skb, src_label, SECLABEL, LXC_ID,
					ret, TC_ACT_SHOT, METRIC_INGRESS);

	skb->cb[0] = skb->mark; // essential for proxy ingress, see bpf_ipsec.c
	return ret;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)), CILIUM_CALL_IPV6_TO_ENDPOINT)
int tail_ipv6_to_endpoint(struct __sk_buff *skb)
{
	__u32 src_identity = skb->cb[CB_SRC_LABEL];
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u16 proxy_port = 0;
	__u8 reason;
	int ret;

	if (!revalidate_data(skb, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto out;
	}

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(src_identity)) {
		union v6addr *src = (union v6addr *) &ip6->saddr;
		struct remote_endpoint_info *info;

		info = ipcache_lookup6(&IPCACHE_MAP, src, V6_CACHE_KEY_LEN);
		if (info != NULL) {
			__u32 sec_label = info->sec_label;
			if (sec_label) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "src_identity"
				 * (passed into this function) reports the src
				 * as the host. So we can ignore the ipcache
				 * if it reports the source as HOST_ID.
				 */
				if (sec_label != HOST_ID)
					src_identity = sec_label;
			}
		}
		cilium_dbg(skb, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   ((__u32 *) src)[3], src_identity);
	}

	cilium_dbg(skb, DBG_LOCAL_DELIVERY, LXC_ID, SECLABEL);

#if defined LOCAL_DELIVERY_METRICS
	update_metrics(skb->len, METRIC_INGRESS, REASON_FORWARDED);
#endif

	skb->cb[CB_SRC_LABEL] = 0;
	ret = ipv6_policy(skb, 0, src_identity, &reason, &proxy_port);

	if (ret == POLICY_ACT_PROXY_REDIRECT)
		ret = skb_redirect_to_proxy_hairpin(skb, proxy_port);

out:
	if (IS_ERR(ret))
		return send_drop_notify(skb, src_identity, SECLABEL, LXC_ID,
					ret, TC_ACT_SHOT, METRIC_INGRESS);

	return ret;
}

#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static inline int __inline__
ipv4_policy(struct __sk_buff *skb, int ifindex, __u32 src_label, __u8 *reason, __u16 *proxy_port)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct csum_offset csum_off = {};
	int ret, verdict, l3_off = ETH_HLEN, l4_off;
	struct ct_state ct_state = {};
	struct ct_state ct_state_new = {};
	bool skip_ingress_proxy = false;
	__be32 orig_dip, orig_sip;
	bool is_fragment = false;
	__u32 monitor = 0;

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	policy_clear_mark(skb);
	tuple.nexthdr = ip4->protocol;

	/* If packet is coming from the ingress proxy we have to skip
	 * redirection to the inggress proxy as we would loop forever. */
	skip_ingress_proxy = tc_index_skip_ingress_proxy(skb);

	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;
	orig_dip = ip4->daddr;
	orig_sip = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);
	is_fragment = ipv4_is_fragment(ip4);

	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, skb, l4_off, CT_INGRESS, &ct_state,
			 &monitor);
	if (ret < 0)
		return ret;

	*reason = ret;

	// Check it this is return traffic to an egress proxy.
	// Do not redirect again if the packet is coming from the egress proxy.
	if ((ret == CT_REPLY || ret == CT_RELATED) && ct_state.proxy_redirect &&
	    !tc_index_skip_egress_proxy(skb)) {
		// This is a reply, the proxy port does not need to be embedded
		// into skb->mark and *proxy_port can be left unset.
		send_trace_notify4(skb, TRACE_TO_PROXY, src_label, SECLABEL, orig_sip,
				  0, ifindex, 0, monitor);
		return POLICY_ACT_PROXY_REDIRECT;
	}

#ifdef ENABLE_NAT46
	if (skb->cb[CB_NAT46_STATE] == NAT46) {
		ep_tail_call(skb, CILIUM_CALL_NAT46);
		return DROP_MISSED_TAIL_CALL;
	}
#endif

	if (unlikely(ret == CT_REPLY && ct_state.rev_nat_index &&
		     !ct_state.loopback)) {
		int ret2;

		ret2 = lb4_rev_nat(skb, l3_off, l4_off, &csum_off,
				   &ct_state, &tuple,
				   REV_NAT_F_TUPLE_SADDR);
		if (IS_ERR(ret2))
			return ret2;
	}

	verdict = policy_can_access_ingress(skb, src_label, tuple.dport,
					    tuple.nexthdr,
					    is_fragment);

	/* Reply packets and related packets are allowed, all others must be
	 * permitted by policy */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0)
		return verdict;

	if (skip_ingress_proxy)
		verdict = 0;

	if (ret == CT_NEW) {
#ifdef ENABLE_DSR
		bool dsr = false;

		ret = handle_dsr_v4(skb, &dsr);
		if (ret != 0)
			return ret;

		ct_state_new.dsr = dsr;
#endif /* ENABLE_DSR */

		ct_state_new.orig_dport = tuple.dport;
		ct_state_new.src_sec_id = src_label;
		ct_state_new.node_port = ct_state.node_port;
		ret = ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple, skb, CT_INGRESS,
				 &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;

		/* NOTE: tuple has been invalidated after this */
	}

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	if (redirect_to_proxy(verdict, *reason)) {
		*proxy_port = verdict;
		send_trace_notify4(skb, TRACE_TO_PROXY, src_label, SECLABEL, orig_sip,
				  0, ifindex, *reason, monitor);
		return POLICY_ACT_PROXY_REDIRECT;
	} else { // Not redirected to host / proxy.
		send_trace_notify4(skb, TRACE_TO_LXC, src_label, SECLABEL, orig_sip,
				  LXC_ID, ifindex, *reason, monitor);
	}

	ifindex = skb->cb[CB_IFINDEX];
	if (ifindex)
		return redirect_peer(ifindex, 0);

	return TC_ACT_OK;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)), CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY)
int tail_ipv4_policy(struct __sk_buff *skb)
{
	int ret, ifindex = skb->cb[CB_IFINDEX];
	__u32 src_label = skb->cb[CB_SRC_LABEL];
	__u16 proxy_port = 0;
	__u8 reason = 0;

	skb->cb[CB_SRC_LABEL] = 0;
	ret = ipv4_policy(skb, ifindex, src_label, &reason, &proxy_port);

	if (ret == POLICY_ACT_PROXY_REDIRECT)
		ret = skb_redirect_to_proxy(skb, proxy_port);

	if (IS_ERR(ret))
		return send_drop_notify(skb, src_label, SECLABEL, LXC_ID,
					ret, TC_ACT_SHOT, METRIC_INGRESS);

	skb->cb[0] = skb->mark; // essential for proxy ingress, see bpf_ipsec.c
	return ret;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)), CILIUM_CALL_IPV4_TO_ENDPOINT)
int tail_ipv4_to_endpoint(struct __sk_buff *skb)
{
	__u32 src_identity = skb->cb[CB_SRC_LABEL];
	void *data, *data_end;
	struct iphdr *ip4;
	__u16 proxy_port = 0;
	__u8 reason;
	int ret;

	if (!revalidate_data(skb, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto out;
	}

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(src_identity)) {
		struct remote_endpoint_info *info;

		info = ipcache_lookup4(&IPCACHE_MAP, ip4->saddr, V4_CACHE_KEY_LEN);
		if (info != NULL) {
			__u32 sec_label = info->sec_label;
			if (sec_label) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "src_identity"
				 * (passed into this function) reports the src
				 * as the host. So we can ignore the ipcache
				 * if it reports the source as HOST_ID.
				 */
				if (sec_label != HOST_ID)
					src_identity = sec_label;
			}
		}
		cilium_dbg(skb, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->saddr, src_identity);
	}

	cilium_dbg(skb, DBG_LOCAL_DELIVERY, LXC_ID, SECLABEL);

#if defined LOCAL_DELIVERY_METRICS
	update_metrics(skb->len, METRIC_INGRESS, REASON_FORWARDED);
#endif

	skb->cb[CB_SRC_LABEL] = 0;
	ret = ipv4_policy(skb, 0, src_identity, &reason, &proxy_port);

	if (ret == POLICY_ACT_PROXY_REDIRECT)
		ret = skb_redirect_to_proxy_hairpin(skb, proxy_port);

out:
	if (IS_ERR(ret))
		return send_drop_notify(skb, src_identity, SECLABEL, LXC_ID,
					ret, TC_ACT_SHOT, METRIC_INGRESS);

	return ret;
}
#endif /* ENABLE_IPV4 */

/* Handle policy decisions as the packet makes its way towards the endpoint.
 * Previously, the packet may have come from another local endpoint, another
 * endpoint in the cluster, or from the big blue room (as identified by the
 * contents of skb->cb[CB_SRC_LABEL]). Determine whether the traffic may be
 * passed into the endpoint or if it needs further inspection by a userspace
 * proxy.
 */
__section_tail(CILIUM_MAP_POLICY, TEMPLATE_LXC_ID) int handle_policy(struct __sk_buff *skb)
{
	__u32 src_label = skb->cb[CB_SRC_LABEL];
	__u16 proto;
	int ret;

	if (!validate_ethertype(skb, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY, tail_ipv6_policy);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY, tail_ipv4_policy);
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify(skb, src_label, SECLABEL, LXC_ID,
					ret, TC_ACT_SHOT, METRIC_INGRESS);

	return ret;
}

#ifdef ENABLE_NAT46
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_NAT64) int tail_ipv6_to_ipv4(struct __sk_buff *skb)
{
	int ret = ipv6_to_ipv4(skb, 14, LXC_IPV4);
	if (IS_ERR(ret))
		return  send_drop_notify(skb, SECLABEL, 0, 0, ret, TC_ACT_SHOT,
				METRIC_EGRESS);

	cilium_dbg_capture(skb, DBG_CAPTURE_AFTER_V64, skb->ingress_ifindex);

	skb->cb[CB_NAT46_STATE] = NAT64;

	invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
			   CILIUM_CALL_IPV4_FROM_LXC, tail_handle_ipv4);
	return ret;
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
		return send_drop_notify(skb, SECLABEL, 0, 0, ret, TC_ACT_SHOT,
				METRIC_INGRESS);

	cilium_dbg_capture(skb, DBG_CAPTURE_AFTER_V46, skb->ingress_ifindex);

	invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
			   CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY, tail_ipv6_policy);
	return ret;
}
#endif
BPF_LICENSE("GPL");

__section("to-container")
int handle_to_container(struct __sk_buff *skb)
{
	int ret, trace = TRACE_FROM_STACK;
	__u32 identity = 0;
	__u16 proto;

	if (!validate_ethertype(skb, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	bpf_clear_cb(skb);

	if (inherit_identity_from_host(skb, &identity))
		trace = TRACE_FROM_PROXY;

	send_trace_notify(skb, trace, identity, 0, 0,
			  skb->ingress_ifindex, 0, TRACE_PAYLOAD_LEN);

	skb->cb[CB_SRC_LABEL] = identity;

	switch (proto) {
#if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ret = TC_ACT_OK;
		break;
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV6_TO_ENDPOINT, tail_ipv6_to_endpoint);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV4_TO_ENDPOINT, tail_ipv4_to_endpoint);
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify(skb, identity, SECLABEL, LXC_ID,
					ret, TC_ACT_SHOT, METRIC_INGRESS);

	return ret;
}
