// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2016-2021 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <ep_config.h>
#include <node_config.h>

#include <bpf/verifier.h>

#include <linux/icmpv6.h>

#define EVENT_SOURCE LXC_ID

#include "lib/tailcall.h"
#include "lib/common.h"
#include "lib/config.h"
#include "lib/maps.h"
#include "lib/arp.h"
#include "lib/edt.h"
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
#include "lib/egress_policies.h"
#include "lib/encap.h"
#include "lib/eps.h"
#include "lib/nat.h"
#include "lib/fib.h"
#include "lib/nodeport.h"
#include "lib/policy_log.h"

#if !defined(ENABLE_HOST_SERVICES_FULL) || defined(ENABLE_SOCKET_LB_HOST_ONLY)
# define ENABLE_PER_PACKET_LB
#endif

#if defined(ENABLE_ARP_PASSTHROUGH) && defined(ENABLE_ARP_RESPONDER)
#error "Either ENABLE_ARP_PASSTHROUGH or ENABLE_ARP_RESPONDER can be defined"
#endif

#if defined(ENABLE_IPV4) || defined(ENABLE_IPV6)
static __always_inline bool redirect_to_proxy(int verdict, __u8 dir)
{
	return is_defined(ENABLE_HOST_REDIRECT) && verdict > 0 &&
	       (dir == CT_NEW || dir == CT_ESTABLISHED ||  dir == CT_REOPENED);
}
#endif

#ifdef ENABLE_CUSTOM_CALLS
/* Encode return value and identity into cb buffer. This is used before
 * executing tail calls to custom programs. "ret" is the return value supposed
 * to be returned to the kernel, needed by the callee to preserve the datapath
 * logics. The "identity" is the security identity of the local endpoint: the
 * source of the packet on ingress path, or its destination on the egress path.
 * We encode it so that custom programs can retrieve it and use it at their
 * convenience.
 */
static __always_inline int
encode_custom_prog_meta(struct __ctx_buff *ctx, int ret, __u32 identity)
{
	__u32 custom_meta = 0;

	/* If we cannot encode return value on 8 bits, return an error so we can
	 * skip the tail call entirely, as custom program has no way to return
	 * expected value and datapath logics will break.
	 */
	if ((ret & 0xff) != ret)
		return -1;
	custom_meta |= (__u32)(ret & 0xff) << 24;
	custom_meta |= (identity & 0xffffff);
	ctx_store_meta(ctx, CB_CUSTOM_CALLS, custom_meta);
	return 0;
}
#endif

#ifdef ENABLE_IPV6
static __always_inline int ipv6_l3_from_lxc(struct __ctx_buff *ctx,
					    struct ipv6_ct_tuple *tuple,
					    int l3_off, struct ipv6hdr *ip6,
					    __u32 *dstID)
{
#ifdef ENABLE_ROUTING
	union macaddr router_mac = NODE_MAC;
#endif
	int ret, verdict = 0, l4_off, hdrlen;
	struct csum_offset csum_off = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	void *data, *data_end;
	union v6addr *daddr, orig_dip;
	__u32 tunnel_endpoint = 0;
	__u8 encrypt_key = 0;
	__u32 monitor = 0;
	__u8 reason;
	bool hairpin_flow = false; /* endpoint wants to access itself via service IP */
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	bool __maybe_unused dst_remote_ep = false;

	if (unlikely(!is_valid_lxc_src_ip(ip6)))
		return DROP_INVALID_SIP;

	ipv6_addr_copy(&tuple->daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple->saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(ctx, l3_off, &tuple->nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = l3_off + hdrlen;

#ifdef ENABLE_PER_PACKET_LB
	{
		struct lb6_service *svc;
		struct lb6_key key = {};

		ret = lb6_extract_key(ctx, tuple, l4_off, &key, &csum_off,
				      CT_EGRESS);
		if (IS_ERR(ret)) {
			if (ret == DROP_NO_SERVICE || ret == DROP_UNKNOWN_L4)
				goto skip_service_lookup;
			else
				return ret;
		}

		/*
		 * Check if the destination address is among the address that should
		 * be load balanced. This operation is performed before we go through
		 * the connection tracker to allow storing the reverse nat index in
		 * the CT entry for destination endpoints where we can't encode the
		 * state in the address.
		 */
		svc = lb6_lookup_service(&key, is_defined(ENABLE_NODEPORT));
		if (svc) {
			ret = lb6_local(get_ct_map6(tuple), ctx, l3_off, l4_off,
					&csum_off, &key, tuple, svc, &ct_state_new,
					false);
			if (IS_ERR(ret))
				return ret;
			hairpin_flow |= ct_state_new.loopback;
		}
	}

skip_service_lookup:
#endif /* ENABLE_PER_PACKET_LB */

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
	 * POLICY_SKIP if the packet is a reply packet to an existing incoming
	 * connection.
	 */
	ret = ct_lookup6(get_ct_map6(tuple), tuple, ctx, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;

	reason = ret;

	/* Check it this is return traffic to an ingress proxy. */
	if ((ret == CT_REPLY || ret == CT_RELATED) && ct_state.proxy_redirect) {
		/* Stack will do a socket match and deliver locally. */
		return ctx_redirect_to_proxy6(ctx, tuple, 0, false);
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* Determine the destination category for policy fallback. */
	if (1) {
		struct remote_endpoint_info *info;

		info = lookup_ip6_remote_endpoint(&orig_dip);
		if (info != NULL && info->sec_label) {
			*dstID = info->sec_label;
			tunnel_endpoint = info->tunnel_endpoint;
			encrypt_key = get_min_encrypt_key(info->key);
#ifdef ENABLE_WIREGUARD
			if (info->tunnel_endpoint != 0 &&
			    info->sec_label != HOST_ID &&
			    info->sec_label != REMOTE_NODE_ID)
				dst_remote_ep = true;
#endif /* ENABLE_WIREGUARD */
		} else {
			*dstID = WORLD_ID;
		}

		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   orig_dip.p4, *dstID);
	}

	/* When an endpoint connects to itself via service clusterIP, we need
	 * to skip the policy enforcement. If we didn't, the user would have to
	 * define policy rules to allow pods to talk to themselves. We still
	 * want to execute the conntrack logic so that replies can be correctly
	 * matched.
	 */
	if (hairpin_flow)
		goto skip_policy_enforcement;

	/* If the packet is in the establishing direction and it's destined
	 * within the cluster, it must match policy or be dropped. If it's
	 * bound for the host/outside, perform the CIDR policy check.
	 */
	verdict = policy_can_egress6(ctx, tuple, SECLABEL, *dstID,
				     &policy_match_type, &audited);

	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, *dstID, tuple->dport,
					   tuple->nexthdr, POLICY_EGRESS, 1,
					   verdict, policy_match_type, audited);
		return verdict;
	}

skip_policy_enforcement:
	switch (ret) {
	case CT_NEW:
		if (!hairpin_flow)
			send_policy_verdict_notify(ctx, *dstID, tuple->dport,
						   tuple->nexthdr, POLICY_EGRESS, 1,
						   verdict, policy_match_type, audited);
ct_recreate6:
		/* New connection implies that rev_nat_index remains untouched
		 * to the index provided by the loadbalancer (if it applied).
		 * Create a CT entry which allows to track replies and to
		 * reverse NAT.
		 */
		ct_state_new.src_sec_id = SECLABEL;
		ret = ct_create6(get_ct_map6(tuple), &CT_MAP_ANY6, tuple, ctx,
				 CT_EGRESS, &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;
		monitor = TRACE_PAYLOAD_LEN;
		break;

	case CT_REOPENED:
		if (!hairpin_flow)
			send_policy_verdict_notify(ctx, *dstID, tuple->dport,
						   tuple->nexthdr, POLICY_EGRESS, 1,
						   verdict, policy_match_type, audited);
	case CT_ESTABLISHED:
		/* Did we end up at a stale non-service entry? Recreate if so. */
		if (unlikely(ct_state.rev_nat_index != ct_state_new.rev_nat_index))
			goto ct_recreate6;
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(ctx);

#ifdef ENABLE_NODEPORT
		/* See comment in handle_ipv4_from_lxc(). */
		if (ct_state.node_port) {
			ctx->tc_index |= TC_INDEX_F_SKIP_RECIRCULATION;
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_REVNAT);
			return DROP_MISSED_TAIL_CALL;
		}
# ifdef ENABLE_DSR
		if (ct_state.dsr) {
			ret = xlate_dsr_v6(ctx, tuple, l4_off);
			if (ret != 0)
				return ret;
		}
# endif /* ENABLE_DSR */
#endif /* ENABLE_NODEPORT */
		if (ct_state.rev_nat_index) {
			ret = lb6_rev_nat(ctx, l4_off, &csum_off,
					  ct_state.rev_nat_index, tuple, 0);
			if (IS_ERR(ret))
				return ret;

			/* A reverse translate packet is always allowed except
			 * for delivery on the local node in which case this
			 * marking is cleared again.
			 */
			policy_mark_skip(ctx);
		}
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	hairpin_flow |= ct_state.loopback;

	if (redirect_to_proxy(verdict, reason)) {
		/* Trace the packet before it is forwarded to proxy */
		send_trace_notify(ctx, TRACE_TO_PROXY, SECLABEL, 0,
				  0, 0, reason, monitor);
		return ctx_redirect_to_proxy6(ctx, tuple, verdict, false);
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
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
		ep = lookup_ip6_endpoint(ip6);
		if (ep) {
#ifdef ENABLE_ROUTING
			if (ep->flags & ENDPOINT_F_HOST) {
#ifdef HOST_IFINDEX
				goto to_host;
#else
				return DROP_HOST_UNREACHABLE;
#endif
			}
#endif /* ENABLE_ROUTING */
			policy_clear_mark(ctx);
			return ipv6_local_delivery(ctx, l3_off, SECLABEL, ep,
						   METRIC_EGRESS, false);
		}
	}

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)
	/* If the destination is the local host and per-endpoint routes are
	 * enabled, jump to the bpf_host program to enforce ingress host policies.
	 */
	if (*dstID == HOST_ID) {
		ctx_store_meta(ctx, CB_FROM_HOST, 0);
		tail_call_static(ctx, &POLICY_CALL_MAP, HOST_EP_ID);
		return DROP_MISSED_TAIL_CALL;
	}
#endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */

	/* The packet goes to a peer not managed by this agent instance */
#ifdef TUNNEL_MODE
# ifdef ENABLE_WIREGUARD
	if (!dst_remote_ep)
# endif /* ENABLE_WIREGUARD */
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
		 * the packet needs IPSec encap so push ctx to stack for encap, or
		 * (c) packet was redirected to tunnel device so return.
		 */
		ret = encap_and_redirect_lxc(ctx, tunnel_endpoint, encrypt_key,
					     &key, SECLABEL, monitor);
		if (ret == IPSEC_ENDPOINT)
			goto encrypt_to_stack;
		else if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif
#ifdef ENABLE_NAT46
	if (unlikely(ipv6_addr_is_mapped(daddr))) {
		ep_tail_call(ctx, CILIUM_CALL_NAT64);
		return DROP_MISSED_TAIL_CALL;
	}
#endif
	if (is_defined(ENABLE_REDIRECT_FAST))
		return redirect_direct_v6(ctx, l3_off, ip6);

	goto pass_to_stack;

#ifdef ENABLE_ROUTING
to_host:
	if (is_defined(ENABLE_HOST_FIREWALL) && *dstID == HOST_ID) {
		send_trace_notify(ctx, TRACE_TO_HOST, SECLABEL, HOST_ID, 0,
				  HOST_IFINDEX, reason, monitor);
		return redirect(HOST_IFINDEX, BPF_F_INGRESS);
	}
#endif

pass_to_stack:
#ifdef ENABLE_ROUTING
	ret = ipv6_l3(ctx, l3_off, NULL, (__u8 *) &router_mac.addr, METRIC_EGRESS);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
#endif

	if (ipv6_store_flowlabel(ctx, l3_off, SECLABEL_NB) < 0)
		return DROP_WRITE_ERROR;

#ifdef ENABLE_WIREGUARD
	if (dst_remote_ep)
		set_encrypt_mark(ctx);
	else
#elif !defined(TUNNEL_MODE)
# ifdef ENABLE_IPSEC
	if (encrypt_key && tunnel_endpoint) {
		set_encrypt_key_mark(ctx, encrypt_key);
#  ifdef IP_POOLS
		set_encrypt_dip(ctx, tunnel_endpoint);
#  endif /* IP_POOLS */
	} else
# endif /* ENABLE_IPSEC */
#endif /* ENABLE_WIREGUARD */
	{
#ifdef ENABLE_IDENTITY_MARK
		/* Always encode the source identity when passing to the stack.
		 * If the stack hairpins the packet back to a local endpoint the
		 * source identity can still be derived even if SNAT is
		 * performed by a component such as portmap.
		 */
		ctx->mark |= MARK_MAGIC_IDENTITY;
		set_identity_mark(ctx, SECLABEL);
#endif
	}

#ifdef TUNNEL_MODE
encrypt_to_stack:
#endif
	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, *dstID, 0, 0,
			  reason, monitor);

	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, 0);

	return CTX_ACT_OK;
}

static __always_inline int handle_ipv6(struct __ctx_buff *ctx, __u32 *dstID)
{
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* Handle special ICMPv6 messages. This includes echo requests to the
	 * logical router address, neighbour advertisements to the router.
	 * All remaining packets are subjected to forwarding into the container.
	 */
	if (unlikely(ip6->nexthdr == IPPROTO_ICMPV6)) {
		if (data + sizeof(*ip6) + ETH_HLEN + sizeof(struct icmp6hdr) > data_end)
			return DROP_INVALID;

		ret = icmp6_handle(ctx, ETH_HLEN, ip6, METRIC_EGRESS);
		if (IS_ERR(ret))
			return ret;
	}

	/* Perform L3 action on the frame */
	tuple.nexthdr = ip6->nexthdr;
	return ipv6_l3_from_lxc(ctx, &tuple, ETH_HLEN, ip6, dstID);
}

declare_tailcall_if(__or3(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6),
			  is_defined(DEBUG)), CILIUM_CALL_IPV6_FROM_LXC)
int tail_handle_ipv6(struct __ctx_buff *ctx)
{
	__u32 dstID = 0;
	int ret = handle_ipv6(ctx, &dstID);

	if (IS_ERR(ret))
		return send_drop_notify(ctx, SECLABEL, dstID, 0, ret,
					CTX_ACT_DROP, METRIC_EGRESS);

#ifdef ENABLE_CUSTOM_CALLS
	if (!encode_custom_prog_meta(ctx, ret, dstID)) {
		tail_call_static(ctx, &CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV6_EGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int handle_ipv4_from_lxc(struct __ctx_buff *ctx,
						__u32 *dstID)
{
	struct ipv4_ct_tuple tuple = {};
#ifdef ENABLE_ROUTING
	union macaddr router_mac = NODE_MAC;
#endif
	void *data, *data_end;
	struct iphdr *ip4;
	int ret, verdict = 0, l3_off = ETH_HLEN, l4_off;
	struct csum_offset csum_off = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	__be32 orig_dip;
	__u32 tunnel_endpoint = 0;
	__u8 encrypt_key = 0;
	__u32 monitor = 0;
	__u8 ct_ret;
	bool hairpin_flow = false; /* endpoint wants to access itself via service IP */
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	bool has_l4_header = false;
	bool __maybe_unused dst_remote_ep = false;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

/* If IPv4 fragmentation is disabled
 * AND a IPv4 fragmented packet is received,
 * then drop the packet.
 */
#ifndef ENABLE_IPV4_FRAGMENTS
	if (ipv4_is_fragment(ip4))
		return DROP_FRAG_NOSUPPORT;
#endif

	has_l4_header = ipv4_has_l4_header(ip4);

	tuple.nexthdr = ip4->protocol;

	if (unlikely(!is_valid_lxc_src_ipv4(ip4)))
		return DROP_INVALID_SIP;

	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);

#ifdef ENABLE_PER_PACKET_LB
	{
		struct lb4_service *svc;
		struct lb4_key key = {};

		ret = lb4_extract_key(ctx, ip4, l4_off, &key, &csum_off,
				      CT_EGRESS);
		if (IS_ERR(ret)) {
			if (ret == DROP_NO_SERVICE || ret == DROP_UNKNOWN_L4)
				goto skip_service_lookup;
			else
				return ret;
		}

		svc = lb4_lookup_service(&key, is_defined(ENABLE_NODEPORT));
		if (svc) {
			ret = lb4_local(get_ct_map4(&tuple), ctx, l3_off, l4_off,
					&csum_off, &key, &tuple, svc, &ct_state_new,
					ip4->saddr, has_l4_header, false);
			if (IS_ERR(ret))
				return ret;
			hairpin_flow |= ct_state_new.loopback;
		}
	}

skip_service_lookup:
#endif /* ENABLE_PER_PACKET_LB */

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
	 * POLICY_SKIP if the packet is a reply packet to an existing incoming
	 * connection.
	 */
	ct_ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_EGRESS,
			    &ct_state, &monitor);
	if (ct_ret < 0)
		return ct_ret;

	/* Check it this is return traffic to an ingress proxy. */
	if ((ct_ret == CT_REPLY || ct_ret == CT_RELATED) && ct_state.proxy_redirect) {
		/* Stack will do a socket match and deliver locally. */
		return ctx_redirect_to_proxy4(ctx, &tuple, 0, false);
	}

	/* Determine the destination category for policy fallback. */
	if (1) {
		struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(orig_dip);
		if (info != NULL && info->sec_label) {
			*dstID = info->sec_label;
			tunnel_endpoint = info->tunnel_endpoint;
			encrypt_key = get_min_encrypt_key(info->key);
#ifdef ENABLE_WIREGUARD
			/* If we detect that the dst is a remote endpoint, we
			 * need to mark the packet. The ip rule which matches
			 * on the MARK_MAGIC_ENCRYPT mark will steer the packet
			 * to the Wireguard tunnel. The marking happens lower
			 * in the code in the same place where we handle IPSec.
			 */
			if (info->tunnel_endpoint != 0 &&
			    info->sec_label != HOST_ID &&
			    info->sec_label != REMOTE_NODE_ID)
				dst_remote_ep = true;
#endif /* ENABLE_WIREGUARD */
		} else {
			*dstID = WORLD_ID;
		}

		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   orig_dip, *dstID);
	}

	/* When an endpoint connects to itself via service clusterIP, we need
	 * to skip the policy enforcement. If we didn't, the user would have to
	 * define policy rules to allow pods to talk to themselves. We still
	 * want to execute the conntrack logic so that replies can be correctly
	 * matched.
	 */
	if (hairpin_flow)
		goto skip_policy_enforcement;

	/* If the packet is in the establishing direction and it's destined
	 * within the cluster, it must match policy or be dropped. If it's
	 * bound for the host/outside, perform the CIDR policy check.
	 */
	verdict = policy_can_egress4(ctx, &tuple, SECLABEL, *dstID,
				     &policy_match_type, &audited);

	if (ct_ret != CT_REPLY && ct_ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, *dstID, tuple.dport,
					   tuple.nexthdr, POLICY_EGRESS, 0,
					   verdict, policy_match_type, audited);
		return verdict;
	}

skip_policy_enforcement:
	switch (ct_ret) {
	case CT_NEW:
		if (!hairpin_flow)
			send_policy_verdict_notify(ctx, *dstID, tuple.dport,
						   tuple.nexthdr, POLICY_EGRESS, 0,
						   verdict, policy_match_type, audited);
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
		ret = ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple, ctx,
				 CT_EGRESS, &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;
		break;

	case CT_REOPENED:
		if (!hairpin_flow)
			send_policy_verdict_notify(ctx, *dstID, tuple.dport,
						   tuple.nexthdr, POLICY_EGRESS, 0,
						   verdict, policy_match_type, audited);
	case CT_ESTABLISHED:
		/* Did we end up at a stale non-service entry? Recreate if so. */
		if (unlikely(ct_state.rev_nat_index != ct_state_new.rev_nat_index))
			goto ct_recreate4;
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(ctx);

#ifdef ENABLE_NODEPORT
		/* This handles reply traffic for the case where the nodeport EP
		 * is local to the node. We'll redirect to bpf_host egress to
		 * perform the reverse DNAT.
		 */
		if (ct_state.node_port) {
			ctx->tc_index |= TC_INDEX_F_SKIP_RECIRCULATION;
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_REVNAT);
			return DROP_MISSED_TAIL_CALL;
		}
# ifdef ENABLE_DSR
		if (ct_state.dsr) {
			ret = xlate_dsr_v4(ctx, &tuple, l4_off, has_l4_header);
			if (ret != 0)
				return ret;
		}
# endif /* ENABLE_DSR */
#endif /* ENABLE_NODEPORT */

		if (ct_state.rev_nat_index) {
			ret = lb4_rev_nat(ctx, l3_off, l4_off, &csum_off,
					  &ct_state, &tuple, 0, has_l4_header);
			if (IS_ERR(ret))
				return ret;
		}
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	hairpin_flow |= ct_state.loopback;

	if (redirect_to_proxy(verdict, ct_ret)) {
		/* Trace the packet before it is forwarded to proxy */
		send_trace_notify(ctx, TRACE_TO_PROXY, SECLABEL, 0,
				  0, 0, ct_ret, monitor);
		return ctx_redirect_to_proxy4(ctx, &tuple, verdict, false);
	}

	/* After L4 write in port mapping: revalidate for direct packet access */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	orig_dip = ip4->daddr;

	/* Allow a hairpin packet to be redirected even if ENABLE_ROUTING is
	 * disabled. Otherwise, the packet will be dropped by the kernel if
	 * it is going to be routed via an interface it came from after it has
	 * been passed to the stack.
	 */
	if (is_defined(ENABLE_ROUTING) || hairpin_flow) {
		struct endpoint_info *ep;

		/* Lookup IPv4 address, this will return a match if:
		 *  - The destination IP address belongs to a local endpoint
		 *    managed by cilium
		 *  - The destination IP address is an IP address associated with the
		 *    host itself
		 *  - The destination IP address belongs to endpoint itself.
		 */
		ep = lookup_ip4_endpoint(ip4);
		if (ep) {
#ifdef ENABLE_ROUTING
			if (ep->flags & ENDPOINT_F_HOST) {
#ifdef HOST_IFINDEX
				goto to_host;
#else
				return DROP_HOST_UNREACHABLE;
#endif
			}
#endif /* ENABLE_ROUTING */
			policy_clear_mark(ctx);
			return ipv4_local_delivery(ctx, l3_off, SECLABEL, ip4,
						   ep, METRIC_EGRESS, false);
		}
	}

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)
	/* If the destination is the local host and per-endpoint routes are
	 * enabled, jump to the bpf_host program to enforce ingress host policies.
	 */
	if (*dstID == HOST_ID) {
		ctx_store_meta(ctx, CB_FROM_HOST, 0);
		tail_call_static(ctx, &POLICY_CALL_MAP, HOST_EP_ID);
		return DROP_MISSED_TAIL_CALL;
	}
#endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */

#ifdef ENABLE_EGRESS_GATEWAY
	{
		struct egress_gw_policy_entry *egress_gw_policy;
		struct endpoint_key key = {};

		if (is_cluster_destination(ip4, *dstID, tunnel_endpoint))
			goto skip_egress_gateway;

		/* If the packet is a reply or is related, it means that outside
		 * has initiated the connection, and so we should skip egress
		 * gateway, since an egress policy is only matching connections
		 * originating from a pod.
		 */
		if (ct_ret == CT_REPLY || ct_ret == CT_RELATED)
			goto skip_egress_gateway;

		egress_gw_policy = lookup_ip4_egress_gw_policy(ip4->saddr, ip4->daddr);
		if (!egress_gw_policy)
			goto skip_egress_gateway;

		/* Encap and redirect the packet to egress gateway node through a tunnel.
		 * Even if the tunnel endpoint is on the same host, follow the same data
		 * path to be consistent. In future, it can be optimized by directly
		 * direct to external interface.
		 */
		ret = encap_and_redirect_lxc(ctx, egress_gw_policy->gateway_ip, encrypt_key,
					     &key, SECLABEL, monitor);
		if (ret == IPSEC_ENDPOINT)
			goto encrypt_to_stack;
		else
			return ret;
	}
skip_egress_gateway:
#endif

#ifdef TUNNEL_MODE
# ifdef ENABLE_WIREGUARD
	/* In the tunnel mode we encapsulate pod2pod traffic only via Wireguard
	 * device, i.e. we do not encapsulate twice.
	 */
	if (!dst_remote_ep)
# endif /* ENABLE_WIREGUARD */
	{
		struct endpoint_key key = {};

		key.ip4 = orig_dip & IPV4_MASK;
		key.family = ENDPOINT_KEY_IPV4;

		ret = encap_and_redirect_lxc(ctx, tunnel_endpoint, encrypt_key,
									 &key, SECLABEL, monitor);
		if (ret == DROP_NO_TUNNEL_ENDPOINT)
			goto pass_to_stack;
		/* If not redirected noteably due to IPSEC then pass up to stack
		 * for further processing.
		 */
		else if (ret == IPSEC_ENDPOINT)
			goto encrypt_to_stack;
		/* This is either redirect by encap code or an error has
		 * occurred either way return and stack will consume ctx.
		 */
		else
			return ret;
	}
#endif /* TUNNEL_MODE */
	if (is_defined(ENABLE_REDIRECT_FAST))
		return redirect_direct_v4(ctx, l3_off, ip4);

	goto pass_to_stack;

#ifdef ENABLE_ROUTING
to_host:
	if (is_defined(ENABLE_HOST_FIREWALL) && *dstID == HOST_ID) {
		send_trace_notify(ctx, TRACE_TO_HOST, SECLABEL, HOST_ID, 0,
				  HOST_IFINDEX, ct_ret, monitor);
		return redirect(HOST_IFINDEX, BPF_F_INGRESS);
	}
#endif

pass_to_stack:
#ifdef ENABLE_ROUTING
	ret = ipv4_l3(ctx, l3_off, NULL, (__u8 *) &router_mac.addr, ip4);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
#endif

#ifdef ENABLE_WIREGUARD
	if (dst_remote_ep)
		set_encrypt_mark(ctx);
	else /* Wireguard and identity mark are mutually exclusive */
#elif !defined(TUNNEL_MODE)
# ifdef ENABLE_IPSEC
	if (encrypt_key && tunnel_endpoint) {
		set_encrypt_key_mark(ctx, encrypt_key);
#  ifdef IP_POOLS
		set_encrypt_dip(ctx, tunnel_endpoint);
#  endif /* IP_POOLS */
	} else
# endif /* ENABLE_IPSEC */
#endif /* ENABLE_WIREGUARD */
	{
#ifdef ENABLE_IDENTITY_MARK
		/* Always encode the source identity when passing to the stack.
		 * If the stack hairpins the packet back to a local endpoint the
		 * source identity can still be derived even if SNAT is
		 * performed by a component such as portmap.
		 */
		ctx->mark |= MARK_MAGIC_IDENTITY;
		set_identity_mark(ctx, SECLABEL);
#endif
	}

#if defined(TUNNEL_MODE) || defined(ENABLE_EGRESS_GATEWAY)
encrypt_to_stack:
#endif
	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, *dstID, 0, 0,
			  ct_ret, monitor);
	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, 0);
	return CTX_ACT_OK;
}

declare_tailcall_if(__or3(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6),
			  is_defined(DEBUG)), CILIUM_CALL_IPV4_FROM_LXC)
int tail_handle_ipv4(struct __ctx_buff *ctx)
{
	__u32 dstID = 0;
	int ret = handle_ipv4_from_lxc(ctx, &dstID);

	if (IS_ERR(ret))
		return send_drop_notify(ctx, SECLABEL, dstID, 0, ret,
					CTX_ACT_DROP, METRIC_EGRESS);

#ifdef ENABLE_CUSTOM_CALLS
	if (!encode_custom_prog_meta(ctx, ret, dstID)) {
		tail_call_static(ctx, &CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV4_EGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

#ifdef ENABLE_ARP_RESPONDER
/*
 * ARP responder for ARP requests from container
 * Respond to IPV4_GATEWAY with NODE_MAC
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_ARP)
int tail_handle_arp(struct __ctx_buff *ctx)
{
	union macaddr mac = NODE_MAC;
	union macaddr smac;
	__be32 sip;
	__be32 tip;

	/* Pass any unknown ARP requests to the Linux stack */
	if (!arp_validate(ctx, &mac, &smac, &sip, &tip))
		return CTX_ACT_OK;

	/*
	 * The endpoint is expected to make ARP requests for its gateway IP.
	 * Most of the time, the gateway IP configured on the endpoint is
	 * IPV4_GATEWAY but it may not be the case if after cilium agent reload
	 * a different gateway is chosen. In such a case, existing endpoints
	 * will have an old gateway configured. Since we don't know the IP of
	 * previous gateways, we answer requests for all IPs with the exception
	 * of the LXC IP (to avoid specific problems, like IP duplicate address
	 * detection checks that might run within the container).
	 */
	if (tip == LXC_IPV4)
		return CTX_ACT_OK;

	return arp_respond(ctx, &mac, tip, &smac, sip, 0);
}
#endif /* ENABLE_ARP_RESPONDER */
#endif /* ENABLE_IPV4 */

/* Attachment/entry point is ingress for veth, egress for ipvlan.
 * It corresponds to packets leaving the container.
 */
__section("from-container")
int handle_xgress(struct __ctx_buff *ctx)
{
	__u16 proto;
	int ret;

	bpf_clear_meta(ctx);

	send_trace_notify(ctx, TRACE_FROM_LXC, SECLABEL, 0, 0, 0, 0,
			  TRACE_PAYLOAD_LEN);

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		edt_set_aggregate(ctx, LXC_ID);
		invoke_tailcall_if(__or3(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6),
					 is_defined(DEBUG)),
				   CILIUM_CALL_IPV6_FROM_LXC, tail_handle_ipv6);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		edt_set_aggregate(ctx, LXC_ID);
		invoke_tailcall_if(__or3(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6),
					 is_defined(DEBUG)),
				   CILIUM_CALL_IPV4_FROM_LXC, tail_handle_ipv4);
		break;
#ifdef ENABLE_ARP_PASSTHROUGH
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
#elif defined(ENABLE_ARP_RESPONDER)
	case bpf_htons(ETH_P_ARP):
		ep_tail_call(ctx, CILIUM_CALL_ARP);
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif /* ENABLE_ARP_RESPONDER */
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, SECLABEL, 0, 0, ret, CTX_ACT_DROP,
					METRIC_EGRESS);
	return ret;
}

#ifdef ENABLE_IPV6
static __always_inline int
ipv6_policy(struct __ctx_buff *ctx, int ifindex, __u32 src_label, __u8 *reason,
	    struct ipv6_ct_tuple *tuple_out, __u16 *proxy_port,
	    bool from_host __maybe_unused)
{
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	int ret, l4_off, verdict, hdrlen;
	struct ct_state ct_state = {};
	struct ct_state ct_state_new = {};
	bool skip_ingress_proxy = false;
	union v6addr orig_sip;
	__u32 monitor = 0;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	policy_clear_mark(ctx);
	tuple.nexthdr = ip6->nexthdr;

	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);
	ipv6_addr_copy(&orig_sip, (union v6addr *) &ip6->saddr);

	/* If packet is coming from the ingress proxy we have to skip
	 * redirection to the ingress proxy as we would loop forever.
	 */
	skip_ingress_proxy = tc_index_skip_ingress_proxy(ctx);

	hdrlen = ipv6_hdrlen(ctx, ETH_HLEN, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = ETH_HLEN + hdrlen;
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off, CT_INGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;

	*reason = ret;

	/* Check it this is return traffic to an egress proxy.
	 * Do not redirect again if the packet is coming from the egress proxy.
	 */
	if ((ret == CT_REPLY || ret == CT_RELATED) && ct_state.proxy_redirect &&
	    !tc_index_skip_egress_proxy(ctx)) {
		/* This is a reply, the proxy port does not need to be embedded
		 * into ctx->mark and *proxy_port can be left unset.
		 */
		send_trace_notify6(ctx, TRACE_TO_PROXY, src_label, SECLABEL, &orig_sip,
				  0, ifindex, 0, monitor);
		if (tuple_out)
			memcpy(tuple_out, &tuple, sizeof(tuple));
		return POLICY_ACT_PROXY_REDIRECT;
	}

	if (unlikely(ct_state.rev_nat_index)) {
		int ret2;

		ret2 = lb6_rev_nat(ctx, l4_off, &csum_off,
				   ct_state.rev_nat_index, &tuple, 0);
		if (IS_ERR(ret2))
			return ret2;
	}

	verdict = policy_can_access_ingress(ctx, src_label, SECLABEL,
					    tuple.dport, tuple.nexthdr, false,
					    &policy_match_type, &audited);

	/* Reply packets and related packets are allowed, all others must be
	 * permitted by policy.
	 */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, src_label, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, 1,
					   verdict, policy_match_type, audited);
		return verdict;
	}

	if (skip_ingress_proxy)
		verdict = 0;

	if (ret == CT_NEW || ret == CT_REOPENED) {
		send_policy_verdict_notify(ctx, src_label, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, 1,
					   verdict, policy_match_type, audited);
	}

	if (ret == CT_NEW) {
#ifdef ENABLE_DSR
	{
		bool dsr = false;

		ret = handle_dsr_v6(ctx, &dsr);
		if (ret != 0)
			return ret;

		ct_state_new.dsr = dsr;
	}
#endif /* ENABLE_DSR */

		ct_state_new.src_sec_id = src_label;
		ct_state_new.node_port = ct_state.node_port;
		ct_state_new.ifindex = ct_state.ifindex;
		ret = ct_create6(get_ct_map6(&tuple), &CT_MAP_ANY6, &tuple, ctx, CT_INGRESS,
				 &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;

		/* NOTE: tuple has been invalidated after this */
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	if (redirect_to_proxy(verdict, *reason)) {
		*proxy_port = verdict;
		send_trace_notify6(ctx, TRACE_TO_PROXY, src_label, SECLABEL, &orig_sip,
				  0, ifindex, *reason, monitor);
		if (tuple_out)
			memcpy(tuple_out, &tuple, sizeof(tuple));
		return POLICY_ACT_PROXY_REDIRECT;
	}
	/* Not redirected to host / proxy. */
	send_trace_notify6(ctx, TRACE_TO_LXC, src_label, SECLABEL, &orig_sip,
			   LXC_ID, ifindex, *reason, monitor);

#if !defined(ENABLE_ROUTING) && defined(TUNNEL_MODE) && !defined(ENABLE_NODEPORT)
	/* See comment in IPv4 path. */
	ctx_change_type(ctx, PACKET_HOST);
#else
	ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	if (ifindex)
		return redirect_ep(ctx, ifindex, from_host);
#endif /* ENABLE_ROUTING && TUNNEL_MODE && !ENABLE_NODEPORT */

	return CTX_ACT_OK;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		    CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY)
int tail_ipv6_policy(struct __ctx_buff *ctx)
{
	struct ipv6_ct_tuple tuple = {};
	int ret, ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	__u32 src_label = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	bool proxy_redirect __maybe_unused = false;
	__u16 proxy_port = 0;
	__u8 reason = 0;

	ctx_store_meta(ctx, CB_SRC_LABEL, 0);
	ctx_store_meta(ctx, CB_FROM_HOST, 0);

	ret = ipv6_policy(ctx, ifindex, src_label, &reason, &tuple,
			  &proxy_port, from_host);
	if (ret == POLICY_ACT_PROXY_REDIRECT) {
		ret = ctx_redirect_to_proxy6(ctx, &tuple, proxy_port, from_host);
		proxy_redirect = true;
	}
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_label, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

	/* Store meta: essential for proxy ingress, see bpf_host.c */
	ctx_store_meta(ctx, CB_PROXY_MAGIC, ctx->mark);

#ifdef ENABLE_CUSTOM_CALLS
	/* Make sure we skip the tail call when the packet is being redirected
	 * to a L7 proxy, to avoid running the custom program twice on the
	 * incoming packet (before redirecting, and on the way back from the
	 * proxy).
	 */
	if (!proxy_redirect && !encode_custom_prog_meta(ctx, ret, src_label)) {
		tail_call_static(ctx, &CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV6_INGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

declare_tailcall_if(__or(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		    CILIUM_CALL_IPV6_TO_ENDPOINT)
int tail_ipv6_to_endpoint(struct __ctx_buff *ctx)
{
	__u32 src_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool proxy_redirect __maybe_unused = false;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u16 proxy_port = 0;
	__u8 reason;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto out;
	}

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(src_identity)) {
		union v6addr *src = (union v6addr *) &ip6->saddr;
		struct remote_endpoint_info *info;

		info = lookup_ip6_remote_endpoint(src);
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
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   ((__u32 *) src)[3], src_identity);
	}

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, LXC_ID, SECLABEL);

#ifdef LOCAL_DELIVERY_METRICS
	update_metrics(ctx_full_len(ctx), METRIC_INGRESS, REASON_FORWARDED);
#endif
	ctx_store_meta(ctx, CB_SRC_LABEL, 0);

	ret = ipv6_policy(ctx, 0, src_identity, &reason, NULL,
			  &proxy_port, true);
	if (ret == POLICY_ACT_PROXY_REDIRECT) {
		ret = ctx_redirect_to_proxy_hairpin(ctx, proxy_port);
		proxy_redirect = true;
	}
out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_identity, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

#ifdef ENABLE_CUSTOM_CALLS
	/* Make sure we skip the tail call when the packet is being redirected
	 * to a L7 proxy, to avoid running the custom program twice on the
	 * incoming packet (before redirecting, and on the way back from the
	 * proxy).
	 */
	if (!proxy_redirect &&
	    !encode_custom_prog_meta(ctx, ret, src_identity)) {
		tail_call_static(ctx, &CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV6_INGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int
ipv4_policy(struct __ctx_buff *ctx, int ifindex, __u32 src_label, __u8 *reason,
	    struct ipv4_ct_tuple *tuple_out, __u16 *proxy_port,
	    bool from_host __maybe_unused)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct csum_offset csum_off = {};
	int ret, verdict = 0, l3_off = ETH_HLEN, l4_off;
	struct ct_state ct_state = {};
	struct ct_state ct_state_new = {};
	bool skip_ingress_proxy = false;
	bool is_untracked_fragment = false;
	bool has_l4_header = false;
	__u32 monitor = 0;
	__be32 orig_sip;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	has_l4_header = ipv4_has_l4_header(ip4);

	policy_clear_mark(ctx);
	tuple.nexthdr = ip4->protocol;

	/* If packet is coming from the ingress proxy we have to skip
	 * redirection to the ingress proxy as we would loop forever.
	 */
	skip_ingress_proxy = tc_index_skip_ingress_proxy(ctx);

	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;
	orig_sip = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);
	if (has_l4_header)
		csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);
#ifndef ENABLE_IPV4_FRAGMENTS
	/* Indicate that this is a datagram fragment for which we cannot
	 * retrieve L4 ports. Do not set flag if we support fragmentation.
	 */
	is_untracked_fragment = ipv4_is_fragment(ip4);
#endif

	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_INGRESS, &ct_state,
			 &monitor);
	if (ret < 0)
		return ret;

	*reason = ret;

	/* Check it this is return traffic to an egress proxy.
	 * Do not redirect again if the packet is coming from the egress proxy.
	 */
	relax_verifier();
	if ((ret == CT_REPLY || ret == CT_RELATED) && ct_state.proxy_redirect &&
	    !tc_index_skip_egress_proxy(ctx)) {
		/* This is a reply, the proxy port does not need to be embedded
		 * into ctx->mark and *proxy_port can be left unset.
		 */
		send_trace_notify4(ctx, TRACE_TO_PROXY, src_label, SECLABEL, orig_sip,
				  0, ifindex, 0, monitor);
		if (tuple_out)
			*tuple_out = tuple;
		return POLICY_ACT_PROXY_REDIRECT;
	}

#ifdef ENABLE_NAT46
	if (ctx_load_meta(ctx, CB_NAT46_STATE) == NAT46) {
		ep_tail_call(ctx, CILIUM_CALL_NAT46);
		return DROP_MISSED_TAIL_CALL;
	}
#endif
	if (unlikely(ret == CT_REPLY && ct_state.rev_nat_index &&
		     !ct_state.loopback)) {
		int ret2;

		ret2 = lb4_rev_nat(ctx, l3_off, l4_off, &csum_off,
				   &ct_state, &tuple,
				   REV_NAT_F_TUPLE_SADDR, has_l4_header);
		if (IS_ERR(ret2))
			return ret2;
	}

#if defined(ENABLE_PER_PACKET_LB) && !defined(DISABLE_LOOPBACK_LB)
	/* When an endpoint connects to itself via service clusterIP, we need
	 * to skip the policy enforcement. If we didn't, the user would have to
	 * define policy rules to allow pods to talk to themselves. We still
	 * want to execute the conntrack logic so that replies can be correctly
	 * matched.
	 */
	if (unlikely(ct_state.loopback))
		goto skip_policy_enforcement;
#endif /* ENABLE_PER_PACKET_LB && !DISABLE_LOOPBACK_LB */

	verdict = policy_can_access_ingress(ctx, src_label, SECLABEL,
					    tuple.dport, tuple.nexthdr,
					    is_untracked_fragment,
					    &policy_match_type, &audited);

	/* Reply packets and related packets are allowed, all others must be
	 * permitted by policy.
	 */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, src_label, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, 0,
					   verdict, policy_match_type, audited);
		return verdict;
	}

	if (skip_ingress_proxy)
		verdict = 0;

	if (ret == CT_NEW || ret == CT_REOPENED) {
		send_policy_verdict_notify(ctx, src_label, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, 0,
					   verdict, policy_match_type, audited);
	}

#if !defined(ENABLE_HOST_SERVICES_FULL) && !defined(DISABLE_LOOPBACK_LB)
skip_policy_enforcement:
#endif /* !ENABLE_HOST_SERVICES_FULL && !DISABLE_LOOPBACK_LB */

	if (ret == CT_NEW) {
#ifdef ENABLE_DSR
	{
		bool dsr = false;

		ret = handle_dsr_v4(ctx, &dsr);
		if (ret != 0)
			return ret;

		ct_state_new.dsr = dsr;
	}
#endif /* ENABLE_DSR */

		ct_state_new.src_sec_id = src_label;
		ct_state_new.node_port = ct_state.node_port;
		ct_state_new.ifindex = ct_state.ifindex;
		ret = ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple, ctx, CT_INGRESS,
				 &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;

		/* NOTE: tuple has been invalidated after this */
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	if (redirect_to_proxy(verdict, *reason)) {
		*proxy_port = verdict;
		send_trace_notify4(ctx, TRACE_TO_PROXY, src_label, SECLABEL, orig_sip,
				  0, ifindex, *reason, monitor);
		if (tuple_out)
			*tuple_out = tuple;
		return POLICY_ACT_PROXY_REDIRECT;
	}
	/* Not redirected to host / proxy. */
	send_trace_notify4(ctx, TRACE_TO_LXC, src_label, SECLABEL, orig_sip,
			   LXC_ID, ifindex, *reason, monitor);

#if !defined(ENABLE_ROUTING) && defined(TUNNEL_MODE) && !defined(ENABLE_NODEPORT)
	/* In tunneling mode, we execute this code to send the packet from
	 * cilium_vxlan to lxc*. If we're using kube-proxy, we don't want to use
	 * redirect() because that would bypass conntrack and the reverse DNAT.
	 * Thus, we send packets to the stack, but since they have the wrong
	 * Ethernet addresses, we need to mark them as PACKET_HOST or the kernel
	 * will drop them.
	 * See #14646 for details.
	 */
	ctx_change_type(ctx, PACKET_HOST);
#else
	ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	if (ifindex)
		return redirect_ep(ctx, ifindex, from_host);
#endif /* ENABLE_ROUTING && TUNNEL_MODE && !ENABLE_NODEPORT */

	return CTX_ACT_OK;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		    CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY)
int tail_ipv4_policy(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	int ret, ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	__u32 src_label = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	bool proxy_redirect __maybe_unused = false;
	__u16 proxy_port = 0;
	__u8 reason = 0;

	ctx_store_meta(ctx, CB_SRC_LABEL, 0);
	ctx_store_meta(ctx, CB_FROM_HOST, 0);

	ret = ipv4_policy(ctx, ifindex, src_label, &reason, &tuple,
			  &proxy_port, from_host);
	if (ret == POLICY_ACT_PROXY_REDIRECT) {
		ret = ctx_redirect_to_proxy4(ctx, &tuple, proxy_port, from_host);
		proxy_redirect = true;
	}
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_label, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

	/* Store meta: essential for proxy ingress, see bpf_host.c */
	ctx_store_meta(ctx, CB_PROXY_MAGIC, ctx->mark);

#ifdef ENABLE_CUSTOM_CALLS
	/* Make sure we skip the tail call when the packet is being redirected
	 * to a L7 proxy, to avoid running the custom program twice on the
	 * incoming packet (before redirecting, and on the way back from the
	 * proxy).
	 */
	if (!proxy_redirect && !encode_custom_prog_meta(ctx, ret, src_label)) {
		tail_call_static(ctx, &CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV4_INGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

declare_tailcall_if(__or(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		    CILIUM_CALL_IPV4_TO_ENDPOINT)
int tail_ipv4_to_endpoint(struct __ctx_buff *ctx)
{
	__u32 src_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool proxy_redirect __maybe_unused = false;
	void *data, *data_end;
	struct iphdr *ip4;
	__u16 proxy_port = 0;
	__u8 reason;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto out;
	}

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(src_identity)) {
		struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(ip4->saddr);
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
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->saddr, src_identity);
	}

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, LXC_ID, SECLABEL);

#ifdef LOCAL_DELIVERY_METRICS
	update_metrics(ctx_full_len(ctx), METRIC_INGRESS, REASON_FORWARDED);
#endif
	ctx_store_meta(ctx, CB_SRC_LABEL, 0);

	ret = ipv4_policy(ctx, 0, src_identity, &reason, NULL,
			  &proxy_port, true);
	if (ret == POLICY_ACT_PROXY_REDIRECT) {
		ret = ctx_redirect_to_proxy_hairpin(ctx, proxy_port);
		proxy_redirect = true;
	}
out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_identity, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

#ifdef ENABLE_CUSTOM_CALLS
	/* Make sure we skip the tail call when the packet is being redirected
	 * to a L7 proxy, to avoid running the custom program twice on the
	 * incoming packet (before redirecting, and on the way back from the
	 * proxy).
	 */
	if (!proxy_redirect &&
	    !encode_custom_prog_meta(ctx, ret, src_identity)) {
		tail_call_static(ctx, &CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV4_INGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}
#endif /* ENABLE_IPV4 */

/* Handle policy decisions as the packet makes its way towards the endpoint.
 * Previously, the packet may have come from another local endpoint, another
 * endpoint in the cluster, or from the big blue room (as identified by the
 * contents of ctx / CB_SRC_LABEL. Determine whether the traffic may be
 * passed into the endpoint or if it needs further inspection by a userspace
 * proxy.
 *
 * This program will be tail called to in ipv{4,6}_local_delivery from either
 * bpf_host, bpf_overlay (if coming from the tunnel), or bpf_lxc (if coming
 * from another local pod).
 */
__section_tail(CILIUM_MAP_POLICY, TEMPLATE_LXC_ID)
int handle_policy(struct __ctx_buff *ctx)
{
	__u32 src_label = ctx_load_meta(ctx, CB_SRC_LABEL);
	__u16 proto;
	int ret;

	if (!validate_ethertype(ctx, &proto)) {
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
		return send_drop_notify(ctx, src_label, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}

#ifdef ENABLE_NAT46
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_NAT64)
int tail_ipv6_to_ipv4(struct __ctx_buff *ctx)
{
	int ret;

	ret = ipv6_to_ipv4(ctx, 14, LXC_IPV4);
	if (IS_ERR(ret))
		goto drop_err;

	cilium_dbg_capture(ctx, DBG_CAPTURE_AFTER_V64, ctx->ingress_ifindex);

	ctx_store_meta(ctx, CB_NAT46_STATE, NAT64);

	invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
			   CILIUM_CALL_IPV4_FROM_LXC, tail_handle_ipv4);
drop_err:
	return send_drop_notify(ctx, SECLABEL, 0, 0, ret, CTX_ACT_DROP,
				METRIC_EGRESS);
}

static __always_inline int handle_ipv4_to_ipv6(struct __ctx_buff *ctx)
{
	union v6addr dp = {};
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	BPF_V6(dp, LXC_IP);
	return ipv4_to_ipv6(ctx, ip4, 14, &dp);

}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_NAT46)
int tail_ipv4_to_ipv6(struct __ctx_buff *ctx)
{
	int ret;

	ret = handle_ipv4_to_ipv6(ctx);
	if (IS_ERR(ret))
		goto drop_err;

	cilium_dbg_capture(ctx, DBG_CAPTURE_AFTER_V46, ctx->ingress_ifindex);

	invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
			   CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY, tail_ipv6_policy);
drop_err:
	return send_drop_notify(ctx, SECLABEL, 0, 0, ret, CTX_ACT_DROP,
				METRIC_INGRESS);
}
#endif
BPF_LICENSE("GPL");

/* Attached to the lxc device on the way to the container, only if endpoint
 * routes are enabled.
 */
__section("to-container")
int handle_to_container(struct __ctx_buff *ctx)
{
	int ret, trace = TRACE_FROM_STACK;
	__u32 identity = 0;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	bpf_clear_meta(ctx);

	if (inherit_identity_from_host(ctx, &identity))
		trace = TRACE_FROM_PROXY;

	send_trace_notify(ctx, trace, identity, 0, 0,
			  ctx->ingress_ifindex, 0, TRACE_PAYLOAD_LEN);

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)
	/* If the packet comes from the hostns and per-endpoint routes are enabled,
	 * jump to bpf_host to enforce egress host policies before anything else.
	 *
	 * We will jump back to bpf_lxc once host policies are enforced. Whenever
	 * we call inherit_identity_from_host, the packet mark is cleared. Thus,
	 * when we jump back, the packet mark will have been cleared and the
	 * identity won't match HOST_ID anymore.
	 */
	if (identity == HOST_ID) {
		ctx_store_meta(ctx, CB_FROM_HOST, 1);
		ctx_store_meta(ctx, CB_DST_ENDPOINT_ID, LXC_ID);
		tail_call_static(ctx, &POLICY_CALL_MAP, HOST_EP_ID);
		return DROP_MISSED_TAIL_CALL;
	}
#endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */

	ctx_store_meta(ctx, CB_SRC_LABEL, identity);

	switch (proto) {
#if defined(ENABLE_ARP_PASSTHROUGH) || defined(ENABLE_ARP_RESPONDER)
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		invoke_tailcall_if(__or(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV6_TO_ENDPOINT, tail_ipv6_to_endpoint);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		invoke_tailcall_if(__or(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV4_TO_ENDPOINT, tail_ipv4_to_endpoint);
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, identity, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}
