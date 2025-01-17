/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "nodeport.h"

#ifdef ENABLE_NODEPORT

#ifdef ENABLE_IPV6
static __always_inline bool
nodeport_has_nat_conflict_ipv6(const struct ipv6hdr *ip6 __maybe_unused,
			       struct ipv6_nat_target *target __maybe_unused)
{
#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
	union v6addr router_ip;

	BPF_V6(router_ip, ROUTER_IP);
	if (ipv6_addr_equals((union v6addr *)&ip6->saddr, &router_ip)) {
		ipv6_addr_copy(&target->addr, &router_ip);
		target->needs_ct = true;

		return true;
	}
#endif /* TUNNEL_MODE && IS_BPF_OVERLAY */

#if defined(IS_BPF_HOST)
	const union v6addr dr_addr = IPV6_DIRECT_ROUTING;
	__u32 dr_ifindex = DIRECT_ROUTING_DEV_IFINDEX;

	/* See comment in nodeport_has_nat_conflict_ipv4(). */
	if (dr_ifindex == THIS_INTERFACE_IFINDEX &&
	    ipv6_addr_equals((union v6addr *)&ip6->saddr, &dr_addr)) {
		ipv6_addr_copy(&target->addr, &dr_addr);
		target->needs_ct = true;

		return true;
	}
#endif /* IS_BPF_HOST */

	return false;
}

static __always_inline int nodeport_snat_fwd_ipv6(struct __ctx_buff *ctx,
						  union v6addr *saddr,
						  struct trace_ctx *trace,
						  __s8 *ext_err)
{
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};
	struct ipv6_ct_tuple tuple = {};
	int hdrlen, l4_off, ret;
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	snat_v6_init_tuple(ip6, NAT_DIR_EGRESS, &tuple);
	l4_off = ETH_HLEN + hdrlen;

	if (lb_is_svc_proto(tuple.nexthdr) &&
	    nodeport_has_nat_conflict_ipv6(ip6, &target))
		goto apply_snat;

	ret = snat_v6_needs_masquerade(ctx, &tuple, l4_off, &target);
	if (IS_ERR(ret))
		goto out;

apply_snat:
	ipv6_addr_copy(saddr, &tuple.saddr);
	ret = snat_v6_nat(ctx, &tuple, l4_off, &target, trace, ext_err);
	if (IS_ERR(ret))
		goto out;

	/* See the equivalent v4 path for comment */
	if (is_defined(IS_BPF_HOST))
		ctx_snat_done_set(ctx);

out:
	if (ret == NAT_PUNT_TO_STACK)
		ret = CTX_ACT_OK;

	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_SNAT_FWD)
int tail_handle_snat_fwd_ipv6(struct __ctx_buff *ctx)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	enum trace_point obs_point;
	union v6addr saddr = {};
	int ret;
	__s8 ext_err = 0;

#ifdef IS_BPF_OVERLAY
	obs_point = TRACE_TO_OVERLAY;
#else
	obs_point = TRACE_TO_NETWORK;
#endif

	ret = nodeport_snat_fwd_ipv6(ctx, &saddr, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);

	/* contrary to tail_handle_snat_fwd_ipv4, we don't check for
	 *
	 *     ret == CTX_ACT_OK
	 *
	 * in order to emit the event, as egress gateway is not yet supported
	 * for IPv6, and so it's not possible yet for masqueraded traffic to get
	 * redirected to another interface
	 */
	send_trace_notify6(ctx, obs_point, UNKNOWN_ID, UNKNOWN_ID, &saddr,
			   TRACE_EP_ID_UNKNOWN, THIS_INTERFACE_IFINDEX,
			   trace.reason, trace.monitor);

	return ret;
}

static __always_inline int
nodeport_rev_dnat_fwd_ipv6(struct __ctx_buff *ctx, bool *snat_done,
			   bool revdnat_only __maybe_unused,
			   struct trace_ctx *trace, __s8 *ext_err __maybe_unused)
{
	struct bpf_fib_lookup_padded fib_params __maybe_unused = {};
	struct lb6_reverse_nat *nat_info;
	struct ipv6_ct_tuple tuple __align_stack_8 = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, l4_off;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ret = lb6_extract_tuple(ctx, ip6, ETH_HLEN, &l4_off, &tuple);
	if (ret < 0) {
		if (ret == DROP_UNSUPP_SERVICE_PROTO || ret == DROP_UNKNOWN_L4)
			return CTX_ACT_OK;
		return ret;
	}

	nat_info = nodeport_rev_dnat_get_info_ipv6(ctx, &tuple);
	if (!nat_info)
		return CTX_ACT_OK;

#if defined(IS_BPF_HOST) && !defined(ENABLE_SKIP_FIB)
	if (revdnat_only)
		goto skip_fib;

	fib_params.l.family = AF_INET6;
	fib_params.l.ifindex = ctx_get_ifindex(ctx);
	ipv6_addr_copy((union v6addr *)fib_params.l.ipv6_src,
		       &nat_info->address);
	ipv6_addr_copy((union v6addr *)fib_params.l.ipv6_dst,
		       &tuple.daddr);

	ret = nodeport_fib_lookup_and_redirect(ctx, &fib_params, ext_err);
	if (ret != CTX_ACT_OK)
		return ret;

skip_fib:
#endif

	ret = ct_lazy_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off, CT_INGRESS,
			      SCOPE_REVERSE, CT_ENTRY_NODEPORT | CT_ENTRY_DSR,
			      NULL, &trace->monitor);
	if (ret == CT_REPLY) {
		trace->reason = TRACE_REASON_CT_REPLY;

		ret = __lb6_rev_nat(ctx, l4_off, &tuple, nat_info);
		if (IS_ERR(ret))
			return ret;

		*snat_done = true;
	}

	return CTX_ACT_OK;
}

static __always_inline int
__handle_nat_fwd_ipv6(struct __ctx_buff *ctx, bool revdnat_only, struct trace_ctx *trace,
		      __s8 *ext_err)
{
	bool snat_done = false;
	int ret;

	ret = nodeport_rev_dnat_fwd_ipv6(ctx, &snat_done, revdnat_only, trace, ext_err);
	if (ret != CTX_ACT_OK || revdnat_only)
		return ret;

#if !defined(ENABLE_DSR) ||						\
    (defined(ENABLE_DSR) && defined(ENABLE_DSR_HYBRID)) ||		\
     defined(ENABLE_MASQUERADE_IPV6)
	if (!snat_done)
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_NODEPORT_SNAT_FWD,
					 ext_err);
#endif

	if (is_defined(IS_BPF_HOST) && snat_done)
		ctx_snat_done_set(ctx);

	return ret;
}

static __always_inline int
handle_nat_fwd_ipv6(struct __ctx_buff *ctx, struct trace_ctx *trace,
		    __s8 *ext_err)
{
	__u32 cb_nat_flags = ctx_load_and_clear_meta(ctx, CB_NAT_FLAGS);
	bool revdnat_only = cb_nat_flags & CB_NAT_FLAGS_REVDNAT_ONLY;

	return __handle_nat_fwd_ipv6(ctx, revdnat_only, trace, ext_err);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_NAT_FWD)
static __always_inline
int tail_handle_nat_fwd_ipv6(struct __ctx_buff *ctx)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	int ret;
	enum trace_point obs_point;
	__s8 ext_err = 0;

#ifdef IS_BPF_OVERLAY
	obs_point = TRACE_TO_OVERLAY;
#else
	obs_point = TRACE_TO_NETWORK;
#endif

	ret = handle_nat_fwd_ipv6(ctx, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);

	if (ret == CTX_ACT_OK)
		send_trace_notify(ctx, obs_point, UNKNOWN_ID, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, THIS_INTERFACE_IFINDEX,
				  trace.reason, trace.monitor);

	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline bool
nodeport_has_nat_conflict_ipv4(const struct iphdr *ip4 __maybe_unused,
			       struct ipv4_nat_target *target __maybe_unused)
{
#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
	if (ip4->saddr == IPV4_GATEWAY) {
		target->addr = IPV4_GATEWAY;
		target->needs_ct = true;

		return true;
	}
#endif /* TUNNEL_MODE && IS_BPF_OVERLAY */

#if defined(IS_BPF_HOST)
	__u32 dr_ifindex = DIRECT_ROUTING_DEV_IFINDEX;

	/* THIS_INTERFACE_IFINDEX == DIRECT_ROUTING_DEV_IFINDEX cannot be moved into
	 * preprocessor, as the former is known only during load time (templating).
	 * This checks whether bpf_host is running on the direct routing device.
	 */
	if (dr_ifindex == THIS_INTERFACE_IFINDEX &&
	    ip4->saddr == IPV4_DIRECT_ROUTING) {
		target->addr = IPV4_DIRECT_ROUTING;
		target->needs_ct = true;

		return true;
	}
#endif /* IS_BPF_HOST */

	return false;
}

static __always_inline int nodeport_snat_fwd_ipv4(struct __ctx_buff *ctx,
						  __u32 cluster_id __maybe_unused,
						  __be32 *saddr,
						  struct trace_ctx *trace,
						  __s8 *ext_err)
{
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
#if defined(ENABLE_CLUSTER_AWARE_ADDRESSING) && defined(ENABLE_INTER_CLUSTER_SNAT)
		.cluster_id = cluster_id,
#endif
	};
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	int l4_off, ret;
	struct endpoint_info *ep;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &tuple);
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	if (is_defined(IS_BPF_HOST)) {
		ep = __lookup_ip4_endpoint(ip4->saddr);
		if (ep && ep->parent_ifindex && ep->parent_ifindex != THIS_INTERFACE_IFINDEX) {
			/* This packet came from an endpoint with a parent interface and
			 * it is currently not egressing on its parent interface.
			 * Check if its a reply packet, if it is, redirect it to the
			 * parent interface.
			 */
			if (ipv4_load_l4_ports(ctx, ip4, l4_off, CT_EGRESS,
					       (__be16 *)&tuple.dport, NULL) < 0)
				return DROP_INVALID;

			if (ct_is_reply4(get_ct_map4(&tuple), &tuple)) {
				/* Look up the parent interface's MAC address and set it as the
				 * source MAC address of the packet. We will assume the destination
				 * MAC address is still correct. This assumption only holds if the
				 * current and parent interfaces are on the same L2 network such as
				 * in EKS.
				 */
				union macaddr smac = NATIVE_DEV_MAC_BY_IFINDEX(ep->parent_ifindex);

				if (eth_store_saddr_aligned(ctx, smac.addr, 0) < 0)
					return DROP_WRITE_ERROR;

				return ctx_redirect(ctx, ep->parent_ifindex, 0);
			}
		}
	}

	if (lb_is_svc_proto(tuple.nexthdr) &&
	    nodeport_has_nat_conflict_ipv4(ip4, &target))
		goto apply_snat;

	ret = snat_v4_needs_masquerade(ctx, &tuple, ip4, l4_off, &target);
	if (IS_ERR(ret))
		goto out;

#if defined(ENABLE_EGRESS_GATEWAY_COMMON) && defined(IS_BPF_HOST)
	if (target.egress_gateway) {
		/* Stay on the desired egress interface: */
		if (target.ifindex && target.ifindex == THIS_INTERFACE_IFINDEX)
			goto apply_snat;

		/* Send packet to the correct egress interface, and SNAT it there. */
		ret = egress_gw_fib_lookup_and_redirect(ctx, target.addr,
							tuple.daddr, target.ifindex,
							ext_err);
		if (ret != CTX_ACT_OK)
			return ret;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
	}
#endif

apply_snat:
	*saddr = tuple.saddr;
	ret = snat_v4_nat(ctx, &tuple, ip4, l4_off, ipv4_has_l4_header(ip4),
			  &target, trace, ext_err);
	if (IS_ERR(ret))
		goto out;

	/* If multiple netdevs process an outgoing packet, then this packets will
	 * be handled multiple times by the "to-netdev" section. This can lead
	 * to multiple SNATs. To prevent from that, set the SNAT done flag.
	 *
	 * XDP doesn't need the flag (there's no egress prog that would utilize it),
	 * and for overlay traffic it makes no difference whether the inner packet
	 * was SNATed.
	 */
	if (is_defined(IS_BPF_HOST))
		ctx_snat_done_set(ctx);

out:
	if (ret == NAT_PUNT_TO_STACK)
		ret = CTX_ACT_OK;

	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_SNAT_FWD)
int tail_handle_snat_fwd_ipv4(struct __ctx_buff *ctx)
{
	__u32 cluster_id = ctx_load_and_clear_meta(ctx, CB_CLUSTER_ID_EGRESS);
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	enum trace_point obs_point;
	__be32 saddr = 0;
	int ret;
	__s8 ext_err = 0;

#ifdef IS_BPF_OVERLAY
	obs_point = TRACE_TO_OVERLAY;
#else
	obs_point = TRACE_TO_NETWORK;
#endif

	ret = nodeport_snat_fwd_ipv4(ctx, cluster_id, &saddr, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);

	/* Don't emit a trace event if the packet has been redirected to another
	 * interface.
	 * This can happen for egress gateway traffic that needs to egress from
	 * the interface to which the egress IP is assigned to.
	 */
	if (ret == CTX_ACT_OK)
		send_trace_notify4(ctx, obs_point, UNKNOWN_ID, UNKNOWN_ID, saddr,
				   TRACE_EP_ID_UNKNOWN, THIS_INTERFACE_IFINDEX,
				   trace.reason, trace.monitor);

	return ret;
}

static __always_inline int
nodeport_rev_dnat_fwd_ipv4(struct __ctx_buff *ctx, bool *snat_done,
			   bool revdnat_only __maybe_unused,
			   struct trace_ctx *trace, __s8 *ext_err __maybe_unused)
{
	struct bpf_fib_lookup_padded fib_params __maybe_unused = {};
	int ret, l3_off = ETH_HLEN, l4_off;
	struct lb4_reverse_nat *nat_info;
	struct ipv4_ct_tuple tuple = {};
	struct ct_state ct_state = {};
	void *data, *data_end;
	bool has_l4_header, is_fragment;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	has_l4_header = ipv4_has_l4_header(ip4);
	is_fragment = ipv4_is_fragment(ip4);

	ret = lb4_extract_tuple(ctx, ip4, ETH_HLEN, &l4_off, &tuple);
	if (ret < 0) {
		/* If it's not a SVC protocol, we don't need to check for RevDNAT: */
		if (ret == DROP_UNSUPP_SERVICE_PROTO || ret == DROP_UNKNOWN_L4)
			return CTX_ACT_OK;
		return ret;
	}

	nat_info = nodeport_rev_dnat_get_info_ipv4(ctx, &tuple);
	if (!nat_info)
		return CTX_ACT_OK;

#if defined(IS_BPF_HOST) && !defined(ENABLE_SKIP_FIB)
	if (revdnat_only)
		goto skip_fib;

	/* Perform FIB lookup with post-RevDNAT src IP, and redirect
	 * packet to the correct egress interface:
	 */
	fib_params.l.family = AF_INET;
	fib_params.l.ifindex = ctx_get_ifindex(ctx);
	fib_params.l.ipv4_src = nat_info->address;
	fib_params.l.ipv4_dst = tuple.daddr;

	ret = nodeport_fib_lookup_and_redirect(ctx, &fib_params, ext_err);
	if (ret != CTX_ACT_OK)
		return ret;

skip_fib:
#endif

	/* Cache is_fragment in advance, nodeport_fib_lookup_and_redirect may invalidate ip4. */
	ret = ct_lazy_lookup4(get_ct_map4(&tuple), &tuple, ctx, is_fragment,
			      l4_off, has_l4_header, CT_INGRESS, SCOPE_REVERSE,
			      CT_ENTRY_NODEPORT | CT_ENTRY_DSR,
			      &ct_state, &trace->monitor);

	/* nodeport_rev_dnat_get_info_ipv4() just checked that such a
	 * CT entry exists:
	 */
	if (ret == CT_REPLY) {
		trace->reason = TRACE_REASON_CT_REPLY;

		ret = __lb4_rev_nat(ctx, l3_off, l4_off, &tuple,
				    nat_info, false, has_l4_header);
		if (IS_ERR(ret))
			return ret;

		*snat_done = true;
	}

	return CTX_ACT_OK;
}

static __always_inline int
__handle_nat_fwd_ipv4(struct __ctx_buff *ctx, __u32 cluster_id __maybe_unused,
		      bool revdnat_only, struct trace_ctx *trace, __s8 *ext_err)
{
	bool snat_done = false;
	int ret;

	ret = nodeport_rev_dnat_fwd_ipv4(ctx, &snat_done, revdnat_only, trace, ext_err);
	if (ret != CTX_ACT_OK || revdnat_only)
		return ret;

#if !defined(ENABLE_DSR) ||						\
    (defined(ENABLE_DSR) && defined(ENABLE_DSR_HYBRID)) ||		\
     defined(ENABLE_MASQUERADE_IPV4) ||					\
    (defined(ENABLE_CLUSTER_AWARE_ADDRESSING) && defined(ENABLE_INTER_CLUSTER_SNAT))
	if (!snat_done) {
		ctx_store_meta(ctx, CB_CLUSTER_ID_EGRESS, cluster_id);
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_NODEPORT_SNAT_FWD,
					 ext_err);
	}
#endif

	if (is_defined(IS_BPF_HOST) && snat_done)
		ctx_snat_done_set(ctx);

	return ret;
}

static __always_inline int
handle_nat_fwd_ipv4(struct __ctx_buff *ctx, struct trace_ctx *trace,
		    __s8 *ext_err)
{
	__u32 cb_nat_flags = ctx_load_and_clear_meta(ctx, CB_NAT_FLAGS);
	bool revdnat_only = cb_nat_flags & CB_NAT_FLAGS_REVDNAT_ONLY;
	__u32 cluster_id = ctx_load_and_clear_meta(ctx, CB_CLUSTER_ID_EGRESS);

	return __handle_nat_fwd_ipv4(ctx, cluster_id, revdnat_only, trace, ext_err);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_NAT_FWD)
static __always_inline
int tail_handle_nat_fwd_ipv4(struct __ctx_buff *ctx)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	int ret;
	enum trace_point obs_point;
	__s8 ext_err = 0;

#ifdef IS_BPF_OVERLAY
	obs_point = TRACE_TO_OVERLAY;
#else
	obs_point = TRACE_TO_NETWORK;
#endif

	ret = handle_nat_fwd_ipv4(ctx, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);

	if (ret == CTX_ACT_OK)
		send_trace_notify(ctx, obs_point, UNKNOWN_ID, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, THIS_INTERFACE_IFINDEX,
				  trace.reason, trace.monitor);

	return ret;
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_HEALTH_CHECK
static __always_inline int
health_encap_v4(struct __ctx_buff *ctx, __u32 tunnel_ep,
		__u32 seclabel)
{
	__u32 key_size = TUNNEL_KEY_WITHOUT_SRC_IP;
	struct bpf_tunnel_key key;

	/* When encapsulating, a packet originating from the local
	 * host is being considered as a packet from a remote node
	 * as it is being received.
	 */
	memset(&key, 0, sizeof(key));
	key.tunnel_id = get_tunnel_id(seclabel == HOST_ID ? LOCAL_NODE_ID : seclabel);
	key.remote_ipv4 = bpf_htonl(tunnel_ep);
	key.tunnel_ttl = IPDEFTTL;

	if (unlikely(ctx_set_tunnel_key(ctx, &key, key_size,
					BPF_F_ZERO_CSUM_TX) < 0))
		return DROP_WRITE_ERROR;
	return 0;
}

static __always_inline int
health_encap_v6(struct __ctx_buff *ctx, const union v6addr *tunnel_ep,
		__u32 seclabel)
{
	__u32 key_size = TUNNEL_KEY_WITHOUT_SRC_IP;
	struct bpf_tunnel_key key;

	memset(&key, 0, sizeof(key));
	key.tunnel_id = get_tunnel_id(seclabel == HOST_ID ? LOCAL_NODE_ID : seclabel);
	key.remote_ipv6[0] = tunnel_ep->p1;
	key.remote_ipv6[1] = tunnel_ep->p2;
	key.remote_ipv6[2] = tunnel_ep->p3;
	key.remote_ipv6[3] = tunnel_ep->p4;
	key.tunnel_ttl = IPDEFTTL;

	if (unlikely(ctx_set_tunnel_key(ctx, &key, key_size,
					BPF_F_ZERO_CSUM_TX |
					BPF_F_TUNINFO_IPV6) < 0))
		return DROP_WRITE_ERROR;
	return 0;
}

static __always_inline int
lb_handle_health(struct __ctx_buff *ctx __maybe_unused, __be16 proto)
{
	void *data __maybe_unused, *data_end __maybe_unused;
	__sock_cookie key __maybe_unused;
	int ret __maybe_unused;

	if ((ctx->mark & MARK_MAGIC_HEALTH_IPIP_DONE) ==
	    MARK_MAGIC_HEALTH_IPIP_DONE)
		return CTX_ACT_OK;

	switch (proto) {
#if defined(ENABLE_IPV4) && DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	case bpf_htons(ETH_P_IP): {
		struct lb4_health *val;

		key = get_socket_cookie(ctx);
		val = map_lookup_elem(&LB4_HEALTH_MAP, &key);
		if (!val)
			return CTX_ACT_OK;
		ret = health_encap_v4(ctx, val->peer.address, 0);
		if (ret != 0)
			return ret;
		ctx->mark |= MARK_MAGIC_HEALTH_IPIP_DONE;
		return ctx_redirect(ctx, ENCAP4_IFINDEX, 0);
	}
#endif
#if defined(ENABLE_IPV6) && DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	case bpf_htons(ETH_P_IPV6): {
		struct lb6_health *val;

		key = get_socket_cookie(ctx);
		val = map_lookup_elem(&LB6_HEALTH_MAP, &key);
		if (!val)
			return CTX_ACT_OK;
		ret = health_encap_v6(ctx, &val->peer.address, 0);
		if (ret != 0)
			return ret;
		ctx->mark |= MARK_MAGIC_HEALTH_IPIP_DONE;
		return ctx_redirect(ctx, ENCAP6_IFINDEX, 0);
	}
#endif
	default:
		return CTX_ACT_OK;
	}
}
#endif /* ENABLE_HEALTH_CHECK */

/* handle_nat_fwd() handles revDNAT, fib_lookup_redirect, and bpf_snat for
 * nodeport. If revdnat_only is set to true, fib_lookup and bpf_snat are
 * skipped. The typical use case of handle_nat_fwd(revdnat_only=true) is for
 * handling reply traffic that requires revDNAT prior to wireguard/IPsec
 * encryption.
 */
static __always_inline int
handle_nat_fwd(struct __ctx_buff *ctx, __u32 cluster_id, __be16 proto,
	       bool revdnat_only, struct trace_ctx *trace __maybe_unused,
	       __s8 *ext_err __maybe_unused)
{
	int ret = CTX_ACT_OK;
	__u32 cb_nat_flags = 0;

	if (revdnat_only)
		cb_nat_flags |= CB_NAT_FLAGS_REVDNAT_ONLY;

	ctx_store_meta(ctx, CB_NAT_FLAGS, cb_nat_flags);
	ctx_store_meta(ctx, CB_CLUSTER_ID_EGRESS, cluster_id);

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = invoke_traced_tailcall_if(__or4(__and(is_defined(ENABLE_IPV4),
							    is_defined(ENABLE_IPV6)),
						      __and(is_defined(ENABLE_HOST_FIREWALL),
							    is_defined(IS_BPF_HOST)),
						      __and(is_defined(ENABLE_CLUSTER_AWARE_ADDRESSING),
							    is_defined(ENABLE_INTER_CLUSTER_SNAT)),
						      __and(is_defined(ENABLE_EGRESS_GATEWAY_COMMON),
							    is_defined(IS_BPF_HOST))),
						CILIUM_CALL_IPV4_NODEPORT_NAT_FWD,
						handle_nat_fwd_ipv4, trace, ext_err);
		break;
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = invoke_traced_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
							   is_defined(ENABLE_IPV6)),
						     __and(is_defined(ENABLE_HOST_FIREWALL),
							   is_defined(IS_BPF_HOST))),
						CILIUM_CALL_IPV6_NODEPORT_NAT_FWD,
						handle_nat_fwd_ipv6, trace, ext_err);
		break;
#endif /* ENABLE_IPV6 */
	default:
		build_bug_on(!(NODEPORT_PORT_MIN_NAT <= NODEPORT_PORT_MAX_NAT));
		build_bug_on(!(NODEPORT_PORT_MIN     <= NODEPORT_PORT_MAX));
		build_bug_on(!(NODEPORT_PORT_MAX     <= NODEPORT_PORT_MIN_NAT));
		break;
	}
	return ret;
}

#endif /* ENABLE_NODEPORT */
