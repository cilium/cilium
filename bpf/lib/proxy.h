/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "conntrack.h"

#if !(__ctx_is == __ctx_skb)
#error "Proxy redirection is only supported from skb context"
#endif

#ifdef ENABLE_TPROXY
static __always_inline int
assign_socket_tcp(struct __ctx_buff *ctx,
		  struct bpf_sock_tuple *tuple, __u32 len, bool established)
{
	int result = DROP_PROXY_LOOKUP_FAILED;
	struct bpf_sock *sk;
	__u32 dbg_ctx;

	sk = skc_lookup_tcp(ctx, tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		goto out;

	if (established && sk->state == BPF_TCP_TIME_WAIT)
		goto release;
	if (established && sk->state == BPF_TCP_LISTEN)
		goto release;

	dbg_ctx = READ_ONCE(sk)->family << 16 | ctx->protocol;
	result = sk_assign(ctx, sk, 0);
	cilium_dbg(ctx, DBG_SK_ASSIGN, -result, dbg_ctx);
	if (result == 0)
		result = CTX_ACT_OK;
	else
		result = DROP_PROXY_SET_FAILED;
release:
	sk_release(sk);
out:
	return result;
}

static __always_inline int
assign_socket_udp(struct __ctx_buff *ctx,
		  struct bpf_sock_tuple *tuple, __u32 len,
		  bool established __maybe_unused)
{
	int result = DROP_PROXY_LOOKUP_FAILED;
	struct bpf_sock *sk;
	__u32 dbg_ctx;

	sk = sk_lookup_udp(ctx, tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		goto out;

	dbg_ctx = READ_ONCE(sk)->family << 16 | ctx->protocol;
	result = sk_assign(ctx, sk, 0);
	cilium_dbg(ctx, DBG_SK_ASSIGN, -result, dbg_ctx);
	if (result == 0)
		result = CTX_ACT_OK;
	else
		result = DROP_PROXY_SET_FAILED;
	sk_release(sk);
out:
	return result;
}

static __always_inline int
assign_socket(struct __ctx_buff *ctx,
	      struct bpf_sock_tuple *tuple, __u32 len,
	      __u8 nexthdr, bool established)
{
	/* Workaround: While the below functions are nearly identical in C
	 * implementation, the 'struct bpf_sock *' has a different verifier
	 * pointer type, which means we can't fold these implementations
	 * together.
	 */
	switch (nexthdr) {
	case IPPROTO_TCP:
		return assign_socket_tcp(ctx, tuple, len, established);
	case IPPROTO_UDP:
		return assign_socket_udp(ctx, tuple, len, established);
	}
	return DROP_PROXY_UNKNOWN_PROTO;
}

/**
 * combine_ports joins the specified ports in a manner consistent with
 * pkg/monitor/dataapth_debug.go to report the ports ino monitor messages.
 */
static __always_inline __u32
combine_ports(__u16 dport, __u16 sport)
{
	return (bpf_ntohs(dport) << 16) | bpf_ntohs(sport);
}

#define CTX_REDIRECT_FN(NAME, CT_TUPLE_TYPE, SK_FIELD,				\
			DBG_LOOKUP_CODE, DADDR_DBG, SADDR_DBG)			\
/**										\
 * ctx_redirect_to_proxy_ingress4 / ctx_redirect_to_proxy_ingress6		\
 * @ctx			pointer to program context				\
 * @tuple		pointer to *scratch buffer* with packet tuple		\
 * @proxy_port		port to redirect traffic towards			\
 *										\
 * Prefetch the proxy socket and associate with the ctx. Must be run on tc	\
 * ingress. Will modify 'tuple'!						\
 */										\
static __always_inline int							\
NAME(struct __ctx_buff *ctx, const CT_TUPLE_TYPE * ct_tuple,			\
     __be16 proxy_port, void *tproxy_addr)					\
{										\
	struct bpf_sock_tuple *tuple = (struct bpf_sock_tuple *)ct_tuple;	\
	__u8 nexthdr = ct_tuple->nexthdr;					\
	__u32 len = sizeof(tuple->SK_FIELD);					\
	__u16 port;								\
	int result;								\
										\
	/* The provided 'ct_tuple' is in the internal Cilium format, which	\
	 * reverses the source/destination ports as compared with the actual	\
	 * packet contents. 'bpf_sock_tuple' in the eBPF API needs these to	\
	 * match normal packet ordering to successfully look up the		\
	 * corresponding socket. So, swap them here.				\
	 */									\
	port = tuple->SK_FIELD.sport;						\
	tuple->SK_FIELD.sport = tuple->SK_FIELD.dport;				\
	tuple->SK_FIELD.dport = port;						\
										\
	/* Look for established socket locally first */				\
	cilium_dbg3(ctx, DBG_LOOKUP_CODE,					\
		    tuple->SK_FIELD.SADDR_DBG, tuple->SK_FIELD.DADDR_DBG,	\
		    combine_ports(tuple->SK_FIELD.dport, tuple->SK_FIELD.sport));	\
	result = assign_socket(ctx, tuple, len, nexthdr, true);			\
	if (result == CTX_ACT_OK)						\
		goto out;							\
										\
	/* if there's no established connection, locate the tproxy socket on the tproxy_addr IP */ \
	tuple->SK_FIELD.dport = proxy_port;	 \
	tuple->SK_FIELD.sport = 0;	\
	memcpy(&tuple->SK_FIELD.daddr, tproxy_addr, sizeof(tuple->SK_FIELD.daddr)); \
	memset(&tuple->SK_FIELD.saddr, 0, sizeof(tuple->SK_FIELD.saddr));	\
	cilium_dbg3(ctx, DBG_LOOKUP_CODE,					\
		    tuple->SK_FIELD.SADDR_DBG, tuple->SK_FIELD.DADDR_DBG,	\
		    combine_ports(tuple->SK_FIELD.dport, tuple->SK_FIELD.sport));	\
	result = assign_socket(ctx, tuple, len, nexthdr, false);		\
	if (result == CTX_ACT_OK)						\
		goto out;	\
										\
	/* if there's no tproxy socket on tproxy_addr look for one bound to all interfaces */ \
	memset(&tuple->SK_FIELD.daddr, 0, sizeof(tuple->SK_FIELD.daddr));	\
	cilium_dbg3(ctx, DBG_LOOKUP_CODE,					\
		    tuple->SK_FIELD.SADDR_DBG, tuple->SK_FIELD.DADDR_DBG,	\
		    combine_ports(tuple->SK_FIELD.dport, tuple->SK_FIELD.sport));	\
	result = assign_socket(ctx, tuple, len, nexthdr, false);		\
										\
out:										\
	return result;								\
}

#ifdef ENABLE_IPV4
CTX_REDIRECT_FN(ctx_redirect_to_proxy_ingress4, struct ipv4_ct_tuple, ipv4,
		DBG_SK_LOOKUP4, daddr, saddr)
#endif
#ifdef ENABLE_IPV6
CTX_REDIRECT_FN(ctx_redirect_to_proxy_ingress6, struct ipv6_ct_tuple, ipv6,
		DBG_SK_LOOKUP6, daddr[3], saddr[3])
#endif
#undef CTX_REDIRECT_FN
#endif /* ENABLE_TPROXY */

/**
 * __ctx_redirect_to_proxy configures the ctx with the proxy mark and proxy
 * port number to ensure that the stack redirects the packet into the proxy.
 *
 * It is called from both ingress and egress side of endpoint devices.
 *
 * In regular veth mode:
 * * To apply egress policy, the egressing endpoint configures the mark,
 *   which returns CTX_ACT_OK to pass the packet to the stack in the context
 *   of the source device (stack ingress).
 * * To apply ingress policy, the egressing endpoint or netdev program tail
 *   calls into the policy program which configures the mark here, which
 *   returns CTX_ACT_OK to pass the packet to the stack in the context of the
 *   source device (netdev or egress endpoint device, stack ingress).
 *
 * In chaining mode with bridged endpoint devices:
 * * To apply egress policy, the egressing endpoint configures the mark,
 *   which is propagated via ctx_store_meta() in the caller. The redirect() call
 *   here redirects the packet to the ingress TC filter configured on the bridge
 *   master device.
 * * To apply ingress policy, the stack transmits the packet into the bridge
 *   master device which tail calls into the policy program for the ingress
 *   endpoint, which configures mark and cb[] as described for the egress path.
 *   The redirect() call here redirects the packet to the ingress TC filter
 *   configured on the bridge master device.
 * * In both cases for bridged endpoint devices, the bridge master device has
 *   a BPF program configured upon ingress to transfer the cb[] to the mark
 *   before passing the traffic up to the stack towards the proxy.
 */
static __always_inline int
__ctx_redirect_to_proxy(struct __ctx_buff *ctx, void *tuple __maybe_unused,
			__be16 proxy_port, bool from_host __maybe_unused,
			bool ipv4 __maybe_unused)
{
	int result __maybe_unused = CTX_ACT_OK;

#ifdef ENABLE_TPROXY
	if (!from_host)
		ctx->mark |= MARK_MAGIC_TO_PROXY;
	else
#endif
		ctx->mark = MARK_MAGIC_TO_PROXY | proxy_port << 16;

	cilium_dbg_capture(ctx, DBG_CAPTURE_PROXY_PRE, proxy_port);

#ifdef ENABLE_TPROXY
	if (proxy_port && !from_host) {
#ifdef ENABLE_IPV4
		if (ipv4) {
			__be32 ipv4_localhost = bpf_htonl(INADDR_LOOPBACK);

			result =
			ctx_redirect_to_proxy_ingress4(ctx, tuple, proxy_port, &ipv4_localhost);
		}
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
		if (!ipv4) {
			union v6addr ipv6_localhost = { .addr[15] = 1,};

			result =
			ctx_redirect_to_proxy_ingress6(ctx, tuple, proxy_port, &ipv6_localhost);
		}
#endif /* ENABLE_IPV6 */
	}
#endif /* ENABLE_TPROXY */
	return result;
}

#ifdef ENABLE_IPV4
static __always_inline int
ctx_redirect_to_proxy4(struct __ctx_buff *ctx, void *tuple __maybe_unused,
		       __be16 proxy_port, bool from_host __maybe_unused)
{
	return __ctx_redirect_to_proxy(ctx, tuple, proxy_port, from_host, true);
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
static __always_inline int
ctx_redirect_to_proxy6(struct __ctx_buff *ctx, void *tuple __maybe_unused,
		       __be16 proxy_port, bool from_host __maybe_unused)
{
	return __ctx_redirect_to_proxy(ctx, tuple, proxy_port, from_host, false);
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_TPROXY
#define IP_TUPLE_EXTRACT_FN(NAME, PREFIX)				\
/**									\
 * extract_tuple4 / extract_tuple6					\
 *									\
 * Extracts the packet 5-tuple into 'tuple'.				\
 *									\
 * Note that it doesn't fully initialize 'tuple' as the directionality	\
 * bit is unused in the proxy paths.					\
 */									\
static __always_inline int						\
NAME(struct __ctx_buff *ctx, struct PREFIX ## _ct_tuple *tuple)		\
{									\
	int err;							\
									\
	err = PREFIX ## _extract_tuple(ctx, tuple);			\
	if (err != CTX_ACT_OK)						\
		return err;						\
									\
	__ ## PREFIX ## _ct_tuple_reverse(tuple);			\
									\
	return CTX_ACT_OK;						\
}

#ifdef ENABLE_IPV4
IP_TUPLE_EXTRACT_FN(extract_tuple4, ipv4)
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
IP_TUPLE_EXTRACT_FN(extract_tuple6, ipv6)
#endif /* ENABLE_IPV6 */
#endif /* ENABLE_TPROXY */

/**
 * ctx_redirect_to_proxy_first() applies changes to the context to forward
 * the packet towards the proxy. It is designed to run as the first function
 * that accesses the context from the current BPF program.
 */
static __always_inline int
ctx_redirect_to_proxy_first(struct __ctx_buff *ctx, __be16 proxy_port)
{
	int ret = CTX_ACT_OK;
#if defined(ENABLE_TPROXY)
	__u16 proto;
#ifdef ENABLE_IPV4
	__be32 ipv4_localhost = bpf_htonl(INADDR_LOOPBACK);
#endif
#ifdef ENABLE_IPV6
	union v6addr ipv6_localhost = { .addr[15] = 1,};
#endif

	/**
	 * For reply traffic to egress proxy for a local endpoint, we skip the
	 * policy & proxy_port lookup and just hairpin & rely on local stack
	 * routing via ctx->mark to ensure that the return traffic reaches the
	 * proxy. This is only relevant for endpoint-routes mode but we don't
	 * have a macro for this so the logic applies unconditionally here.
	 * See ct_state.proxy_redirect usage in bpf_lxc.c for more info.
	 */
	if (!proxy_port)
		goto mark;

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;

	ret = DROP_UNKNOWN_L3;
	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6): {
		struct ipv6_ct_tuple tuple;

		ret = extract_tuple6(ctx, &tuple);
		if (ret < 0)
			return ret;
		ret = ctx_redirect_to_proxy_ingress6(ctx, &tuple, proxy_port, &ipv6_localhost);
		break;
	}
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		struct ipv4_ct_tuple tuple;

		ret = extract_tuple4(ctx, &tuple);
		if (ret < 0)
			return ret;

		ret = ctx_redirect_to_proxy_ingress4(ctx, &tuple, proxy_port, &ipv4_localhost);
		break;
	}
#endif /* ENABLE_IPV4 */
	default:
		goto out;
	}
#endif /* ENABLE_TPROXY */

mark: __maybe_unused;
	cilium_dbg_capture(ctx, DBG_CAPTURE_PROXY_POST, proxy_port);
	ctx->mark = MARK_MAGIC_TO_PROXY | (proxy_port << 16);
	ctx_change_type(ctx, PACKET_HOST);

out: __maybe_unused;
	return ret;
}

/**
 * tc_index_from_ingress_proxy - returns true if packet originates from ingress proxy
 */
static __always_inline bool tc_index_from_ingress_proxy(struct __ctx_buff *ctx)
{
	volatile __u32 tc_index = ctx->tc_index;
#ifdef DEBUG
	if (tc_index & TC_INDEX_F_FROM_INGRESS_PROXY)
		cilium_dbg(ctx, DBG_SKIP_PROXY, tc_index, 0);
#endif

	return tc_index & TC_INDEX_F_FROM_INGRESS_PROXY;
}

/**
 * tc_index_from_egress_proxy - returns true if packet originates from egress proxy
 */
static __always_inline bool tc_index_from_egress_proxy(struct __ctx_buff *ctx)
{
	volatile __u32 tc_index = ctx->tc_index;
#ifdef DEBUG
	if (tc_index & TC_INDEX_F_FROM_EGRESS_PROXY)
		cilium_dbg(ctx, DBG_SKIP_PROXY, tc_index, 0);
#endif

	return tc_index & TC_INDEX_F_FROM_EGRESS_PROXY;
}
