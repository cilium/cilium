/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_PROXY_H_
#define __LIB_PROXY_H_

#include "conntrack.h"

#if !(__ctx_is == __ctx_skb)
#error "Proxy redirection is only supported from skb context"
#endif

/**
 * ctx_redirect_to_proxy configures the ctx with the proxy mark and proxy port
 * number to ensure that the stack redirects the packet into the proxy.
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
ctx_redirect_to_proxy(struct __ctx_buff *ctx, __be16 proxy_port,
		      bool from_host __maybe_unused)
{
	ctx->mark = MARK_MAGIC_TO_PROXY | proxy_port << 16;

#ifdef HOST_REDIRECT_TO_INGRESS
	cilium_dbg(ctx, DBG_CAPTURE_PROXY_PRE, proxy_port, 0);
	/* In this case, the DBG_CAPTURE_PROXY_POST will be sent from the
	 * program attached to HOST_IFINDEX.
	 */
	return redirect(HOST_IFINDEX, BPF_F_INGRESS);
#else
	cilium_dbg(ctx, DBG_CAPTURE_PROXY_PRE, proxy_port, 0);

	ctx_change_type(ctx, PACKET_HOST); /* Required for ingress packets from overlay */
	return CTX_ACT_OK;
#endif
}

/**
 * ctx_redirect_to_proxy_first() applies changes to the context to forward
 * the packet towards the proxy. It is designed to run as the first function
 * that accesses the context from the current BPF program.
 */
static __always_inline void
ctx_redirect_to_proxy_first(struct __ctx_buff *ctx, __be16 proxy_port)
{
	cilium_dbg(ctx, DBG_CAPTURE_PROXY_POST, proxy_port, 0);
	ctx->mark = MARK_MAGIC_TO_PROXY | (proxy_port << 16);
	ctx_change_type(ctx, PACKET_HOST);
}

/**
 * tc_index_skip_ingress_proxy - returns true if packet originates from ingress proxy
 */
static __always_inline bool tc_index_skip_ingress_proxy(struct __ctx_buff *ctx)
{
	volatile __u32 tc_index = ctx->tc_index;
#ifdef DEBUG
	if (tc_index & TC_INDEX_F_SKIP_INGRESS_PROXY)
		cilium_dbg(ctx, DBG_SKIP_PROXY, tc_index, 0);
#endif

	return tc_index & TC_INDEX_F_SKIP_INGRESS_PROXY;
}

/**
 * tc_index_skip_egress_proxy - returns true if packet originates from egress proxy
 */
static __always_inline bool tc_index_skip_egress_proxy(struct __ctx_buff *ctx)
{
	volatile __u32 tc_index = ctx->tc_index;
#ifdef DEBUG
	if (tc_index & TC_INDEX_F_SKIP_EGRESS_PROXY)
		cilium_dbg(ctx, DBG_SKIP_PROXY, tc_index, 0);
#endif

	return tc_index & TC_INDEX_F_SKIP_EGRESS_PROXY;
}
#endif /* __LIB_PROXY_H_ */
