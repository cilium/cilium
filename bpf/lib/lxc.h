/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_LXC_H_
#define __LIB_LXC_H_

#include "common.h"
#include "utils.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "dbg.h"
#include "trace.h"
#include "csum.h"
#include "l4.h"

#define TEMPLATE_LXC_ID 0xffff

#ifndef DISABLE_SIP_VERIFICATION
static __always_inline int is_valid_lxc_src_ip(struct ipv6hdr *ip6)
{
#ifdef ENABLE_IPV6
	union v6addr valid = {};

	BPF_V6(valid, LXC_IP);

	return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
#else
	return 0;
#endif
}

static __always_inline int is_valid_lxc_src_ipv4(struct iphdr *ip4)
{
#ifdef ENABLE_IPV4
	return ip4->saddr == LXC_IPV4;
#else
	/* Can't send IPv4 if no IPv4 address is configured */
	return 0;
#endif
}
#else
static __always_inline int is_valid_lxc_src_ip(struct ipv6hdr *ip6)
{
	return 1;
}

static __always_inline int is_valid_lxc_src_ipv4(struct iphdr *ip4)
{
	return 1;
}
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
ctx_redirect_to_proxy(struct __ctx_buff *ctx, __be16 proxy_port)
{
	ctx->mark = MARK_MAGIC_TO_PROXY | proxy_port << 16;

#ifdef HOST_REDIRECT_TO_INGRESS
	cilium_dbg_capture(ctx, DBG_CAPTURE_PROXY_PRE, proxy_port);
	/* In this case, the DBG_CAPTURE_PROXY_POST will be sent from the
	 * programm attached to HOST_IFINDEX. */
	return redirect(HOST_IFINDEX, BPF_F_INGRESS);
#else
	cilium_dbg_capture(ctx, DBG_CAPTURE_PROXY_POST, proxy_port);
	ctx_change_type(ctx, PACKET_HOST); // Required for ingress packets from overlay
	return CTX_ACT_OK;
#endif
}

/**
 * ctx_redirect_to_proxy_hairpin redirects to the proxy by hairpining the
 * packet out the incoming interface
 */
static __always_inline int
ctx_redirect_to_proxy_hairpin(struct __ctx_buff *ctx, __be16 proxy_port)
{
	union macaddr host_mac = HOST_IFINDEX_MAC;
	union macaddr router_mac = NODE_MAC;
	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void *) (long) ctx->data;
	struct iphdr *ip4;
	int ret;

	ctx_store_meta(ctx, 0, MARK_MAGIC_TO_PROXY | (proxy_port << 16));
	bpf_barrier(); /* verifier workaround */

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	ret = ipv4_l3(ctx, ETH_HLEN, (__u8 *) &router_mac, (__u8 *) &host_mac, ip4);
	if (IS_ERR(ret))
		return ret;

	cilium_dbg_capture(ctx, DBG_CAPTURE_PROXY_POST, proxy_port);

	return redirect(HOST_IFINDEX, 0);
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
#endif /* __LIB_LXC_H_ */
