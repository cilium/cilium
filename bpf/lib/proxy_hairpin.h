/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "utils.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "dbg.h"
#include "trace.h"
#include "l3.h"
#include "l4.h"

/** Redirect to the proxy by hairpinning the packet out the incoming
 *  interface.
 *
 * @arg ctx		Packet
 * @arg ip4		Pointer to IPv4 header. NULL for IPv6 packet.
 * @arg proxy_port	Proxy port
 */
static __always_inline int
ctx_redirect_to_proxy_hairpin(struct __ctx_buff *ctx, struct iphdr *ip4,
			      __be16 proxy_port)
{
	union macaddr __maybe_unused host_mac = CILIUM_HOST_MAC;
	union macaddr __maybe_unused router_mac = CONFIG(interface_mac);
	int ret = 0;

	ctx_store_meta(ctx, CB_PROXY_MAGIC,
		       MARK_MAGIC_TO_PROXY | (proxy_port << 16));
	bpf_barrier(); /* verifier workaround */

	if (!ip4) {
#ifdef ENABLE_IPV6
		ret = ipv6_l3(ctx, ETH_HLEN, (__u8 *)&router_mac, (__u8 *)&host_mac,
			      METRIC_EGRESS);
#endif
	} else {
#ifdef ENABLE_IPV4
		ret = ipv4_l3(ctx, ETH_HLEN, (__u8 *)&router_mac, (__u8 *)&host_mac,
			      ip4);
#endif
	}
	if (IS_ERR(ret))
		return ret;

	cilium_dbg_capture(ctx, DBG_CAPTURE_PROXY_PRE, proxy_port);

	/* Note that the actual __ctx_buff preparation for submitting the
	 * packet to the proxy will occur in a subsequent program via
	 * ctx_redirect_to_proxy_first().
	 */

	return ctx_redirect(ctx, CONFIG(cilium_net_ifindex), 0);
}

#ifdef ENABLE_IPV4
static __always_inline int
ctx_redirect_to_proxy_hairpin_ipv4(struct __ctx_buff *ctx, struct iphdr *ip4,
				   __be16 proxy_port)
{
	return ctx_redirect_to_proxy_hairpin(ctx, ip4, proxy_port);
}
#endif

#ifdef ENABLE_IPV6
static __always_inline int
ctx_redirect_to_proxy_hairpin_ipv6(struct __ctx_buff *ctx, __be16 proxy_port)
{
	return ctx_redirect_to_proxy_hairpin(ctx, NULL, proxy_port);
}
#endif
