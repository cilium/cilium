/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"

/* Classifiers are used only for tracing in TC so far. */
#if __ctx_is == __ctx_skb && (defined(TRACE_NOTIFY) || defined(DROP_NOTIFY))
# define ENABLE_ETH_HDR_CLASSIFIERS 1
#endif

typedef __u8 cls_flags_t;

enum {
	CLS_FLAG_IPV6	= (1 << 0),
	CLS_FLAG_L3_DEV = (1 << 1),
};

/* Compute classifiers for a potential L3 packet (based on ETH_HLEN):
 * - CLS_FLAG_L3_DEV: packet from a L3 device;
 * - CLS_FLAG_IPV6:   IPv6 packet, computed when also from a L3 device.
 *                    When already handling IPv6 packets, use ctx_classify_by_eth_hlen6.
 */
static __always_inline cls_flags_t
ctx_classify_by_eth_hlen(const struct __ctx_buff *ctx __maybe_unused)
{
#ifdef ENABLE_ETH_HDR_CLASSIFIERS
	if (ETH_HLEN != 0)
		return 0;

	if (ctx->protocol == bpf_htons(ETH_P_IPV6))
		return CLS_FLAG_L3_DEV | CLS_FLAG_IPV6;

	return CLS_FLAG_L3_DEV;
#endif /* ENABLE_ETH_HDR_CLASSIFIERS */

	return 0;
}

/* Compute classifiers for a potential L3 IPv4 packet. See ctx_classify_by_eth_hlen. */
static __always_inline cls_flags_t
ctx_classify_by_eth_hlen4(const struct __ctx_buff *ctx __maybe_unused)
{
#ifdef ENABLE_ETH_HDR_CLASSIFIERS
	return ctx_classify_by_eth_hlen(ctx);
#endif /* ENABLE_ETH_HDR_CLASSIFIERS */

	return 0;
}

/* Compute classifiers for a potential L3 IPv6 packet. See ctx_classify_by_eth_hlen. */
static __always_inline cls_flags_t
ctx_classify_by_eth_hlen6(const struct __ctx_buff *ctx __maybe_unused)
{
#ifdef ENABLE_ETH_HDR_CLASSIFIERS
	return ctx_classify_by_eth_hlen(ctx) | CLS_FLAG_IPV6;
#endif /* ENABLE_ETH_HDR_CLASSIFIERS */

	return 0;
}
