/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"

/* Layer 3 packets are observed from the WireGuard device cilium_wg0 */
#if defined(IS_BPF_WIREGUARD)
# define CLASSIFIERS_DEVICE
#endif

typedef __u8 cls_flags_t;

enum {
	CLS_FLAG_IPV6	   = (1 << 0),
	CLS_FLAG_L3_DEV    = (1 << 1),
	CLS_FLAG_IPSEC     = (1 << 2),
	CLS_FLAG_WIREGUARD = (1 << 3),
};

#define EMPTY_CLASSIFIERS ((cls_flags_t)0)

#ifdef CLASSIFIERS_DEVICE
/* Compute packet layer classifiers
 * - CLS_FLAG_L3_DEV: packet from a L3 device
 * - CLS_FLAG_IPV6:   IPv6 packet when CLS_FLAG_L3_DEV is set. When already knowing a
 *                    packet is IPv6, use ctx_device_classifiers6() instead.
 */
static __always_inline cls_flags_t
ctx_device_classifiers(const struct __ctx_buff *ctx __maybe_unused)
{
	if (ctx->protocol == bpf_htons(ETH_P_IPV6))
		return CLS_FLAG_L3_DEV | CLS_FLAG_IPV6;

	return CLS_FLAG_L3_DEV;
}

#define ctx_device_classifiers4(ctx) (ctx_device_classifiers(ctx))
#define ctx_device_classifiers6(ctx) (ctx_device_classifiers(ctx) | CLS_FLAG_IPV6)
#else
#define ctx_device_classifiers(ctx)  ((cls_flags_t)0)
#define ctx_device_classifiers4(ctx) ((cls_flags_t)0)
#define ctx_device_classifiers6(ctx) ((cls_flags_t)CLS_FLAG_IPV6)
#endif /* CLASSIFIERS_DEVICE */
