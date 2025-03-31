/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"

#if defined(IS_BPF_WIREGUARD) || (defined(IS_BPF_HOST) && defined(ENABLE_WIREGUARD))
# define CLASSIFIERS_BASE
#endif

typedef __u8 cls_t;

enum classifiers {
	CLS_FLAG_IPV6	= (1 << 0),
	CLS_FLAG_L3_DEV = (1 << 1),
};

#define NULL_CLASSIFIERS ((cls_t)0)

#ifdef CLASSIFIERS_BASE
/* Compute base classifiers
 * - CLS_FLAG_L3_DEV: packet from an L3 device
 * - CLS_FLAG_IPV6:   IPv6 packet when CLS_FLAG_L3_DEV is set. When already knowing a
 *                    packet is IPv6, use ctx_base_classifiers_6() instead.
 */
static __always_inline cls_t
ctx_base_classifiers(const struct __ctx_buff *ctx)
{
	cls_t cls = 0;

#if defined(IS_BPF_HOST)
	if (THIS_INTERFACE_IFINDEX == WG_IFINDEX)
#endif
	{
		cls |= CLS_FLAG_L3_DEV;
		if (ctx->protocol == bpf_htons(ETH_P_IPV6))
			cls |= CLS_FLAG_IPV6;
	}

	return cls;
}

#define ctx_base_classifiers4(ctx) ctx_base_classifiers(ctx)
#define ctx_base_classifiers6(ctx) (ctx_base_classifiers(ctx) | CLS_FLAG_IPV6)
#else
#define ctx_base_classifiers(ctx) NULL_CLASSIFIERS
#define ctx_base_classifiers4(ctx) NULL_CLASSIFIERS
#define ctx_base_classifiers6(ctx) NULL_CLASSIFIERS
#endif /* CLASSIFIERS_BASE */
