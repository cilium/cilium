/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "icmp6.h"

#ifdef ENABLE_IPV6
static __always_inline int ipv6_l3(struct __ctx_buff *ctx, int l3_off,
				   const __u8 *smac, const __u8 *dmac,
				   __u8 __maybe_unused direction)
{
	int ret;

	ret = ipv6_dec_hoplimit(ctx, l3_off);
	if (IS_ERR(ret)) {
#ifndef SKIP_ICMPV6_HOPLIMIT_HANDLING
		if (ret == DROP_TTL_EXCEEDED)
			return icmp6_send_time_exceeded(ctx, l3_off, direction);
#endif
		return ret;
	}

	if (smac && eth_store_saddr(ctx, smac, 0) < 0)
		return DROP_WRITE_ERROR;
	if (dmac && eth_store_daddr(ctx, dmac, 0) < 0)
		return DROP_WRITE_ERROR;

	return CTX_ACT_OK;
}
#endif /* ENABLE_IPV6 */

static __always_inline int ipv4_l3(struct __ctx_buff *ctx, int l3_off,
				   const __u8 *smac, const __u8 *dmac,
				   struct iphdr *ip4)
{
	int ret;

	ret = ipv4_dec_ttl(ctx, l3_off, ip4);
	/* FIXME: Send ICMP TTL */
	if (IS_ERR(ret))
		return ret;

	if (smac && eth_store_saddr(ctx, smac, 0) < 0)
		return DROP_WRITE_ERROR;
	if (dmac && eth_store_daddr(ctx, dmac, 0) < 0)
		return DROP_WRITE_ERROR;

	return CTX_ACT_OK;
}
