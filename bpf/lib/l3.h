/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "icmp6.h"

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

/* IPIP-aware IPv4 revalidation helpers.
 *
 * When an external load balancer forwards traffic using IPIP
 * encapsulation, the outer IPv4 header has protocol=IPPROTO_IPIP. These
 * helpers detect that case and advance past the outer header to the inner
 * IPv4 header, so the BPF programs process the actual TCP/UDP payload.
 *
 * *l3_off is set to the L3 offset of the (possibly inner) IPv4 header.
 */
static __always_inline __maybe_unused bool
__revalidate_data_ipv4_l3(struct __ctx_buff *ctx, void **data, void **data_end,
			  struct iphdr **ip4, int *l3_off, bool pull)
{
	bool result;

	*l3_off = ETH_HLEN;
	result = __revalidate_data_pull(ctx, data, data_end, (void **)ip4,
					ETH_HLEN, sizeof(**ip4), pull);
	if (result && (*ip4)->protocol == IPPROTO_IPIP) {
		*l3_off = ETH_HLEN + ipv4_hdrlen(*ip4);
		result = __revalidate_data_pull(ctx, data, data_end,
						(void **)ip4, *l3_off,
						sizeof(**ip4), pull);
	}
	return result;
}

static __always_inline __maybe_unused bool
revalidate_data_ipv4_l3(struct __ctx_buff *ctx, void **data, void **data_end,
			struct iphdr **ip4, int *l3_off)
{
	return __revalidate_data_ipv4_l3(ctx, data, data_end, ip4, l3_off,
					 false);
}

static __always_inline __maybe_unused bool
revalidate_data_ipv4_l3_pull(struct __ctx_buff *ctx, void **data,
			     void **data_end, struct iphdr **ip4, int *l3_off)
{
	return __revalidate_data_ipv4_l3(ctx, data, data_end, ip4, l3_off,
					 true);
}
