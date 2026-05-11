/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "icmp6.h"
#include "arp.h"

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

/* Pull the L3 header for the given ethertype into linear memory.
 * Should be called at the first ethertype de-mux point, before branching into
 * per-protocol handlers that expect the header to be in linear memory.
 * Returns DROP_INVALID if the pull fails, 0 otherwise.
 */
static __always_inline int pull_l3_hdr(struct __ctx_buff *ctx __maybe_unused,
				       __be16 proto)
{
	switch (bpf_ntohs(proto)) {
#ifdef ENABLE_IPV6
	case ETH_P_IPV6: {
		void *data, *data_end;
		struct ipv6hdr *ip6;

		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
		break;
	}
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case ETH_P_IP: {
		void *data, *data_end;
		struct iphdr *ip4;

		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		break;
	}
	case ETH_P_ARP: {
		void *data, *data_end;
		struct arp_eth *arp;

		if (!revalidate_data_arp_pull(ctx, &data, &data_end, &arp))
			return DROP_INVALID;
		break;
	}
#endif /* ENABLE_IPV4 */
	default:
		break;
	}
	return 0;
}
