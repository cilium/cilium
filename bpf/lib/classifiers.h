/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"
#include "lib/l4.h"
#include "lib/ipv4.h"
#include "lib/ipv6.h"

/* Classifiers are used only for tracing in TC so far. */
#if __ctx_is == __ctx_skb && (defined(TRACE_NOTIFY) || defined(DROP_NOTIFY))
# define ENABLE_ETH_HDR_CLASSIFIERS 1
/* Given the additional complexity, selectively enable classifiers
 * requiring packet processing logic based on the observed traffic:
 * - bpf_host -> WireGuard
 */
# if defined(IS_BPF_HOST) && defined(ENABLE_WIREGUARD)
# define ENABLE_PKT_HDR_CLASSIFIERS 1
# endif
#endif

typedef __u8 cls_flags_t;

enum {
	CLS_FLAG_IPV6	   = (1 << 0),
	CLS_FLAG_L3_DEV    = (1 << 1),
	CLS_FLAG_IPSEC     = (1 << 2),
	CLS_FLAG_WIREGUARD = (1 << 3),
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

/* Compute classifiers by looking at the packet headers:
 * - CLS_FLAG_WIREGUARD: UDP using WG_PORT
 */
static __always_inline cls_flags_t
ctx_classify_by_pkt_hdr(struct __ctx_buff *ctx __maybe_unused,
			int l4_off __maybe_unused,
			__u8 protocol __maybe_unused)
{
#ifdef ENABLE_PKT_HDR_CLASSIFIERS
	struct {
		__be16 sport;
		__be16 dport;
	} l4;

	switch (protocol) {
	case IPPROTO_UDP:
		if (!is_defined(ENABLE_WIREGUARD))
			break;

		if (l4_load_ports(ctx, l4_off + UDP_SPORT_OFF, &l4.sport) < 0)
			break;

# if defined(ENABLE_WIREGUARD)
		if (is_defined(ENABLE_WIREGUARD) && is_defined(IS_BPF_HOST) &&
		    (l4.sport == bpf_htons(WG_PORT) || l4.dport == bpf_htons(WG_PORT)))
			return CLS_FLAG_WIREGUARD;
# endif
		break;
	}
#endif /* ENABLE_PKT_HDR_CLASSIFIERS */

	return 0;
}

/* Compute classifiers by looking at the IPv4 packet headers. See ctx_classify_by_pkt_hdr. */
static __always_inline cls_flags_t
ctx_classify_by_pkt_hdr4(struct __ctx_buff *ctx __maybe_unused,
			 struct iphdr *ip4 __maybe_unused)
{
#ifdef ENABLE_PKT_HDR_CLASSIFIERS
	__u8 next_proto = ip4->protocol;
	int hdrlen = ipv4_hdrlen(ip4);

	return ctx_classify_by_pkt_hdr(ctx, ETH_HLEN + hdrlen, next_proto);
#endif /* ENABLE_PKT_HDR_CLASSIFIERS */

	return 0;
}

/* Compute classifiers by looking at the IPv6 packet headers. See ctx_classify_by_pkt_hdr. */
static __always_inline cls_flags_t
ctx_classify_by_pkt_hdr6(struct __ctx_buff *ctx __maybe_unused,
			 const struct ipv6hdr *ip6 __maybe_unused)
{
#ifdef ENABLE_PKT_HDR_CLASSIFIERS
	__u8 next_proto = ip6->nexthdr;
	int hdrlen = ipv6_hdrlen(ctx, &next_proto);

	if (likely(hdrlen > 0))
		return CLS_FLAG_IPV6 | ctx_classify_by_pkt_hdr(ctx, ETH_HLEN + hdrlen, next_proto);

	return CLS_FLAG_IPV6;
#endif /* ENABLE_PKT_HDR_CLASSIFIERS */

	return 0;
}
