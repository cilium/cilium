/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"
#include "lib/l4.h"
#include "lib/ipv4.h"
#include "lib/ipv6.h"

/* Wireguard-encrypted packets are observed from from-netdev */
#if defined(IS_BPF_HOST) && defined(ENABLE_WIREGUARD)
# define CLASSIFIERS_FROM_NETDEV
#endif

/* Wireguard-encrypted packets are observed from to-netdev */
#if defined(IS_BPF_HOST) && defined(ENABLE_WIREGUARD)
# define CLASSIFIERS_TO_NETDEV
#endif

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

#ifdef CLASSIFIERS_FROM_NETDEV
/* Compute from_netdev classifiers upon receiving an ingress network packet:
 * - CLS_FLAG_WIREGUARD, in case of a WireGuard packet (l4 WG_PORT)
 */
static __always_inline cls_flags_t
ctx_from_netdev_classifiers(struct __ctx_buff *ctx, int l4_off, __u8 protocol)
{
	struct {
		__be16 sport;
		__be16 dport;
	} l4;

	if (protocol != IPPROTO_UDP)
		goto out;

	if (l4_load_ports(ctx, l4_off + UDP_SPORT_OFF, &l4.sport) < 0)
		goto out;

#if defined(IS_BPF_HOST) && defined(ENABLE_WIREGUARD)
	if (l4.sport == bpf_htons(WG_PORT) || l4.dport == bpf_htons(WG_PORT))
		return CLS_FLAG_WIREGUARD;
#endif

out:
	return 0;
}

static __always_inline cls_flags_t
ctx_from_netdev_classifiers4(struct __ctx_buff *ctx, struct iphdr *ip4)
{
	__u8 next_proto = ip4->protocol;
	int hdrlen = ipv4_hdrlen(ip4);

	return ctx_from_netdev_classifiers(ctx, ETH_HLEN + hdrlen, next_proto);
}

static __always_inline cls_flags_t
ctx_from_netdev_classifiers6(struct __ctx_buff *ctx, const struct ipv6hdr *ip6)
{
	__u8 next_proto = ip6->nexthdr;
	int hdrlen = ipv6_hdrlen(ctx, &next_proto);

	if (likely(hdrlen <= 0))
		return CLS_FLAG_IPV6;

	return CLS_FLAG_IPV6 | ctx_from_netdev_classifiers(ctx, ETH_HLEN + hdrlen, next_proto);
}
#else
#define ctx_from_netdev_classifiers(ctx, l4_off, protocol) ((cls_flags_t)0)
#define ctx_from_netdev_classifiers4(ctx, ip4)             ((cls_flags_t)0)
#define ctx_from_netdev_classifiers6(ctx, ip6)             ((cls_flags_t)CLS_FLAG_IPV6)
#endif /* CLASSIFIERS_FROM_NETDEV */

#ifdef CLASSIFIERS_TO_NETDEV
/* Compute to_netdev classifiers upon processing an egress network packet:
 * - CLS_FLAG_WIREGUARD, in case of a WireGuard packet (MARK_MAGIC_WG_ENCRYPTED)
 */
static __always_inline cls_flags_t
ctx_to_netdev_classifiers(struct __ctx_buff *ctx)
{
#if defined(IS_BPF_HOST) && defined(ENABLE_WIREGUARD)
	if (ctx_is_wireguard(ctx))
		return CLS_FLAG_WIREGUARD;
#endif

	return 0;
}
#else
#define ctx_to_netdev_classifiers(ctx) ((cls_flags_t)0)
#endif /* CLASSIFIERS_TO_NETDEV */
