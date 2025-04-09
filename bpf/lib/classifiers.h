/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"
#include "lib/l4.h"
#include "lib/ipv4.h"
#include "lib/ipv6.h"

#if __ctx_is == __ctx_skb && defined(ENABLE_WIREGUARD)
# define CLASSIFIERS_FROM_NETDEV
#endif

#if __ctx_is == __ctx_skb && (defined(ENABLE_WIREGUARD) || defined(HAVE_ENCAP))
# define CLASSIFIERS_TO_NETDEV
#endif

#if defined(IS_BPF_WIREGUARD) || (defined(IS_BPF_HOST) && defined(ENABLE_WIREGUARD))
# define CLASSIFIERS_BASE
#endif

typedef __u8 cls_t;

enum classifiers {
	CLS_FLAG_IPV6      = (1 << 0),
	CLS_FLAG_L3_DEV    = (1 << 1),
	CLS_FLAG_IPSEC     = (1 << 2),
	CLS_FLAG_WIREGUARD = (1 << 3),
	CLS_FLAG_VXLAN     = (1 << 4),
	CLS_FLAG_GENEVE    = (1 << 5),
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

#ifdef CLASSIFIERS_FROM_NETDEV
/* Compute from_netdev classifiers upon receiving an ingress network packet:
 * - CLS_FLAG_WIREGUARD, in case of a WireGuard packet (l4 WG_PORT)
 */
static __always_inline cls_t
ctx_from_netdev_classifiers(struct __ctx_buff *ctx, int l4_off, __u8 protocol)
{
	struct {
		__be16 sport;
		__be16 dport;
	} l4;
	cls_t flags = 0;

	if (protocol != IPPROTO_UDP)
		goto out;

	if (l4_load_ports(ctx, l4_off + UDP_SPORT_OFF, &l4.sport) < 0)
		goto out;

#ifdef ENABLE_WIREGUARD
	if (l4.sport == bpf_htons(WG_PORT) || l4.dport == bpf_htons(WG_PORT))
		flags |= CLS_FLAG_WIREGUARD;
#endif

out:
	return flags;
}

static __always_inline cls_t
ctx_from_netdev_classifiers4(struct __ctx_buff *ctx, struct iphdr *ip4)
{
	__u8 next_proto = ip4->protocol;
	int hdrlen = ipv4_hdrlen(ip4);

	return ctx_from_netdev_classifiers(ctx, ETH_HLEN + hdrlen, next_proto);
}

static __always_inline cls_t
ctx_from_netdev_classifiers6(struct __ctx_buff *ctx, const struct ipv6hdr *ip6)
{
	__u8 next_proto = ip6->nexthdr;
	int hdrlen = ipv6_hdrlen(ctx, &next_proto);
	cls_t flags = CLS_FLAG_IPV6;

	if (likely(hdrlen > 0))
		flags |= ctx_from_netdev_classifiers(ctx, ETH_HLEN + hdrlen, next_proto);

	return flags;
}
#else
#define ctx_from_netdev_classifiers(ctx, l4_off, protocol) NULL_CLASSIFIERS
#define ctx_from_netdev_classifiers4(ctx, ip4) NULL_CLASSIFIERS
#define ctx_from_netdev_classifiers6(ctx, ip6) NULL_CLASSIFIERS
#endif /* CLASSIFIERS_FROM_NETDEV */

#ifdef CLASSIFIERS_TO_NETDEV
/* Compute to_netdev classifiers upon processing an egress network packet:
 * - CLS_FLAG_WIREGUARD, in case of a WireGuard packet (MARK_MAGIC_WG_ENCRYPTED)
 */
static __always_inline cls_t
ctx_to_netdev_classifiers(struct __ctx_buff *ctx)
{
	cls_t flags = 0;

#ifdef ENABLE_WIREGUARD
	if (ctx_is_wireguard(ctx))
		flags |= CLS_FLAG_WIREGUARD;
#endif

#ifdef HAVE_ENCAP
	if (ctx_is_overlay(ctx))
		switch (TUNNEL_PROTOCOL) {
		case TUNNEL_PROTOCOL_VXLAN:
			flags |= CLS_FLAG_VXLAN;
			break;
		case TUNNEL_PROTOCOL_GENEVE:
			flags |= CLS_FLAG_GENEVE;
			break;
		default:
			__throw_build_bug();
		}
#endif

	return flags;
}
#else
#define ctx_to_netdev_classifiers(ctx) NULL_CLASSIFIERS
#endif /* CLASSIFIERS_TO_NETDEV */
