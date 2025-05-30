/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"
#include "lib/ipv4.h"
#include "lib/ipv6.h"
#include "lib/l4.h"

typedef __u8 cls_flags_t;

/* Classification flags used to enrich trace/drop notifications events. */
enum {
	/* Packet uses IPv6. This flag is only needed/set in trace event:
	 * - carrying the orig_ip IPv6 info from send_trace_notify6, or
	 * - with L3 IPv6 packets, to instruct Hubble to use the right decoder.
	 */
	CLS_FLAG_IPV6	   = (1 << 0),
	/* Packet originates from a L3 device (no ethernet header). */
	CLS_FLAG_L3_DEV    = (1 << 1),
	/* Packet uses underlay VXLAN. */
	CLS_FLAG_VXLAN     = (1 << 2),
	/* Packet uses underlay Geneve. */
	CLS_FLAG_GENEVE    = (1 << 3),
};

/* Wrapper for specifying empty flags during the trace/drop event. */
#define CLS_FLAG_NONE ((cls_flags_t)0)

/* Overlay traffic should be observed from bpf_xdp, bpf_host, and bpf_wireguard. */
#if defined(HAVE_ENCAP) && \
	(defined(IS_BPF_XDP) || defined(IS_BPF_HOST) || defined(IS_BPF_WIREGUARD))
# define OVERLAY_CLASSIFIERS
#endif

/**
 * ctx_classify
 * @ctx: socket buffer
 * @proto: the layer 3 protocol (ETH_P_IP, ETH_P_IPV6). 0 if unknown.
 *
 * Compute classifiers (CLS_FLAG_*) for the given packet to be used during
 * trace/drop notification events. In the worst case, three different checks
 * are performed to obtain a sufficiently informative classification:
 *
 * 1. packets from L3 devices: needed to signal CLS_FLAG_L3_DEV and CLS_FLAG_IPV6.
 * 2. ctx->mark: in case it carries magic values (ex. MARK_MAGIC_OVERLAY).
 * 3. packet headers: to look for known traffic patterns (ex. UDP+OverlayPort).
 *
 * The check (1) is always performed, (2) is skipped in XDP but executed in other
 * contexts, and (3) runs only when (2) was not informative enough.
 *
 * NOTE: this function uses `revalidate_data` rather than `revalidate_data_pull`
 * to preserve complexity. If a precise classification is expected where (3) is
 * needed to execute, make sure to use `revalidate_data_pull` before `ctx_classify`.
 */
static __always_inline cls_flags_t
ctx_classify(struct __ctx_buff *ctx, __be16 proto)
{
	cls_flags_t flags = CLS_FLAG_NONE;
	struct {
		__be16 sport;
		__be16 dport;
	} l4;
	__u8 l4_proto;
	int l3_hdrlen;
#if defined(ENABLE_IPV6) || defined(ENABLE_IPV4)
	void *data, *data_end;
# ifdef ENABLE_IPV6
	struct ipv6hdr *ip6 __maybe_unused;
# endif
# ifdef ENABLE_IPV4
	struct iphdr *ip4 __maybe_unused;
# endif
#endif /* ENABLE IPV6 || ENABLE_IPV4 */

	/*
	 * Check whether the packet comes from a L3 device (no ethernet).
	 * In that case, set the CLS_FLAG_L3_DEV flag and additionally set
	 * CLS_FLAG_IPV6 for IPv6 layer 3 packets (useful when reaching this
	 * code via the generic send_trace_notify).
	 */
	if (ETH_HLEN == 0) {
		flags |= CLS_FLAG_L3_DEV;
		if (!proto)
			proto = ctx_get_protocol(ctx);
		if (proto == bpf_htons(ETH_P_IPV6))
			flags |=  CLS_FLAG_IPV6;
	}

/*
 * Try computing remaining classifiers by looking at the ctx->mark.
 * This is useful for all those codepaths that rely on the mark
 * (e.g., MARK_MAGIC_OVERLAY).
 * In XDP this part is skipped, given the mark is not available.
 */
#if __ctx_is == __ctx_skb
# ifdef OVERLAY_CLASSIFIERS
	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY)
		switch (TUNNEL_PROTOCOL) {
		case TUNNEL_PROTOCOL_VXLAN:
			flags |= CLS_FLAG_VXLAN;
			goto out;
		case TUNNEL_PROTOCOL_GENEVE:
			flags |= CLS_FLAG_GENEVE;
			goto out;
		default:
			__throw_build_bug();
		}
# endif /* OVERLAY_CLASSIFIERS */
#endif /* __ctx_skb */

/*
 * Skip subsequent logic that parses the packet L3/L4 headers
 * when not needed (none of the following classifiers are enabled).
 * If previous checks on ctx->mark were already informative, the
 * whole codepath is already skipped with `goto out;`.
 */
#if !defined(OVERLAY_CLASSIFIERS)
	goto out;
#endif

	/*
	 * Inspect the L3 protocol, and retrieve l4_proto and l3_hdrlen.
	 * For IPv6, let's stop at the first header.
	 */
	if (!proto)
		proto = ctx_get_protocol(ctx);
	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			goto out;

		l4_proto = ip6->nexthdr;
		l3_hdrlen = sizeof(struct ipv6hdr);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			goto out;

		l4_proto = ip4->protocol;
		l3_hdrlen = ipv4_hdrlen(ip4);
		break;
#endif /* ENABLE_IPV4 */
	default:
		goto out;
	}

	/*
	 * Inspect the L4 protocol, looking for specific traffic patterns:
	 * - Overlay: UDP using TUNNEL_PORT.
	 */
	switch (l4_proto) {
	case IPPROTO_UDP:
		if (l4_load_ports(ctx, ETH_HLEN + l3_hdrlen + UDP_SPORT_OFF, &l4.sport) < 0)
			goto out;
#ifdef OVERLAY_CLASSIFIERS
		if (l4.sport == bpf_htons(TUNNEL_PORT) || l4.dport == bpf_htons(TUNNEL_PORT))
			switch (TUNNEL_PROTOCOL) {
			case TUNNEL_PROTOCOL_VXLAN:
				flags |= CLS_FLAG_VXLAN;
				goto out;
			case TUNNEL_PROTOCOL_GENEVE:
				flags |= CLS_FLAG_GENEVE;
				goto out;
			default:
				__throw_build_bug();
			}
#endif /* OVERLAY_CLASSIFIERS */
		break;
	}

out:
	return flags;
}
