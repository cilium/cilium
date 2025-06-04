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

#ifdef HAVE_ENCAP
/* Return the correct overlay flag CLS_FLAG_{VXLAN,GENEVE} based on the current TUNNEL_PROTOCOL. */
#define CLS_FLAG_TUNNEL                               \
	(__builtin_constant_p(TUNNEL_PROTOCOL) ?              \
		((TUNNEL_PROTOCOL) == TUNNEL_PROTOCOL_VXLAN ? CLS_FLAG_VXLAN : \
		 (TUNNEL_PROTOCOL) == TUNNEL_PROTOCOL_GENEVE ? CLS_FLAG_GENEVE : \
		 (__throw_build_bug(), 0))                        \
	: (__throw_build_bug(), 0))
#endif

/**
 * ctx_classify
 * @ctx: socket buffer
 * @proto: the layer 3 protocol (ETH_P_IP, ETH_P_IPV6).
 *
 * Compute classifiers (CLS_FLAG_*) for the given packet to be used during
 * trace/drop notification events. There exists two main computation methods:
 *
 * 1. inspecting ctx->mark for known magic values (ex. MARK_MAGIC_OVERLAY).
 * 3. inspecting L3/L4 headers for known traffic patterns (ex. UDP+OverlayPort).
 */
static __always_inline cls_flags_t
ctx_classify(struct __ctx_buff *ctx, __be16 proto)
{
	cls_flags_t flags = CLS_FLAG_NONE;
	bool parse_overlay = false;
	void __maybe_unused *data;
	void __maybe_unused *data_end;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	__be16 __maybe_unused dport;
	__u8 __maybe_unused l4_proto;
	int __maybe_unused l3_hdrlen;

	/*
	 * Retrieve protocol when not being provided.
	 * (ex. from drop notifications, or when previous calls to validate_ethertype failed)
	 */
	if (!proto)
		proto = ctx_get_protocol(ctx);

	/* Check whether the packet comes from a L3 device (no ethernet). */
	if (ETH_HLEN == 0)
		flags |= CLS_FLAG_L3_DEV;

	/* Check if IPv6 packet. */
	if (proto == bpf_htons(ETH_P_IPV6))
		flags |= CLS_FLAG_IPV6;

/* ctx->mark not available in XDP. */
#if __ctx_is == __ctx_skb
# ifdef HAVE_ENCAP
	/* MARK_MAGIC_OVERLAY is used in to-{netdev,wireguard}. */
	if ((is_defined(IS_BPF_HOST) || is_defined(IS_BPF_WIREGUARD)) &&
	    (ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY) {
		flags |= CLS_FLAG_TUNNEL;
		goto out;
	}
# endif /* HAVE_ENCAP */
#endif /* __ctx_skb */

#ifdef HAVE_ENCAP
	/* Enable parsing packet headers for Overlay in from-{netdev,wireguard} and to-stack. */
	if (is_defined(IS_BPF_HOST) || is_defined(IS_BPF_WIREGUARD))
		parse_overlay = true;
#endif /* HAVE_ENCAP */

	/*
	 * Skip subsequent logic that parses the packet L3/L4 headers
	 * when not needed. For new classifiers, let's use other variables `parse_*`.
	 */
	if (!parse_overlay)
		goto out;

	/*
	 * Inspect the L3 protocol, and retrieve l4_proto and l3_hdrlen.
	 * For IPv6, let's stop at the first header.
	 */
	switch (proto) {
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			goto out;

		l4_proto = ip6->nexthdr;
		l3_hdrlen = sizeof(struct ipv6hdr);
		break;
# endif /* ENABLE_IPV6 */
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			goto out;

		l4_proto = ip4->protocol;
		l3_hdrlen = ipv4_hdrlen(ip4);
		break;
# endif /* ENABLE_IPV4 */
	default:
		goto out;
	}

	/*
	 * Inspect the L4 protocol, looking for specific traffic patterns:
	 * - Overlay: UDP with destination port TUNNEL_PORT.
	 */
	switch (l4_proto) {
	case IPPROTO_UDP:
		if (l4_load_port(ctx, ETH_HLEN + l3_hdrlen + UDP_DPORT_OFF, &dport) < 0)
			goto out;
#ifdef HAVE_ENCAP
		if (parse_overlay && dport == bpf_htons(TUNNEL_PORT)) {
			flags |= CLS_FLAG_TUNNEL;
			goto out;
		}
#endif /* HAVE_ENCAP */
		break;
	}

out:
	return flags;
}
