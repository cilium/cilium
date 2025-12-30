/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/config/node.h>

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
	CLS_FLAG_IPV6      = (1 << 0),
	/* Packet originates from a L3 device (no ethernet header). */
	CLS_FLAG_L3_DEV    = (1 << 1),
	/* Packet uses underlay VXLAN. */
	CLS_FLAG_VXLAN     = (1 << 2),
	/* Packet uses underlay Geneve. */
	CLS_FLAG_GENEVE    = (1 << 3),
};

/* Wrapper for specifying empty flags during the trace/drop event. */
#define CLS_FLAG_NONE ((cls_flags_t)0)

static __always_inline __u8
cls_flag_tunnel()
{
#ifdef HAVE_ENCAP
	if (CONFIG(tunnel_protocol) == TUNNEL_PROTOCOL_VXLAN)
		return CLS_FLAG_VXLAN;
	if (CONFIG(tunnel_protocol) == TUNNEL_PROTOCOL_GENEVE)
		return CLS_FLAG_GENEVE;
#endif
	return 0;
}

static __always_inline bool
is_tunnel_port(__be16 dport __maybe_unused)
{
#ifdef HAVE_ENCAP
	return dport == bpf_htons(CONFIG(tunnel_port));
#else
	return false;
#endif
}

/**
 * can_observe_overlay_mark
 * @obs_point: trace observation point (TRACE_{FROM,TO}_*)
 *
 * Returns true whether the provided observation point can observe overlay traffic marked
 * with MARK_MAGIC_OVERLAY. This mark used in to-{netdev,wireguard}.
 */
static __always_inline bool
can_observe_overlay_mark(enum trace_point obs_point __maybe_unused)
{
	if (!is_defined(HAVE_ENCAP) || ctx_is_xdp())
		return false;

	if (is_defined(IS_BPF_HOST) && (obs_point == TRACE_TO_NETWORK ||
					obs_point == TRACE_POINT_UNKNOWN))
		return true;

	if (is_defined(IS_BPF_WIREGUARD) && (obs_point == TRACE_TO_CRYPTO ||
					     obs_point == TRACE_POINT_UNKNOWN))
		return true;

	return false;
}

/**
 * can_observe_overlay_hdr
 * @obs_point: trace observation point (TRACE_{FROM,TO}_*)
 *
 * Returns true whether the provided observation point can observe overlay traffic via raw packet
 * parsing of L2/L3/L4 headers. Such packets are traced in from-{netdev,wireguard}, and in to-stack
 * events with ENABLE_IPSEC (VinE).
 */
static __always_inline bool
can_observe_overlay_hdr(enum trace_point obs_point)
{
	if (!is_defined(HAVE_ENCAP))
		return false;

	if (is_defined(IS_BPF_HOST) && (obs_point == TRACE_FROM_NETWORK ||
					obs_point == TRACE_POINT_UNKNOWN ||
					(is_defined(ENABLE_IPSEC) && obs_point == TRACE_TO_STACK)))
		return true;

	if (is_defined(IS_BPF_WIREGUARD) && (obs_point == TRACE_FROM_CRYPTO ||
					     obs_point == TRACE_POINT_UNKNOWN))
		return true;

	return false;
}

/**
 * ctx_is_overlay_hdr
 * @ctx: socket buffer
 * @proto: the layer 3 protocol (ETH_P_IP, ETH_P_IPV6).
 *
 * Returns true whether the packet carries Overlay traffic. This is true when the
 * outer L4 header is UDP and the destination port matches tunnel_port.
 */
static __always_inline bool
ctx_is_overlay_hdr(struct __ctx_buff *ctx, __be16 proto)
{
	void __maybe_unused *data;
	void __maybe_unused *data_end;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	__be16 dport;
	__u8 l4_proto;
	int l3_hdrlen;

	if (!is_defined(HAVE_ENCAP))
		return false;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return false;

		l4_proto = ip6->nexthdr;
		l3_hdrlen = sizeof(struct ipv6hdr);
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return false;

		l4_proto = ip4->protocol;
		l3_hdrlen = ipv4_hdrlen(ip4);
		break;
#endif
	default:
		return false;
	}

	if (l4_proto != IPPROTO_UDP)
		return false;

	if (l4_load_port(ctx, ETH_HLEN + l3_hdrlen + UDP_DPORT_OFF, &dport) < 0)
		return false;

	return is_tunnel_port(dport);
}

/**
 * ctx_is_encrypted_by_point
 * @ctx: socket buffer
 * @obs_point: trace observation point (TRACE_{FROM,TO}_*)
 *
 * Returns true whether the provided observation point can observe an encrypted
 * IPSec/WireGuard packet based on MARK_MAGIC_{EN,DE}CRYPT.
 *
 * The following cases are handled:
 * 1. Encrypted IPSec/WireGuard packets pre-decryption in from-netdev.
 * 2. Encrypted IPSec/WireGuard packets post-encryption in to-netdev.
 * 3. Encrypted IPSec packets pre-decryption in from-network.
 *
 * The TRACE_{FROM,TO}_CRYPTO in bpf_wireguard are explicitly ignored, given
 * they handle post-decryption/pre-encryption packets. This can come at hand in
 * future extension, but for now Hubble has enough info from the obs_point.
 * In addition, in these hook we can still observe unmarked overlay packets,
 * so we don't want to skip the `ctx_is_overlay_hdr` parsing in `ctx_classify`.
 */
static __always_inline bool
ctx_is_encrypted_by_point(struct __ctx_buff *ctx __maybe_unused,
			  enum trace_point obs_point __maybe_unused)
{
#if __ctx_is == __ctx_skb
	if (is_defined(IS_BPF_HOST) &&
	    (is_defined(ENABLE_IPSEC) || is_defined(ENABLE_WIREGUARD)) &&
	    (obs_point == TRACE_FROM_NETWORK || obs_point == TRACE_TO_NETWORK || obs_point == TRACE_POINT_UNKNOWN))
		return ctx_is_decrypt(ctx);

	if (is_defined(IS_BPF_HOST) && is_defined(ENABLE_IPSEC) &&
	    (obs_point == TRACE_FROM_STACK || obs_point == TRACE_POINT_UNKNOWN))
		return ctx_is_encrypt(ctx);

	if (is_defined(IS_BPF_NETWORK) && is_defined(ENABLE_IPSEC) &&
	    (obs_point == TRACE_FROM_NETWORK || obs_point == TRACE_TO_HOST || obs_point == TRACE_POINT_UNKNOWN))
		return ctx_is_decrypt(ctx);
#endif

	return false;
}

/**
 * ctx_classify
 * @ctx: socket buffer
 * @proto: the layer 3 protocol (ETH_P_IP, ETH_P_IPV6).
 * @obs_point: the observation point (TRACE_{FROM,TO}_*).
 *
 * Compute classifiers (CLS_FLAG_*) for the given packet to be used during
 * trace/drop notification events. There exists two main computation methods:
 *
 * 1. inspecting ctx->mark for known magic values (ex. MARK_MAGIC_OVERLAY):
 *    this is used for matching patterns that mark packets (e.g., Overlay).
 * 2. inspecting L3/L4 headers for known traffic patterns (ex. UDP+OverlayPort):
 *    this is done ONLY to match Overlay packets, given all the other known
 *    patterns (IPSec/WireGuard) will mark packets accordingly.
 *
 * Both the two methods are optimized based on the observation point to preserve
 * performance and verifier complexity.
 */
static __always_inline cls_flags_t
ctx_classify(struct __ctx_buff *ctx, __be16 proto, enum trace_point obs_point)
{
	cls_flags_t flags = CLS_FLAG_NONE;

	/* Retrieve protocol when not being provided. */
	if (!proto)
		proto = ctx_get_protocol(ctx);

	/* Check whether the packet comes from a L3 device (no ethernet). */
	if (THIS_IS_L3_DEV)
		flags |= CLS_FLAG_L3_DEV;

	/* Check if IPv6 packet. */
	if (proto == bpf_htons(ETH_P_IPV6))
		flags |= CLS_FLAG_IPV6;

/* ctx->mark not available in XDP. */
#if __ctx_is == __ctx_skb
	/* Check if Encrypted by packet mark. */
	if (ctx_is_encrypted_by_point(ctx, obs_point))
		goto out;

	/* Check if Overlay by packet mark. */
	if (can_observe_overlay_mark(obs_point) && ctx_is_overlay(ctx)) {
		flags |= cls_flag_tunnel();
		goto out;
	}
#endif /* __ctx_skb */

	/* Check if Overlay by packet header. */
	if (can_observe_overlay_hdr(obs_point) && ctx_is_overlay_hdr(ctx, proto))
		flags |= cls_flag_tunnel();

out: __maybe_unused
	return flags;
}

/**
 * compute_capture_len
 * @ctx: socket buffer
 * @monitor: the monitor value
 * @flags: the classifier flags (CLS_FLAG_*)
 * @obs_point: the trace observation point (TRACE_{FROM,TO}_*)
 *
 * Compute capture length for the trace/drop notification event.
 * Return at most `ctx_full_len` bytes.
 * With monitor=0, use the config value `trace_payload_len` for native packets, and
 * `trace_payload_len_overlay` for overlay packets with CLS_FLAG_{VXLAN,GENEVE} set. For overlay
 * packets, reuse the `obs_point` to save complexity.
 */
static __always_inline __u64
compute_capture_len(struct __ctx_buff *ctx, __u64 monitor,
		    cls_flags_t flags, enum trace_point obs_point)
{
	__u32 cap_len_default = CONFIG(trace_payload_len);

	if ((can_observe_overlay_mark(obs_point) || can_observe_overlay_hdr(obs_point)) &&
	    flags & cls_flag_tunnel())
		cap_len_default = CONFIG(trace_payload_len_overlay);

	if (monitor == 0 || monitor == CONFIG(trace_payload_len))
		monitor = cap_len_default;

	return min_t(__u64, monitor, ctx_full_len(ctx));
}
