/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * Packet forwarding notification via perf event ring buffer.
 *
 * API:
 * void send_trace_notify(ctx, obs_point, src, dst, dst_id, ifindex, reason, monitor)
 *
 * @ctx:	socket buffer
 * @obs_point:	observation point (TRACE_*)
 * @src:	source identity
 * @dst:	destination identity
 * @dst_id:	destination endpoint id or proxy destination port
 * @ifindex:	network interface index
 * @reason:	reason for forwarding the packet (TRACE_REASON_*),
 *		e.g. return value of ct_lookup or TRACE_REASON_ENCRYPTED
 * @monitor:	monitor aggregation value, e.g. the 'monitor' output of ct_lookup
 *
 * If TRACE_NOTIFY is not defined, the API will be compiled in as a NOP.
 */
#pragma once

#include "dbg.h"
#include "events.h"
#include "common.h"
#include "ipv6.h"
#include "utils.h"
#include "metrics.h"
#include "ratelimit.h"
#include "classifiers.h"
#include "trace_helpers.h"

/* Reasons for forwarding a packet, keep in sync with pkg/monitor/datapath_trace.go */
enum trace_reason {
	TRACE_REASON_POLICY = CT_NEW,
	TRACE_REASON_CT_ESTABLISHED = CT_ESTABLISHED,
	TRACE_REASON_CT_REPLY = CT_REPLY,
	TRACE_REASON_CT_RELATED = CT_RELATED,
	TRACE_REASON_RESERVED,      /* Previous TRACE_REASON_CT_REOPENED. */
	TRACE_REASON_UNKNOWN,
	TRACE_REASON_SRV6_ENCAP,
	TRACE_REASON_SRV6_DECAP,
	TRACE_REASON_RESERVED_2,    /* Previous TRACE_REASON_ENCRYPT_OVERLAY. */
	/* Note: TRACE_REASON_ENCRYPTED is used as a mask. Beware if you add
	 * new values below it, they would match with that mask.
	 */
	TRACE_REASON_ENCRYPTED = 0x80,
} __packed;

/* Trace aggregation levels. */
enum {
	TRACE_AGGREGATE_NONE = 0,      /* Trace every packet on rx & tx */
	TRACE_AGGREGATE_RX = 1,        /* Hide trace on packet receive */
	TRACE_AGGREGATE_ACTIVE_CT = 3, /* Ratelimit active connection traces */
};

#define TRACE_EP_ID_UNKNOWN		0
#define TRACE_IFINDEX_UNKNOWN		0	/* Linux kernel doesn't use ifindex 0 */

#ifndef MONITOR_AGGREGATION
#define MONITOR_AGGREGATION TRACE_AGGREGATE_NONE
#endif

#ifndef TRACE_EXTENSION
#define TRACE_EXTENSION
#define trace_extension_hook(ctx, msg) do {} while (0)
#endif

/**
 * update_trace_metrics
 * @ctx:	socket buffer
 * @obs_point:	observation point (TRACE_*)
 * @reason:	reason for forwarding the packet (TRACE_REASON_*)
 *
 * Update metrics based on a trace event
 */
#define update_trace_metrics(ctx, obs_point, reason) \
	_update_trace_metrics(ctx, obs_point, reason, __MAGIC_LINE__, __MAGIC_FILE__)
static __always_inline void
_update_trace_metrics(struct __ctx_buff *ctx, enum trace_point obs_point,
		      enum trace_reason reason, __u16 line, __u8 file)
{
	__u8 encrypted;

	switch (obs_point) {
	case TRACE_TO_LXC:
		_update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
				REASON_FORWARDED, line, file);
		break;
	case TRACE_TO_HOST:
	case TRACE_TO_STACK:
	case TRACE_TO_OVERLAY:
	case TRACE_TO_NETWORK:
		_update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
				REASON_FORWARDED, line, file);
		break;
	case TRACE_FROM_HOST:
	case TRACE_FROM_STACK:
	case TRACE_FROM_OVERLAY:
	case TRACE_FROM_NETWORK:
		encrypted = reason & TRACE_REASON_ENCRYPTED;
		if (!encrypted)
			_update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
					REASON_PLAINTEXT, line, file);
		else
			_update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
					REASON_DECRYPT, line, file);
		break;
	/* TRACE_FROM_LXC, i.e endpoint-to-endpoint delivery is handled
	 * separately in ipv*_local_delivery() where we can bump an egress
	 * forward. It could still be dropped but it would show up later as an
	 * ingress drop, in that scenario.
	 *
	 * TRACE_{FROM,TO}_PROXY are not handled in datapath. This is because
	 * we have separate L7 proxy "forwarded" and "dropped" (ingress/egress)
	 * counters in the proxy layer to capture these metrics.
	 */
	case TRACE_FROM_LXC:
	case TRACE_FROM_PROXY:
	case TRACE_TO_PROXY:
		break;
	/* TRACE_FROM_CRYPTO and TRACE_TO_CRYPTO are used to trace encrypted/decrypted
	 * packets in the WireGuard interface cilium_wg0.
	 * Using these obs points from different programs would result in a build bug.
	 */
#if defined(IS_BPF_WIREGUARD)
	case TRACE_TO_CRYPTO:
		_update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
				REASON_ENCRYPTING, line, file);
		break;
	case TRACE_FROM_CRYPTO:
		_update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
				REASON_DECRYPTING, line, file);
		break;
#else
	case TRACE_TO_CRYPTO:
	case TRACE_FROM_CRYPTO:
		__throw_build_bug();
		break;
#endif
	case TRACE_POINT_UNKNOWN:
		__throw_build_bug();
		break;
	}
}

struct trace_ctx {
	enum trace_reason reason;
	__u32 monitor;	/* Monitor length for number of bytes to forward in
			 * trace message. 0 means do not monitor.
			 */
};

struct trace_notify {
	NOTIFY_CAPTURE_HDR
	__u32		src_label;
	__u32		dst_label;
	__u16		dst_id;
	__u8		reason;
	__u8		flags; /* __u8 instead of cls_flags_t so that it will error
				* when cls_flags_t grows (move to flags_lower/flags_upper).
				*/
	__u32		ifindex;
	union {
		struct {
			__be32		orig_ip4;
			__u32		orig_pad1;
			__u32		orig_pad2;
			__u32		orig_pad3;
		};
		union v6addr	orig_ip6;
	};
	__u64		ip_trace_id;
	TRACE_EXTENSION
};

#ifdef TRACE_NOTIFY

/* Trace notify version 2 includes IP Trace support. */
#define NOTIFY_TRACE_VER 2

static __always_inline bool
emit_trace_notify(enum trace_point obs_point, __u32 monitor)
{
	if (MONITOR_AGGREGATION >= TRACE_AGGREGATE_RX) {
		switch (obs_point) {
		case TRACE_FROM_LXC:
		case TRACE_FROM_PROXY:
		case TRACE_FROM_HOST:
		case TRACE_FROM_STACK:
		case TRACE_FROM_OVERLAY:
		case TRACE_FROM_CRYPTO:
		case TRACE_FROM_NETWORK:
			return false;
		default:
			break;
		}
	}

	/*
	 * Ignore sample when aggregation is enabled and 'monitor' is set to 0.
	 * Rate limiting (trace message aggregation) relies on connection tracking,
	 * so if there is no CT information available at the observation point,
	 * then 'monitor' will be set to 0 to avoid emitting trace notifications
	 * when aggregation is enabled (the default).
	 */
	if (MONITOR_AGGREGATION >= TRACE_AGGREGATE_ACTIVE_CT && !monitor)
		return false;

	return true;
}

static __always_inline void
_send_trace_notify(struct __ctx_buff *ctx, enum trace_point obs_point,
		   __u32 src, __u32 dst, __u16 dst_id, __u32 ifindex,
		   enum trace_reason reason, __u32 monitor,
		   __be16 proto, __u16 line, __u8 file)
{
	__u64 ip_trace_id = load_ip_trace_id();
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len;
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_EVENTS_MAP,
	};
	struct ratelimit_settings settings = {
		.topup_interval_ns = NSEC_PER_SEC,
	};
	struct trace_notify msg __align_stack_8;
	cls_flags_t flags = CLS_FLAG_NONE;

	_update_trace_metrics(ctx, obs_point, reason, line, file);

	if (!emit_trace_notify(obs_point, monitor))
		return;

	if (EVENTS_MAP_RATE_LIMIT > 0) {
		settings.bucket_size = EVENTS_MAP_BURST_LIMIT;
		settings.tokens_per_topup = EVENTS_MAP_RATE_LIMIT;
		if (!ratelimit_check_and_take(&rkey, &settings))
			return;
	}

	flags = ctx_classify(ctx, proto, obs_point);
	cap_len = compute_capture_len(ctx, monitor, flags, obs_point);

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_TRACE, obs_point),
		__notify_pktcap_hdr((__u32)ctx_len, (__u16)cap_len, NOTIFY_TRACE_VER),
		.src_label	= src,
		.dst_label	= dst,
		.dst_id		= dst_id,
		.reason		= reason,
		.flags		= flags,
		.ifindex	= ifindex,
		.ip_trace_id	= ip_trace_id,
	};
	memset(&msg.orig_ip6, 0, sizeof(union v6addr));

	trace_extension_hook(ctx, msg);
	ctx_event_output(ctx, &cilium_events,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static __always_inline void
_send_trace_notify4(struct __ctx_buff *ctx, enum trace_point obs_point,
		    __u32 src, __u32 dst, __be32 orig_addr, __u16 dst_id,
		    __u32 ifindex, enum trace_reason reason, __u32 monitor,
		    __u16 line, __u8 file)
{
	__u64 ip_trace_id = load_ip_trace_id();
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len;
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_EVENTS_MAP,
	};
	struct ratelimit_settings settings = {
		.topup_interval_ns = NSEC_PER_SEC,
	};
	struct trace_notify msg __align_stack_8;
	cls_flags_t flags = CLS_FLAG_NONE;

	_update_trace_metrics(ctx, obs_point, reason, line, file);

	if (!emit_trace_notify(obs_point, monitor))
		return;

	if (EVENTS_MAP_RATE_LIMIT > 0) {
		settings.bucket_size = EVENTS_MAP_BURST_LIMIT;
		settings.tokens_per_topup = EVENTS_MAP_RATE_LIMIT;
		if (!ratelimit_check_and_take(&rkey, &settings))
			return;
	}

	flags = ctx_classify(ctx, bpf_htons(ETH_P_IP), obs_point);
	cap_len = compute_capture_len(ctx, monitor, flags, obs_point);

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_TRACE, obs_point),
		__notify_pktcap_hdr((__u32)ctx_len, (__u16)cap_len, NOTIFY_TRACE_VER),
		.src_label	= src,
		.dst_label	= dst,
		.dst_id		= dst_id,
		.reason		= reason,
		.ifindex	= ifindex,
		.flags		= flags,
		.orig_ip4	= orig_addr,
		.ip_trace_id	= ip_trace_id,
	};

	trace_extension_hook(ctx, msg);
	ctx_event_output(ctx, &cilium_events,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static __always_inline void
_send_trace_notify6(struct __ctx_buff *ctx, enum trace_point obs_point,
		    __u32 src, __u32 dst, const union v6addr *orig_addr,
		    __u16 dst_id, __u32 ifindex, enum trace_reason reason,
		    __u32 monitor, __u16 line, __u8 file)
{
	__u64 ip_trace_id = load_ip_trace_id();
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len;
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_EVENTS_MAP,
	};
	struct ratelimit_settings settings = {
		.topup_interval_ns = NSEC_PER_SEC,
	};
	struct trace_notify msg __align_stack_8;
	cls_flags_t flags = CLS_FLAG_NONE;

	_update_trace_metrics(ctx, obs_point, reason, line, file);

	if (!emit_trace_notify(obs_point, monitor))
		return;

	if (EVENTS_MAP_RATE_LIMIT > 0) {
		settings.bucket_size = EVENTS_MAP_BURST_LIMIT;
		settings.tokens_per_topup = EVENTS_MAP_RATE_LIMIT;
		if (!ratelimit_check_and_take(&rkey, &settings))
			return;
	}

	flags = ctx_classify(ctx, bpf_htons(ETH_P_IPV6), obs_point);
	cap_len = compute_capture_len(ctx, monitor, flags, obs_point);

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_TRACE, obs_point),
		__notify_pktcap_hdr((__u32)ctx_len, (__u16)cap_len, NOTIFY_TRACE_VER),
		.src_label	= src,
		.dst_label	= dst,
		.dst_id		= dst_id,
		.reason		= reason,
		.ifindex	= ifindex,
		.flags		= flags,
		.ip_trace_id	= ip_trace_id,
	};

	ipv6_addr_copy(&msg.orig_ip6, orig_addr);

	trace_extension_hook(ctx, msg);
	ctx_event_output(ctx, &cilium_events,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}
#else
static __always_inline void
_send_trace_notify(struct __ctx_buff *ctx, enum trace_point obs_point,
		   __u32 src __maybe_unused, __u32 dst __maybe_unused,
		   __u16 dst_id __maybe_unused, __u32 ifindex __maybe_unused,
		   enum trace_reason reason, __u32 monitor __maybe_unused,
		   __be16 proto __maybe_unused, __u16 line, __u8 file)
{
	_update_trace_metrics(ctx, obs_point, reason, line, file);
}

static __always_inline void
_send_trace_notify4(struct __ctx_buff *ctx, enum trace_point obs_point,
		    __u32 src __maybe_unused, __u32 dst __maybe_unused,
		    __be32 orig_addr __maybe_unused, __u16 dst_id __maybe_unused,
		    __u32 ifindex __maybe_unused, enum trace_reason reason,
		    __u32 monitor __maybe_unused,
		    __u16 line, __u8 file)
{
	_update_trace_metrics(ctx, obs_point, reason, line, file);
}

static __always_inline void
_send_trace_notify6(struct __ctx_buff *ctx, enum trace_point obs_point,
		    __u32 src __maybe_unused, __u32 dst __maybe_unused,
		    union v6addr *orig_addr __maybe_unused,
		    __u16 dst_id __maybe_unused, __u32 ifindex __maybe_unused,
		    enum trace_reason reason, __u32 monitor __maybe_unused,
		    __u16 line, __u8 file)
{
	_update_trace_metrics(ctx, obs_point, reason, line, file);
}
#endif /* TRACE_NOTIFY */

/* send_trace_notify emits a generic trace notify. */
#define send_trace_notify(ctx, obs_point, src, dst, dst_id, ifindex, reason, monitor, proto) \
	_send_trace_notify(ctx, obs_point, src, dst, dst_id, ifindex, reason, monitor, proto, \
	__MAGIC_LINE__, __MAGIC_FILE__)

/* send_trace_notify4 emits a trace notify with the original IPv4 address before translation. */
#define send_trace_notify4(ctx, obs_point, src, dst, orig_addr, dst_id, ifindex, reason, monitor) \
	_send_trace_notify4(ctx, obs_point, src, dst, orig_addr, dst_id, ifindex, reason, monitor, \
	__MAGIC_LINE__, __MAGIC_FILE__)

/* send_trace_notify6 emits a trace notify with the original IPv6 address before translation. */
#define send_trace_notify6(ctx, obs_point, src, dst, orig_addr, dst_id, ifindex, reason, monitor) \
	_send_trace_notify6(ctx, obs_point, src, dst, orig_addr, dst_id, ifindex, reason, monitor, \
	__MAGIC_LINE__, __MAGIC_FILE__)
