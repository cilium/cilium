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
#ifndef __LIB_TRACE__
#define __LIB_TRACE__

#include "dbg.h"
#include "events.h"
#include "common.h"
#include "utils.h"
#include "metrics.h"

/* Available observation points. */
enum trace_point {
	TRACE_TO_LXC,
	TRACE_TO_PROXY,
	TRACE_TO_HOST,
	TRACE_TO_STACK,
	TRACE_TO_OVERLAY,
	TRACE_FROM_LXC,
	TRACE_FROM_PROXY,
	TRACE_FROM_HOST,
	TRACE_FROM_STACK,
	TRACE_FROM_OVERLAY,
	TRACE_FROM_NETWORK,
	TRACE_TO_NETWORK,
} __packed;

/* Reasons for forwarding a packet. */
enum trace_reason {
	TRACE_REASON_POLICY = CT_NEW,
	TRACE_REASON_CT_ESTABLISHED = CT_ESTABLISHED,
	TRACE_REASON_CT_REPLY = CT_REPLY,
	TRACE_REASON_CT_RELATED = CT_RELATED,
	TRACE_REASON_CT_REOPENED = CT_REOPENED,
	TRACE_REASON_UNKNOWN,
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

#ifndef MONITOR_AGGREGATION
#define MONITOR_AGGREGATION TRACE_AGGREGATE_NONE
#endif

/**
 * update_trace_metrics
 * @ctx:	socket buffer
 * @obs_point:	observation point (TRACE_*)
 * @reason:	reason for forwarding the packet (TRACE_REASON_*)
 *
 * Update metrics based on a trace event
 */
static __always_inline void
update_trace_metrics(struct __ctx_buff *ctx, enum trace_point obs_point,
		     enum trace_reason reason)
{
	__u8 encrypted;

	switch (obs_point) {
	case TRACE_TO_LXC:
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_FORWARDED);
		break;
	case TRACE_TO_HOST:
	case TRACE_TO_STACK:
	case TRACE_TO_OVERLAY:
	case TRACE_TO_NETWORK:
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
			       REASON_FORWARDED);
		break;
	case TRACE_FROM_HOST:
	case TRACE_FROM_STACK:
	case TRACE_FROM_OVERLAY:
	case TRACE_FROM_NETWORK:
		encrypted = reason & TRACE_REASON_ENCRYPTED;
		if (!encrypted)
			update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
				       REASON_PLAINTEXT);
		else
			update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
				       REASON_DECRYPT);
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
	}
}

struct trace_ctx {
	enum trace_reason reason;
	__u32 monitor;	/* Monitor length for number of bytes to forward in
			 * trace message. 0 means do not monitor.
			 */
};

#ifdef TRACE_NOTIFY
struct trace_notify {
	NOTIFY_CAPTURE_HDR
	__u32		src_label;
	__u32		dst_label;
	__u16		dst_id;
	__u8		reason;
	__u8		ipv6:1;
	__u8		pad:7;
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
};

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
send_trace_notify(struct __ctx_buff *ctx, enum trace_point obs_point,
		  __u32 src, __u32 dst, __u16 dst_id, __u32 ifindex,
		  enum trace_reason reason, __u32 monitor)
{
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, monitor ? : TRACE_PAYLOAD_LEN,
			      ctx_len);
	struct trace_notify msg __align_stack_8;

	update_trace_metrics(ctx, obs_point, reason);

	if (!emit_trace_notify(obs_point, monitor))
		return;

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_TRACE, obs_point),
		__notify_pktcap_hdr(ctx_len, (__u16)cap_len),
		.src_label	= src,
		.dst_label	= dst,
		.dst_id		= dst_id,
		.reason		= reason,
		.ifindex	= ifindex,
	};
	memset(&msg.orig_ip6, 0, sizeof(union v6addr));

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static __always_inline void
send_trace_notify4(struct __ctx_buff *ctx, enum trace_point obs_point,
		   __u32 src, __u32 dst, __be32 orig_addr, __u16 dst_id,
		   __u32 ifindex, enum trace_reason reason, __u32 monitor)
{
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, monitor ? : TRACE_PAYLOAD_LEN,
			      ctx_len);
	struct trace_notify msg;

	update_trace_metrics(ctx, obs_point, reason);

	if (!emit_trace_notify(obs_point, monitor))
		return;

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_TRACE, obs_point),
		__notify_pktcap_hdr(ctx_len, (__u16)cap_len),
		.src_label	= src,
		.dst_label	= dst,
		.dst_id		= dst_id,
		.reason		= reason,
		.ifindex	= ifindex,
		.ipv6		= 0,
		.orig_ip4	= orig_addr,
	};

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static __always_inline void
send_trace_notify6(struct __ctx_buff *ctx, enum trace_point obs_point,
		   __u32 src, __u32 dst, const union v6addr *orig_addr,
		   __u16 dst_id, __u32 ifindex, enum trace_reason reason,
		   __u32 monitor)
{
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, monitor ? : TRACE_PAYLOAD_LEN,
			      ctx_len);
	struct trace_notify msg;

	update_trace_metrics(ctx, obs_point, reason);

	if (!emit_trace_notify(obs_point, monitor))
		return;

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_TRACE, obs_point),
		__notify_pktcap_hdr(ctx_len, (__u16)cap_len),
		.src_label	= src,
		.dst_label	= dst,
		.dst_id		= dst_id,
		.reason		= reason,
		.ifindex	= ifindex,
		.ipv6		= 1,
	};

	ipv6_addr_copy(&msg.orig_ip6, orig_addr);

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}
#else
static __always_inline void
send_trace_notify(struct __ctx_buff *ctx, enum trace_point obs_point,
		  __u32 src __maybe_unused, __u32 dst __maybe_unused,
		  __u16 dst_id __maybe_unused, __u32 ifindex __maybe_unused,
		  enum trace_reason reason, __u32 monitor __maybe_unused)
{
	update_trace_metrics(ctx, obs_point, reason);
}

static __always_inline void
send_trace_notify4(struct __ctx_buff *ctx, enum trace_point obs_point,
		   __u32 src __maybe_unused, __u32 dst __maybe_unused,
		   __be32 orig_addr __maybe_unused, __u16 dst_id __maybe_unused,
		   __u32 ifindex __maybe_unused, enum trace_reason reason,
		   __u32 monitor __maybe_unused)
{
	update_trace_metrics(ctx, obs_point, reason);
}

static __always_inline void
send_trace_notify6(struct __ctx_buff *ctx, enum trace_point obs_point,
		   __u32 src __maybe_unused, __u32 dst __maybe_unused,
		   union v6addr *orig_addr __maybe_unused,
		   __u16 dst_id __maybe_unused, __u32 ifindex __maybe_unused,
		   enum trace_reason reason, __u32 monitor __maybe_unused)
{
	update_trace_metrics(ctx, obs_point, reason);
}
#endif /* TRACE_NOTIFY */
#endif /* __LIB_TRACE__ */
