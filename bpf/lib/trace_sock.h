/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * Socket based service load-balancing notification via perf event ring buffer.
 *
 * API:
 * void send_trace_sock_notify(ctx, xlate_point, dst_ip, dst_port)
 *
 * @ctx:	 socket address structre
 * @xlate_point: pre- or post- service translation point for load-balancing
 * @dst_ip:	 pre- or post- service translation destination ip address
 * @dst_port:	 pre- or post- service translation destination port
 *
 * If TRACE_SOCK_NOTIFY is not defined, the API will be compiled in as a NOP.
 */
#pragma once

#include <bpf/ctx/sock.h>

#include "common.h"
#include "events.h"
#include "ratelimit.h"
#include "sock.h"
#include "time.h"

/* Trace aggregation levels for socket traces (sock context only). */
enum {
	TRACE_SOCK_AGGREGATE_NONE	= 0, /* Trace every syscall */
	TRACE_SOCK_AGGREGATE_RECV	= 1, /* Hide trace on receive syscalls */
	TRACE_SOCK_AGGREGATE_CONNECT	= 3, /* Only trace connect syscalls */
};

/* Default monitor aggregation value when not provided by build defines. */
#ifndef MONITOR_AGGREGATION
#define MONITOR_AGGREGATION TRACE_SOCK_AGGREGATE_NONE
#endif

#ifndef TRACE_SOCK_EXTENSION
#define TRACE_SOCK_EXTENSION
#define trace_sock_extension_hook(ctx, msg) do {} while (0)
#endif

/* L4 protocol for the trace event */
enum l4_protocol {
	L4_PROTOCOL_UNKNOWN = 0,
	L4_PROTOCOL_TCP = 1,
	L4_PROTOCOL_UDP = 2,
} __packed;

/* Direction for translation between service and backend IP */
enum xlate_point {
	XLATE_UNKNOWN = 0,
	XLATE_PRE_DIRECTION_FWD = 1,  /* Pre service forward translation */
	XLATE_POST_DIRECTION_FWD = 2, /* Post service forward translation */
	XLATE_PRE_DIRECTION_REV = 3,  /* Pre reverse service translation */
	XLATE_POST_DIRECTION_REV = 4, /* Post reverse service translation */
} __packed;

struct ip {
	union {
		struct {
			__be32 ip4;
			__u32 pad1;
			__u32 pad2;
			__u32 pad3;
		};
		union v6addr ip6;
	} __packed;
};

struct trace_sock_notify {
	__u8 type;
	__u8 xlate_point;
	__u8 l4_proto;
	__u8 ipv6 : 1;
	__u8 pad : 7;
	__u16 dst_port;
	__u16 pad2;
	__u64 sock_cookie;
	__u64 cgroup_id;
	struct ip dst_ip;
	TRACE_SOCK_EXTENSION
};

#ifdef TRACE_SOCK_NOTIFY
static __always_inline enum l4_protocol
parse_protocol(__u32 l4_proto) {
	switch (l4_proto) {
	case IPPROTO_TCP:
		return L4_PROTOCOL_TCP;
	case IPPROTO_UDP:
		return L4_PROTOCOL_UDP;
	default:
		return L4_PROTOCOL_UNKNOWN;
	}
}

/* Apply monitor aggregation mapping for socket events.
 * Mapping mirrors packet-side behavior and documented levels:
 * - none (0): emit all socket trace events
 * - lowest/low (1/2): suppress reverse-direction (recv) socket traces
 * - medium/max (3/4): only emit connect-initiated traces
 *
 * When aggregation is enabled (>=1), rate limiting aligns to CT_REPORT_INTERVAL.
 */
static __always_inline bool
emit_trace_sock_notify(enum xlate_point xlate_point, bool is_connect)
{
	/* Hide reverse-direction traces starting at RX-level aggregation. */
	if (MONITOR_AGGREGATION >= TRACE_SOCK_AGGREGATE_RECV) {
		switch (xlate_point) {
		case XLATE_PRE_DIRECTION_REV:
		case XLATE_POST_DIRECTION_REV:
			return false;
		default:
			break;
		}
	}

	/* At ACTIVE_CT (3) and up, only emit for connect syscalls. */
	if (MONITOR_AGGREGATION >= TRACE_SOCK_AGGREGATE_CONNECT)
		if (!is_connect)
			return false;

	return true;
}

static __always_inline void
send_trace_sock_notify4(struct __ctx_sock *ctx,
			enum xlate_point xlate_point,
			__u32 dst_ip, __u16 dst_port,
			bool is_connect)
{
	struct trace_sock_notify msg __align_stack_8;
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_SOCKET_EVENTS_MAP,
	};
	struct ratelimit_settings settings = {
		.topup_interval_ns = CT_REPORT_INTERVAL * NSEC_PER_SEC,
	};

	if (!emit_trace_sock_notify(xlate_point, is_connect))
		return;

	/* Rate limit socket traces when monitor aggregation is enabled.
	 * Uses CT_REPORT_INTERVAL as the time bucket for aggregation to
	 * align with monitor aggregation timing.
	 */
	if (MONITOR_AGGREGATION != TRACE_SOCK_AGGREGATE_NONE) {
		/* One token per CT_REPORT_INTERVAL with no burst to align with
		 * monitor aggregation semantics ("~1 per interval").
		 */
		settings.bucket_size = 1;
		settings.tokens_per_topup = 1;
		if (!ratelimit_check_and_take(&rkey, &settings))
			return;
	}

	msg = (typeof(msg)){
		.type		= CILIUM_NOTIFY_TRACE_SOCK,
		.xlate_point	= xlate_point,
		.dst_ip.ip4	= dst_ip,
		.dst_port	= dst_port,
		.sock_cookie	= sock_local_cookie(ctx),
		.cgroup_id	= get_current_cgroup_id(),
		.l4_proto	= parse_protocol(ctx->protocol),
		.ipv6		= 0,
	};

	trace_sock_extension_hook(ctx, msg);
	ctx_event_output(ctx, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
}

static __always_inline void
send_trace_sock_notify6(struct __ctx_sock *ctx,
			enum xlate_point xlate_point,
			const union v6addr *dst_addr,
			__u16 dst_port,
			bool is_connect)
{
	struct trace_sock_notify msg __align_stack_8;
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_SOCKET_EVENTS_MAP,
	};
	struct ratelimit_settings settings = {
		.topup_interval_ns = CT_REPORT_INTERVAL * NSEC_PER_SEC,
	};

	if (!emit_trace_sock_notify(xlate_point, is_connect))
		return;

	/* Rate limit socket traces when monitor aggregation is enabled.
	 * Uses CT_REPORT_INTERVAL as the time bucket for aggregation to
	 * align with monitor aggregation timing.
	 */
	if (MONITOR_AGGREGATION != TRACE_SOCK_AGGREGATE_NONE) {
		/* One token per CT_REPORT_INTERVAL with no burst to align with
		 * monitor aggregation semantics ("~1 per interval").
		 */
		settings.bucket_size = 1;
		settings.tokens_per_topup = 1;
		if (!ratelimit_check_and_take(&rkey, &settings))
			return;
	}

	msg = (typeof(msg)){
		.type		= CILIUM_NOTIFY_TRACE_SOCK,
		.xlate_point	= xlate_point,
		.dst_port	= dst_port,
		.sock_cookie	= sock_local_cookie(ctx),
		.cgroup_id	= get_current_cgroup_id(),
		.l4_proto	= parse_protocol(ctx->protocol),
		.ipv6		= 1,
	};
	ipv6_addr_copy_unaligned(&msg.dst_ip.ip6, dst_addr);

	trace_sock_extension_hook(ctx, msg);
	ctx_event_output(ctx, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
}
#else
static __always_inline void
send_trace_sock_notify4(struct __ctx_sock *ctx __maybe_unused,
			enum xlate_point xlate_point __maybe_unused,
			__u32 dst_ip __maybe_unused, __u16 dst_port __maybe_unused,
			bool is_connect __maybe_unused)
{
}

static __always_inline void
send_trace_sock_notify6(struct __ctx_sock *ctx __maybe_unused,
			enum xlate_point xlate_point __maybe_unused,
			const union v6addr *dst_addr __maybe_unused,
			__u16 dst_port __maybe_unused,
			bool is_connect __maybe_unused)
{
}
#endif /* TRACE_SOCK_NOTIFY */
