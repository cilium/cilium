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
#ifndef __LIB_TRACE_SOCK__
#define __LIB_TRACE_SOCK__

#include <bpf/ctx/sock.h>

#include "common.h"
#include "events.h"

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

#ifdef TRACE_SOCK_NOTIFY
struct trace_sock_notify {
	__u8 type;
	__u8 xlate_point;
	struct ip dst_ip;
	__u16 dst_port;
	__u64 sock_cookie;
	__u64 cgroup_id;
	__u8 l4_proto;
	__u8 ipv6 : 1;
	__u8 pad : 7;
} __packed;

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

static __always_inline void
send_trace_sock_notify4(struct __ctx_sock *ctx,
			enum xlate_point xlate_point,
			__u32 dst_ip, __u16 dst_port)
{
	__u64 cgroup_id = 0;
	struct trace_sock_notify msg __align_stack_8;

	if (is_defined(HAVE_CGROUP_ID))
		cgroup_id = get_current_cgroup_id();

	msg = (typeof(msg)){
		.type		= CILIUM_NOTIFY_TRACE_SOCK,
		.xlate_point	= xlate_point,
		.dst_ip.ip4	= dst_ip,
		.dst_port	= dst_port,
		.sock_cookie	= sock_local_cookie(ctx),
		.cgroup_id	= cgroup_id,
		.l4_proto	= parse_protocol(ctx->protocol),
		.ipv6		= 0,
	};

	ctx_event_output(ctx, &EVENTS_MAP, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
}

static __always_inline void
send_trace_sock_notify6(struct __ctx_sock *ctx,
			enum xlate_point xlate_point,
			union v6addr *dst_addr,
			__u16 dst_port)
{
	__u64 cgroup_id = 0;
	struct trace_sock_notify msg __align_stack_8;

	if (is_defined(HAVE_CGROUP_ID))
		cgroup_id = get_current_cgroup_id();
	msg = (typeof(msg)){
		.type		= CILIUM_NOTIFY_TRACE_SOCK,
		.xlate_point	= xlate_point,
		.dst_port	= dst_port,
		.sock_cookie	= sock_local_cookie(ctx),
		.cgroup_id	= cgroup_id,
		.l4_proto	= parse_protocol(ctx->protocol),
		.ipv6		= 1,
	};
	ipv6_addr_copy(&msg.dst_ip.ip6, dst_addr);

	ctx_event_output(ctx, &EVENTS_MAP, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
}
#else
static __always_inline void
send_trace_sock_notify4(struct __ctx_sock *ctx __maybe_unused,
			enum xlate_point xlate_point __maybe_unused,
			__u32 dst_ip __maybe_unused, __u16 dst_port __maybe_unused)
{
}

static __always_inline void
send_trace_sock_notify6(struct __ctx_sock *ctx __maybe_unused,
			enum xlate_point xlate_point __maybe_unused,
			union v6addr *dst_addr __maybe_unused,
			__u16 dst_port __maybe_unused)
{
}
#endif /* TRACE_SOCK_NOTIFY */
#endif /* __LIB_TRACE_SOCK__ */
