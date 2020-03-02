/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

/*
 * Drop & error notification via perf event ring buffer
 *
 * API:
 * int send_drop_notify(ctx, src, dst, dst_id, reason, exitcode, __u8 direction)
 * int send_drop_notify_error(ctx, error, exitcode, __u8 direction)
 *
 * If DROP_NOTIFY is not defined, the API will be compiled in as a NOP.
 */

#ifndef __LIB_DROP__
#define __LIB_DROP__

#include "dbg.h"
#include "events.h"
#include "common.h"
#include "utils.h"
#include "metrics.h"

#ifdef DROP_NOTIFY

struct drop_notify {
	NOTIFY_CAPTURE_HDR
	__u32		src_label;
	__u32		dst_label;
	__u32		dst_id;
	__u32		unused;
};

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_DROP_NOTIFY) int __send_drop_notify(struct __ctx_buff *ctx)
{
	__u64 ctx_len = (__u64)ctx->len, cap_len = min((__u64)TRACE_PAYLOAD_LEN, (__u64)ctx_len);
	__u32 hash = get_hash_recalc(ctx);
	struct drop_notify msg = {
		.type = CILIUM_NOTIFY_DROP,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = ctx_len,
		.len_cap = cap_len,
		.version = NOTIFY_CAPTURE_VER,
		.src_label = ctx->cb[0],
		.dst_label = ctx->cb[1],
		.dst_id = ctx->cb[3],
		.unused = 0,
	};
	// mask needed to calm verifier
	int error = ctx->cb[2] & 0xFFFFFFFF;

	if (error < 0)
		error = -error;

	msg.subtype = error;

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));

	return ctx->cb[4];
}

/**
 * send_drop_notify
 * @ctx:	socket buffer
 * @src:	source identity
 * @dst:	destination identity
 * @dst_id:	designated destination endpoint ID
 * @reason:	Reason for drop
 * @exitcode:	error code to return to the kernel
 *
 * Generate a notification to indicate a packet was dropped.
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
static __always_inline int send_drop_notify(struct __ctx_buff *ctx, __u32 src,
					    __u32 dst, __u32 dst_id, int reason,
					    int exitcode, __u8 direction)
{
	ctx->cb[0] = src;
	ctx->cb[1] = dst;
	ctx->cb[2] = reason;
	ctx->cb[3] = dst_id;
	ctx->cb[4] = exitcode;

	update_metrics(ctx->len, direction, -reason);

	ep_tail_call(ctx, CILIUM_CALL_DROP_NOTIFY);

	return exitcode;
}
#else
static __always_inline int send_drop_notify(struct __ctx_buff *ctx, __u32 src,
					    __u32 dst, __u32 dst_id, int reason,
					    int exitcode, __u8 direction)
{
	update_metrics(ctx->len, direction, -reason);
	return exitcode;
}
#endif

static __always_inline int send_drop_notify_error(struct __ctx_buff *ctx, __u32 src,
						  int error, int exitcode,
						  __u8 direction)
{
	return send_drop_notify(ctx, src, 0, 0, error, exitcode, direction);
}

#endif /* __LIB_DROP__ */
