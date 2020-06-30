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

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_DROP_NOTIFY)
int __send_drop_notify(struct __ctx_buff *ctx)
{
	/* Mask needed to calm verifier. */
	int error = ctx_load_meta(ctx, 2) & 0xFFFFFFFF;
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, TRACE_PAYLOAD_LEN, ctx_len);
	struct drop_notify msg;

	if (error < 0)
		error = -error;

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_DROP, error),
		__notify_pktcap_hdr(ctx_len, cap_len),
		.src_label	= ctx_load_meta(ctx, 0),
		.dst_label	= ctx_load_meta(ctx, 1),
		.dst_id		= ctx_load_meta(ctx, 3),
	};

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));

	return ctx_load_meta(ctx, 4);
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
	ctx_store_meta(ctx, 0, src);
	ctx_store_meta(ctx, 1, dst);
	ctx_store_meta(ctx, 2, reason);
	ctx_store_meta(ctx, 3, dst_id);
	ctx_store_meta(ctx, 4, exitcode);

	update_metrics(ctx_full_len(ctx), direction, -reason);
	ep_tail_call(ctx, CILIUM_CALL_DROP_NOTIFY);

	return exitcode;
}
#else
static __always_inline
int send_drop_notify(struct __ctx_buff *ctx, __u32 src __maybe_unused,
		     __u32 dst __maybe_unused, __u32 dst_id __maybe_unused,
		     int reason, int exitcode, __u8 direction)
{
	update_metrics(ctx_full_len(ctx), direction, -reason);
	return exitcode;
}
#endif /* DROP_NOTIFY */

static __always_inline int send_drop_notify_error(struct __ctx_buff *ctx, __u32 src,
						  int error, int exitcode,
						  __u8 direction)
{
	return send_drop_notify(ctx, src, 0, 0, error, exitcode, direction);
}

#endif /* __LIB_DROP__ */
