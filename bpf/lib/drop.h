/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * Drop & error notification via perf event ring buffer
 *
 * API:
 * int send_drop_notify(ctx, src, dst, dst_id, reason, exitcode, enum metric_dir direction)
 * int send_drop_notify_error(ctx, error, exitcode, enum metric_dir direction)
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
	__u16		line;
	__u8		file;
	__u8		unused;
};

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_DROP_NOTIFY)
int __send_drop_notify(struct __ctx_buff *ctx)
{
	/* Mask needed to calm verifier. */
	int error = ctx_load_meta(ctx, 2) & 0xFFFFFFFF;
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, TRACE_PAYLOAD_LEN, ctx_len);
	__u32 meta4 = ctx_load_meta(ctx, 4);
	__u16 line = (__u16)(meta4 >> 16);
	__u8 file = (__u8)(meta4 >> 8);
	__u8 exitcode = (__u8)meta4;
	struct drop_notify msg;

	if (error < 0)
		error = -error;

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_DROP, (__u8)error),
		__notify_pktcap_hdr(ctx_len, (__u16)cap_len),
		.src_label	= ctx_load_meta(ctx, 0),
		.dst_label	= ctx_load_meta(ctx, 1),
		.dst_id		= ctx_load_meta(ctx, 3),
		.line           = line,
		.file           = file,
	};

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));

	return exitcode;
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
static __always_inline int
_send_drop_notify(__u8 file, __u16 line, struct __ctx_buff *ctx,
		  __u32 src, __u32 dst, __u32 dst_id,
		  int reason, __u32 exitcode, enum metric_dir direction)
{
	/* These fields should be constants and fit (together) in 32 bits */
	if (!__builtin_constant_p(exitcode) || exitcode > 0xff ||
	    !__builtin_constant_p(file) || file > 0xff ||
	    !__builtin_constant_p(line) || line > 0xffff)
		__throw_build_bug();

	ctx_store_meta(ctx, 0, src);
	ctx_store_meta(ctx, 1, dst);
	ctx_store_meta(ctx, 2, reason);
	ctx_store_meta(ctx, 3, dst_id);
	ctx_store_meta(ctx, 4, exitcode | file << 8 | line << 16);

	update_metrics(ctx_full_len(ctx), direction, (__u8)-reason);
	ep_tail_call(ctx, CILIUM_CALL_DROP_NOTIFY);

	return exitcode;
}
#else
static __always_inline
int _send_drop_notify(__u8 file __maybe_unused, __u16 line __maybe_unused,
		      struct __ctx_buff *ctx, __u32 src __maybe_unused,
		      __u32 dst __maybe_unused, __u32 dst_id __maybe_unused,
		      int reason, __u32 exitcode, enum metric_dir direction)
{
	update_metrics(ctx_full_len(ctx), direction, (__u8)-reason);
	return exitcode;
}
#endif /* DROP_NOTIFY */

static __always_inline int _send_drop_notify_error(__u8 file, __u16 line,
						   struct __ctx_buff *ctx, __u32 src,
						   int error, __u32 exitcode,
						   enum metric_dir direction)
{
	return _send_drop_notify(file, line, ctx, src, 0, 0, error, exitcode, direction);
}

#ifndef __MAGIC_FILE__
#define __MAGIC_FILE__ 0
#endif

#define send_drop_notify(...) _send_drop_notify(__MAGIC_FILE__, __LINE__, __VA_ARGS__)
#define send_drop_notify_error(...) _send_drop_notify_error(__MAGIC_FILE__, __LINE__, __VA_ARGS__)

#endif /* __LIB_DROP__ */
