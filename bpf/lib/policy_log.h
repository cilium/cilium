/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

/*
 * Policy verdict notification via perf event ring buffer.
 *
 * API:
 * void send_policy_verdict_notify(ctx, remote_label, dst_port, proto, dir, is_ipv6, verdict, match_type)
 *
 * If POLICY_VERDICT_NOTIFY is not defined, the API will be a non-op.
 */
#ifndef __LIB_POLICY_LOG__
#define __LIB_POLICY_LOG__

#include "common.h"

#ifdef POLICY_VERDICT_NOTIFY
struct policy_verdict_notify {
	NOTIFY_CAPTURE_HDR
	__u32	remote_label;
	__s32	verdict;
	__u16	dst_port;
	__u8	proto;
	__u8	dir:2,
		ipv6:1,
		match_type:3,
		pad0:2;
	__u32	pad1; // align with 64 bits
};

static __always_inline void
send_policy_verdict_notify(struct __ctx_buff *ctx, __u32 remote_label, __u16 dst_port,
			   __u8 proto, __u8 dir, __u8 is_ipv6, int verdict,
			   __u8 match_type)
{
	__u64 ctx_len = (__u64)ctx_full_len(ctx);
	__u64 cap_len = min((__u64)TRACE_PAYLOAD_LEN, (__u64)ctx_len);
	__u32 hash = get_hash_recalc(ctx);
	struct policy_verdict_notify msg = {
		.type = CILIUM_NOTIFY_POLICY_VERDICT,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = ctx_len,
		.len_cap = cap_len,
		.version = NOTIFY_CAPTURE_VER,
		.remote_label = remote_label,
		.verdict = verdict,
		.dst_port = bpf_ntohs(dst_port),
		.proto = proto,
		.dir = dir,
		.ipv6 = is_ipv6,
		.match_type = match_type,
		.pad0 = 0,
		.pad1 = 0,
	};

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}
#else
static __always_inline void
send_policy_verdict_notify(struct __ctx_buff *ctx, __u32 remote_label, __u16 dst_port,
			   __u8 proto, __u8 dir, __u8 is_ipv6, int verdict,
			   __u8 match_type)
{
}
#endif /* POLICY_VERDICT_NOTIFY */
#endif /* __LIB_POLICY_LOG__*/
