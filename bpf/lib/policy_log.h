/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * Policy verdict notification via perf event ring buffer.
 *
 * API:
 * void send_policy_verdict_notify(ctx, remote_label, dst_port, proto, dir,
 *                                 is_ipv6, verdict, match_type)
 *
 * If POLICY_VERDICT_NOTIFY is not defined, the API will be a non-op.
 */
#ifndef __LIB_POLICY_LOG__
#define __LIB_POLICY_LOG__

#include "common.h"

#ifdef POLICY_VERDICT_NOTIFY

#ifndef POLICY_VERDICT_LOG_FILTER
DEFINE_U32(POLICY_VERDICT_LOG_FILTER, 0xffff);
#define POLICY_VERDICT_LOG_FILTER fetch_u32(POLICY_VERDICT_LOG_FILTER)
#endif

struct policy_verdict_notify {
	NOTIFY_CAPTURE_HDR
	__u32	remote_label;
	__s32	verdict;
	__u16	dst_port;
	__u8	proto;
	__u8	dir:2,
		ipv6:1,
		match_type:3,
		audited:1,
		pad0:1;
	__u8	auth_type;
	__u8	pad1; /* align with 64 bits */
	__u16	pad2; /* align with 64 bits */
};

static __always_inline bool policy_verdict_filter_allow(__u32 filter, __u8 dir)
{
	/* Make dir being volatile to avoid compiler optimizing out
	 * filter (thinking it to be zero).
	 */
	volatile __u8 d = dir;

	return ((filter & d) > 0);
}

static __always_inline void
send_policy_verdict_notify(struct __ctx_buff *ctx, __u32 remote_label, __u16 dst_port,
			   __u8 proto, __u8 dir, __u8 is_ipv6, int verdict, __u16 proxy_port,
			   __u8 match_type, __u8 is_audited, __u8 auth_type)
{
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, TRACE_PAYLOAD_LEN, ctx_len);
	struct policy_verdict_notify msg;

	if (!policy_verdict_filter_allow(POLICY_VERDICT_LOG_FILTER, dir))
		return;

	if (verdict == 0)
		verdict = (int)proxy_port;

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_POLICY_VERDICT, 0),
		__notify_pktcap_hdr(ctx_len, (__u16)cap_len),
		.remote_label	= remote_label,
		.verdict	= verdict,
		.dst_port	= bpf_ntohs(dst_port),
		.match_type	= match_type,
		.proto		= proto,
		.dir		= dir,
		.ipv6		= is_ipv6,
		.audited	= is_audited,
		.auth_type      = auth_type,
	};

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}
#else
static __always_inline void
send_policy_verdict_notify(struct __ctx_buff *ctx __maybe_unused,
			   __u32 remote_label __maybe_unused, __u16 dst_port __maybe_unused,
			   __u8 proto __maybe_unused, __u8 dir __maybe_unused,
			   __u8 is_ipv6 __maybe_unused, int verdict __maybe_unused,
			   __u16 proxy_port __maybe_unused,
			   __u8 match_type __maybe_unused, __u8 is_audited __maybe_unused,
			   __u8 auth_type __maybe_unused)
{
}
#endif /* POLICY_VERDICT_NOTIFY */
#endif /* __LIB_POLICY_LOG__*/
