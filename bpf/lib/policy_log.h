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
#pragma once

#include "common.h"
#include "ratelimit.h"

#if defined(IS_BPF_LXC)
DECLARE_CONFIG(__u32, policy_verdict_log_filter, "The log level for policy verdicts in workload endpoints")
#define POLICY_VERDICT_LOG_FILTER CONFIG(policy_verdict_log_filter)
#endif

#ifndef POLICY_VERDICT_EXTENSION
#define POLICY_VERDICT_EXTENSION
#define policy_verdict_extension_hook(ctx, msg) do {} while (0)
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
		l3:1;
	__u8	auth_type;
	__u8	pad1[3]; /* align with 64 bits */
	__u32	cookie;
	__u32	pad2; /* align with 64 bits */
	POLICY_VERDICT_EXTENSION
};

#ifdef POLICY_VERDICT_NOTIFY
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
			   __u8 match_type, __u8 is_audited, __u8 auth_type, __u32 cookie)
{
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, TRACE_PAYLOAD_LEN, ctx_len);
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_EVENTS_MAP,
	};
	struct ratelimit_settings settings = {
		.topup_interval_ns = NSEC_PER_SEC,
	};
	struct policy_verdict_notify msg;

#if defined(IS_BPF_HOST)
	/* When this function is called in the context of bpf_host (e.g. by
	 * host firewall) POLICY_VERDICT_LOG_FILTER is always set to 0,
	 * preventing any policy verdict notification, as the logic to set it
	 * is only wired up to endpoints.
	 *
	 * Insead of tweaking POLICY_VERDICT_LOG_FILTER and reloading bpf_host
	 * based on whether host firewall policies are present or not, just
	 * always enable policy verdicts notifications, and filter out the ones
	 * for default allow policies, to prevent a flood of notifications for
	 * traffic allowed by default.
	 */
	if (match_type == POLICY_MATCH_ALL && verdict == CTX_ACT_OK)
		return;
#elif defined(IS_BPF_LXC)
	if (!policy_verdict_filter_allow(POLICY_VERDICT_LOG_FILTER, dir))
		return;
#else
	#error "policy_log.h only supports inclusion from bpf_host or bpf_lxc"
#endif

	if (verdict == 0)
		verdict = (int)proxy_port;

	if (EVENTS_MAP_RATE_LIMIT > 0) {
		settings.bucket_size = EVENTS_MAP_BURST_LIMIT;
		settings.tokens_per_topup = EVENTS_MAP_RATE_LIMIT;
		if (!ratelimit_check_and_take(&rkey, &settings))
			return;
	}

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_POLICY_VERDICT, 0),
		__notify_pktcap_hdr((__u32)ctx_len, (__u16)cap_len, NOTIFY_CAPTURE_VER),
		.remote_label	= remote_label,
		.verdict	= verdict,
		.dst_port	= bpf_ntohs(dst_port),
		.match_type	= match_type,
		.proto		= proto,
		.dir		= dir,
		.ipv6		= is_ipv6,
		.audited	= is_audited,
		.auth_type      = auth_type,
		.cookie		= cookie,
		.l3		= THIS_IS_L3_DEV,
	};

	policy_verdict_extension_hook(ctx, msg);
	ctx_event_output(ctx, &cilium_events,
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
			   __u8 auth_type __maybe_unused, __u32 cookie __maybe_unused)
{
}
#endif /* POLICY_VERDICT_NOTIFY */
