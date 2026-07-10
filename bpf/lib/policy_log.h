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

DEFINE_AUX(struct policy_verdict_notify, policy_verdict_notify);

static __always_inline bool policy_verdict_filter_allow(__u32 filter, __u8 dir)
{
	/* Make dir being volatile to avoid compiler optimizing out
	 * filter (thinking it to be zero).
	 */
	volatile __u8 d = dir;

	return ((filter & d) > 0);
}

#ifdef POLICY_VERDICT_NOTIFY
static __always_inline
struct policy_verdict_notify *get_policy_verdict_notify(struct __ctx_buff *ctx)
{
	struct policy_verdict_notify *msg = AUX(policy_verdict_notify);
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, TRACE_PAYLOAD_LEN, ctx_len);

	memset(msg, 0, sizeof(*msg));
	*msg = (typeof(*msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_POLICY_VERDICT, 0),
		__notify_pktcap_hdr((__u32)ctx_len, (__u16)cap_len, NOTIFY_CAPTURE_VER),
	};

	return msg;
}

static __always_inline void
send_policy_verdict_notify(const struct __ctx_buff *ctx,
			   struct policy_verdict_notify *verdict_notify)
{
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_EVENTS_MAP,
	};
	struct ratelimit_settings settings = {
		.topup_interval_ns = NSEC_PER_SEC,
	};

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
	if (verdict_notify->match_type == POLICY_MATCH_ALL && verdict_notify->verdict == CTX_ACT_OK)
		return;
#elif defined(IS_BPF_LXC)
	if (!policy_verdict_filter_allow(POLICY_VERDICT_LOG_FILTER, verdict_notify->dir))
		return;
#else
	#error "policy_log.h only supports inclusion from bpf_host or bpf_lxc"
#endif

	if (CONFIG(events_map_rate_limit) > 0) {
		settings.bucket_size = CONFIG(events_map_burst_limit);
		settings.tokens_per_topup = CONFIG(events_map_rate_limit);
		if (!ratelimit_check_and_take(&rkey, &settings))
			return;
	}

	policy_verdict_extension_hook(ctx, verdict_notify);
	ctx_event_output(ctx, &cilium_events,
			 (((__u64)verdict_notify->len_cap) << 32) | BPF_F_CURRENT_CPU,
			 verdict_notify, sizeof(*verdict_notify));
}
#else
static __always_inline
struct policy_verdict_notify *get_policy_verdict_notify(struct __ctx_buff *ctx __maybe_unused)
{
	return AUX(policy_verdict_notify);
}

static __always_inline void
send_policy_verdict_notify(const struct __ctx_buff *ctx __maybe_unused,
			   struct policy_verdict_notify *verdict_notify __maybe_unused)
{
}
#endif /* POLICY_VERDICT_NOTIFY */
