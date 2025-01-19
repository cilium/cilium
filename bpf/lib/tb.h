/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include <linux/bpf.h>

#include "common.h"
#include "time.h"
#include "maps.h"

/* For now the map is not thread safe, may add spin lock in the future */

#if defined(ENABLE_BANDWIDTH_MANAGER) && __ctx_is == __ctx_skb
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct throttle_id);
	__type(value, struct throttle_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, INGRESS_THROTTLE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} INGRESS_THROTTLE_MAP __section_maps_btf;

static __always_inline int accept(struct __ctx_buff *ctx, __u32 ep_id)
{
	__u64 tokens, now, t_last, elapsed_time, bps;
	struct throttle_id aggregate;
	struct throttle_info *info;
	__u32 ret = CTX_ACT_OK;

	aggregate.id = ep_id;
	if (!aggregate.id)
		return CTX_ACT_OK;

	info = map_lookup_elem(&INGRESS_THROTTLE_MAP, &aggregate);
	if (!info)
		return CTX_ACT_OK;

	now = ktime_get_ns();

	bps = READ_ONCE(info->bps);
	t_last = READ_ONCE(info->t_last);
	tokens = READ_ONCE(info->tokens);
	elapsed_time = now - t_last;
	if (elapsed_time > 0) {
		tokens += (bps * elapsed_time / NSEC_PER_SEC);
		if (tokens > bps)
			tokens = bps;
	}
	if (tokens >= ctx_wire_len(ctx))
		tokens -= ctx_wire_len(ctx);
	else
		ret = CTX_ACT_DROP;
	WRITE_ONCE(info->t_last, now);
	WRITE_ONCE(info->tokens, tokens);
	return ret;
}
#else
static __always_inline int
accept(struct __ctx_buff *ctx __maybe_unused, __u32 ep_id __maybe_unused)
{
	return CTX_ACT_OK;
}
#endif /* ENABLE_BANDWIDTH_MANAGER */
