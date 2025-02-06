/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>

#include "common.h"
#include "time.h"

/* From XDP layer, we neither go through an egress hook nor qdisc
 * from here, hence nothing to be set.
 */
#if defined(ENABLE_BANDWIDTH_MANAGER) && __ctx_is == __ctx_skb
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct edt_id);
	__type(value, struct edt_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, THROTTLE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_throttle __section_maps_btf;

static __always_inline void edt_set_aggregate(struct __ctx_buff *ctx,
					      __u32 aggregate)
{
	/* 16 bit as current used aggregate, and preserved in host ns. */
	ctx->queue_mapping = aggregate;
}

static __always_inline __u32 edt_get_aggregate(struct __ctx_buff *ctx)
{
	__u32 aggregate = ctx->queue_mapping;

	/* We need to reset queue mapping here such that new mapping will
	 * be performed based on skb hash. See netdev_pick_tx().
	 */
	ctx->queue_mapping = 0;

	return aggregate;
}

static __always_inline int
edt_sched_departure(struct __ctx_buff *ctx, __be16 proto)
{
	__u64 delay, now, t, t_next;
	struct edt_id aggregate = {};
	struct edt_info *info;

	if (!eth_is_supported_ethertype(proto))
		return CTX_ACT_OK;
	if (proto != bpf_htons(ETH_P_IP) &&
	    proto != bpf_htons(ETH_P_IPV6))
		return CTX_ACT_OK;

	aggregate.id = edt_get_aggregate(ctx);
	if (!aggregate.id)
		return CTX_ACT_OK;

	aggregate.direction = DIRECTION_EGRESS;

	info = map_lookup_elem(&cilium_throttle, &aggregate);
	if (!info)
		return CTX_ACT_OK;
	if (!info->bps)
		goto out;

	now = ktime_get_ns();
	t = ctx->tstamp;
	if (t < now)
		t = now;
	delay = ((__u64)ctx_wire_len(ctx)) * NSEC_PER_SEC / info->bps;
	t_next = READ_ONCE(info->t_last) + delay;
	if (t_next <= t) {
		WRITE_ONCE(info->t_last, t);
		return CTX_ACT_OK;
	}
	/* FQ implements a drop horizon, see also 39d010504e6b ("net_sched:
	 * sch_fq: add horizon attribute"). However, we explicitly need the
	 * drop horizon here to i) avoid having t_last messed up and ii) to
	 * potentially allow for per aggregate control.
	 */
	if (t_next - now >= info->t_horizon_drop)
		return DROP_EDT_HORIZON;
	WRITE_ONCE(info->t_last, t_next);
	ctx->tstamp = t_next;
out:
	/* TODO: Hack to avoid defaulting prio 0 when user doesn't specify anything.
	 * Priority set by user will always be 1 greater than what scheduler expects.
	 */
	if (info->prio)
		ctx->priority = info->prio - 1;
	return CTX_ACT_OK;
}
#else
static __always_inline void
edt_set_aggregate(struct __ctx_buff *ctx __maybe_unused,
		  __u32 aggregate __maybe_unused)
{
}
#endif /* ENABLE_BANDWIDTH_MANAGER */
