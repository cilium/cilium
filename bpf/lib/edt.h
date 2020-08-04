/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef __EDT_H_
#define __EDT_H_

#include "common.h"
#include "time.h"
#include "maps.h"

#if defined(ENABLE_BANDWIDTH_MANAGER)
static __always_inline int edt_sched_departure(struct __ctx_buff *ctx)
{
	__u64 delay, now, t, t_next;
	struct edt_id aggregate;
	struct edt_info *info;
	__u16 proto;

	if (HOST_DEV == 1)
		return CTX_ACT_OK;
	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;
	if (proto != bpf_htons(ETH_P_IP) &&
	    proto != bpf_htons(ETH_P_IPV6))
		return CTX_ACT_OK;

	aggregate.id = get_cgroup_classid(ctx);
	if (!aggregate.id)
		return CTX_ACT_OK;

	info = map_lookup_elem(&THROTTLE_MAP, &aggregate);
	if (!info)
		return CTX_ACT_OK;

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
	if (t_next - now >= info->t_horizon_drop)
		return CTX_ACT_DROP;

	WRITE_ONCE(info->t_last, t_next);
	ctx->tstamp = t_next;
	return CTX_ACT_OK;
}
#endif /* ENABLE_BANDWIDTH_MANAGER */
#endif /* __EDT_H_ */
