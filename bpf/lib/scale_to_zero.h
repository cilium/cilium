/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <bpf/loader.h>
#include <bpf/config/node.h>

#include "common.h"
#include "signal.h"

/* Rate-limit window per service. As in ratelimit.h, last_emit_ns is updated
 * without cross-CPU sync, so a boundary can let one extra signal through per CPU.
 */
#ifndef SCALE_TO_ZERO_INTERVAL_NS
#define SCALE_TO_ZERO_INTERVAL_NS 30000000000ULL /* 30s */
#endif

/* The agent owns membership (pkg/maps/scaletozero); the datapath only updates
 * last_emit_ns in place, so NO_PREALLOC is safe. map_flags must match the agent
 * side or the loader recreates the pinned map.
 */
struct scale_to_zero_key {
	__u16 svc_id; /* rev_nat_index, network byte order */
	__u16 pad;
};

struct scale_to_zero_value {
	__u64 last_emit_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct scale_to_zero_key);
	__type(value, struct scale_to_zero_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_SCALE_TO_ZERO_MAP_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_scale_to_zero __section_maps_btf;

#ifdef ENABLE_SCALE_TO_ZERO
static __always_inline bool scale_to_zero_should_signal(__u16 svc_id)
{
	struct scale_to_zero_key key = { .svc_id = svc_id };
	struct scale_to_zero_value *value;
	__u64 now;

	value = map_lookup_elem(&cilium_scale_to_zero, &key);
	if (!value)
		return false;

	/* last_emit_ns == 0 (freshly seeded) is never rate-limited, so the first
	 * packet after a scale-down always signals.
	 */
	now = ktime_get_ns();
	if (value->last_emit_ns != 0 &&
	    now - value->last_emit_ns < SCALE_TO_ZERO_INTERVAL_NS)
		return false;

	value->last_emit_ns = now;
	return true;
}

/* Rate-limited demand signal for a tracked service.
 *
 * Socket LB signals on every forward translation, holding demand while
 * pod->ClusterIP traffic flows. lb{4,6}_local signals only at no_service, to
 * stay off the per-packet hot path, so NodePort/LB can scale back down under
 * short-lived north-south traffic once a backend exists.
 *
 * ctx is void *: socket LB and lb_local pass different ctx types.
 */
static __always_inline void scale_to_zero_signal(void *ctx, __u16 svc_id)
{
	if (scale_to_zero_should_signal(svc_id))
		SEND_SIGNAL(ctx, SIGNAL_SCALE_TO_ZERO, svc_id, svc_id);
}
#endif /* ENABLE_SCALE_TO_ZERO */
