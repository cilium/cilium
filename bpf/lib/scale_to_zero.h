/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "map_defs.h"
#include "signal.h"
#include "static_data.h"
#include "time.h"

DECLARE_CONFIG(bool, enable_scale_to_zero,
	       "Hold new connections to services that are scaled to zero")

/* Services that opted into scale-to-zero, keyed by rev_nat_index (the service
 * ID). Membership is owned by the agent, the datapath only reads it and stamps
 * the value with the time of the last wake signal it emitted.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 4096);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} cilium_scale_to_zero __section_maps_btf;

#define SCALE_TO_ZERO_WAKE_INTERVAL	(30 * NSEC_PER_SEC)

/* Returns true if the service opted into scale-to-zero, in which case
 * last_wake points at its rate limiter state.
 */
static __always_inline bool
scale_to_zero_tracked(__u16 rev_nat_index, __u64 **last_wake)
{
	__u64 *value;

	if (!CONFIG(enable_scale_to_zero))
		return false;

	value = map_lookup_elem(&cilium_scale_to_zero, &rev_nat_index);
	if (!value)
		return false;

	*last_wake = value;
	return true;
}

/* Returns true when the caller may emit a wake signal for the service that
 * last_wake belongs to, and stamps the rate limiter.
 *
 * The stamp is deliberately racy: two CPUs can both find the window expired
 * and emit a duplicate wake, which the agent handles idempotently. A lost
 * signal is equally survivable, the client's retransmit re-signals once the
 * window expires.
 */
static __always_inline bool
scale_to_zero_take_wake_token(__u64 *last_wake)
{
	__u64 now = ktime_get_ns();

	if (*last_wake && now - *last_wake < SCALE_TO_ZERO_WAKE_INTERVAL)
		return false;

	*last_wake = now;
	return true;
}

/* Asks the agent to scale the service up, at most once per
 * SCALE_TO_ZERO_WAKE_INTERVAL. Returns true when the service is tracked,
 * whether or not a signal was emitted this time, so that callers can use it
 * as their "hold this packet" predicate.
 *
 * bpf_sock.c has its own emitter: ctx_event_output() only becomes the socket
 * flavour further down that translation unit.
 */
static __always_inline bool
scale_to_zero_wake(const struct __ctx_buff *ctx, __u16 rev_nat_index)
{
	__u64 *last_wake = NULL;

	if (!scale_to_zero_tracked(rev_nat_index, &last_wake))
		return false;

	if (scale_to_zero_take_wake_token(last_wake))
		send_signal_scale_from_zero(ctx, rev_nat_index);

	return true;
}
