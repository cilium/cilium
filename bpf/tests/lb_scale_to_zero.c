// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include <bpf/config/node.h>

#include <lib/time.h>

#define ENABLE_SCALE_TO_ZERO

/* Mock the monotonic clock to exercise the rate-limit window, as in
 * bpf/tests/ratelimit.c.
 */
static __u64 mock_time;
static __u64 mock_ktime_get_ns(void)
{
	return mock_time;
}

#define ktime_get_ns mock_ktime_get_ns

#include "lib/scale_to_zero.h"

CHECK("tc", "scale_to_zero") int test_scale_to_zero(struct __ctx_buff *ctx)
{
	struct scale_to_zero_key key = { .svc_id = 1 };
	struct scale_to_zero_value seed = { .last_emit_ns = 0 };
	struct scale_to_zero_value *value;
	__u64 first;

	test_init();

	TEST("untracked-service-is-noop", {
		mock_time = 1000 * NSEC_PER_SEC;
		scale_to_zero_signal(ctx, key.svc_id);

		value = map_lookup_elem(&cilium_scale_to_zero, &key);
		if (value)
			test_fatal("untracked service must not create a map entry");
	})

	TEST("first-packet-records-emit-time", {
		if (map_update_elem(&cilium_scale_to_zero, &key, &seed, BPF_ANY))
			test_fatal("failed to seed tracked service");

		mock_time = 1000 * NSEC_PER_SEC;
		scale_to_zero_signal(ctx, key.svc_id);

		value = map_lookup_elem(&cilium_scale_to_zero, &key);
		if (!value)
			test_fatal("tracked entry vanished");
		if (value->last_emit_ns != mock_time)
			test_fatal("first packet did not record the emit time");
	})

	TEST("rate-limited-within-window", {
		value = map_lookup_elem(&cilium_scale_to_zero, &key);
		if (!value)
			test_fatal("tracked entry missing");
		first = value->last_emit_ns;

		mock_time = first + SCALE_TO_ZERO_INTERVAL_NS - 1;
		scale_to_zero_signal(ctx, key.svc_id);

		if (value->last_emit_ns != first)
			test_fatal("emit time advanced inside the rate-limit window");
	})

	TEST("signals-again-after-window", {
		value = map_lookup_elem(&cilium_scale_to_zero, &key);
		if (!value)
			test_fatal("tracked entry missing");
		first = value->last_emit_ns;

		mock_time = first + SCALE_TO_ZERO_INTERVAL_NS + 1;
		scale_to_zero_signal(ctx, key.svc_id);

		if (value->last_emit_ns != mock_time)
			test_fatal("emit time did not advance after the rate-limit window");
	})

	test_finish();
}

/* bpf_perf_event_output requires a GPL-compatible license. */
BPF_LICENSE("Dual BSD/GPL");
