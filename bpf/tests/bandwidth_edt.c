// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>

static __u64 __now;

#define ktime_get_ns()	(__now)

#include "common.h"

#define ENABLE_BANDWIDTH_MANAGER 1

#include <bpf/config/node.h>
#include "lib/common.h"
#include "lib/edt.h"

#define AGGREGATE_ID	42
#define BPS		(1000000000ULL / 8)
#define HORIZON		(2 * NSEC_PER_SEC)

static void throttle_reset(__u64 t_last)
{
	struct edt_id key = {
		.id = AGGREGATE_ID,
		.direction = DIRECTION_EGRESS,
	};
	struct edt_info info = {
		.bps = BPS,
		.t_last = t_last,
		.t_horizon_drop = HORIZON,
	};

	map_update_elem(&cilium_throttle, &key, &info, BPF_ANY);
}

static __u64 throttle_t_last(void)
{
	struct edt_id key = {
		.id = AGGREGATE_ID,
		.direction = DIRECTION_EGRESS,
	};
	struct edt_info *info = map_lookup_elem(&cilium_throttle, &key);

	return info ? info->t_last : 0;
}

static int departure(struct __ctx_buff *ctx, __u64 tstamp)
{
	ctx->tstamp = tstamp;
	edt_set_aggregate(ctx, AGGREGATE_ID);
	return edt_sched_departure(ctx, bpf_htons(ETH_P_IP));
}

CHECK("tc", "edt_sched_departure")
int test_edt_sched_departure(struct __ctx_buff *ctx)
{
	__u64 delay;
	int ret;

	test_init();

	__now = 1000 * NSEC_PER_SEC;
	delay = (__u64)ctx_wire_len(ctx) * NSEC_PER_SEC / BPS;

	TEST("unstamped packet is paced at the aggregate rate", {
		throttle_reset(__now);

		ret = departure(ctx, 0);
		assert(ret == CTX_ACT_OK);
		assert(ctx->tstamp == __now + delay);
		assert(throttle_t_last() == __now + delay);
	});

	TEST("stamp within the horizon advances t_last", {
		throttle_reset(__now);

		ret = departure(ctx, __now + NSEC_PER_SEC);
		assert(ret == CTX_ACT_OK);
		assert(throttle_t_last() == __now + NSEC_PER_SEC);
	});

	/* TCP stamps skb->tstamp len/pacing_rate ahead. After an RTT sample
	 * spanning a peer stall, the pacing rate collapses and the stamp lands
	 * tens of seconds in the future.
	 */
	TEST("stamp beyond the horizon does not move t_last", {
		throttle_reset(__now);

		departure(ctx, __now + 40 * NSEC_PER_SEC);
		assert(throttle_t_last() < __now + HORIZON);
	});

	TEST("stamp beyond the horizon does not starve other flows", {
		throttle_reset(__now);

		departure(ctx, __now + 40 * NSEC_PER_SEC);

		/* Another socket of the same pod, far below the rate limit. */
		__now += 100000000ULL;
		ret = departure(ctx, 0);
		assert(ret == CTX_ACT_OK);
		assert(ctx->tstamp < __now + HORIZON);
	});

	TEST("over-rate packet past the horizon is dropped", {
		throttle_reset(__now + HORIZON - 1);

		ret = departure(ctx, 0);
		assert(ret == DROP_EDT_HORIZON);
		assert(throttle_t_last() == __now + HORIZON - 1);
	});

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
