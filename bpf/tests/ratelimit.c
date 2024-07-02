// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "bpf/ctx/xdp.h"
#include "node_config.h"
#include "common.h"
#include "lib/maps.h"

static __u64 mock_ktime_get_ns(void)
{
	return 3000 * NSEC_PER_SEC;
}

#define ktime_get_ns mock_ktime_get_ns

#include "lib/ratelimit.h"

CHECK("xdp", "ratelimit") int test_ratelimit(void)
{
	struct ratelimit_settings settings = {
		.bucket_size = 1000,
		.tokens_per_topup = 100,
		.topup_interval_ns = NSEC_PER_SEC,
	};
	struct ratelimit_key key = {
		.usage = RATELIMIT_USAGE_ICMPV6,
		.key = {
			.icmpv6 = {
				.netdev_idx = 1,
			},
		},
	};
	struct ratelimit_value *value;

	test_init();

	TEST("bucket-created-when-missing", {
		value = map_lookup_elem(&RATELIMIT_MAP, &key);
		if (value)
			test_fatal("Bucket already exits");

		ratelimit_check_and_take(&key, &settings);

		value = map_lookup_elem(&RATELIMIT_MAP, &key);
		if (!value)
			test_fatal("Bucket not created");
	})

	TEST("block-on-bucket-empty", {
		value = map_lookup_elem(&RATELIMIT_MAP, &key);
		if (!value)
			test_fatal("Bucket not created");

		value->tokens = 1;
		if (!ratelimit_check_and_take(&key, &settings))
			test_fatal("Rate limit not allowed when bucket not empty");

		if (value->tokens != 0)
			test_fatal("Bucket not empty");

		if (ratelimit_check_and_take(&key, &settings))
			test_fatal("Rate limit allowed when bucket empty");
	})

	TEST("topup-after-interval", {
		value = map_lookup_elem(&RATELIMIT_MAP, &key);
		if (!value)
			test_fatal("Bucket not created");

		/* Set last topup to 1 interval ago */
		value->tokens = 0;
		value->last_topup = ktime_get_ns() - (settings.topup_interval_ns + 1);

		if (!ratelimit_check_and_take(&key, &settings))
			test_fatal("Rate limit not allowed after topup");

		if (value->tokens != settings.tokens_per_topup - 1)
			test_fatal("Unexpected token amount after topup");
	})

	TEST("do-not-go-over-bucket-size", {
		value = map_lookup_elem(&RATELIMIT_MAP, &key);
		if (!value)
			test_fatal("Bucket not created");

		/* Set last topup to 100 intervals ago */
		value->tokens = 0;
		value->last_topup = ktime_get_ns() - (100 * settings.topup_interval_ns);

		if (!ratelimit_check_and_take(&key, &settings))
			test_fatal("Rate limit not allowed after topup");

		if (value->tokens != settings.bucket_size - 1)
			test_fatal("Unexpected token amount after topup");
	})

	test_finish();
}
