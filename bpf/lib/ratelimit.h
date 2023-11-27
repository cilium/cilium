/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __RATELIMIT_H_
#define __RATELIMIT_H_

#include "common.h"
#include "bpf/helpers.h"

struct ratelimit_key {
	__u32 netdev_idx;
};

struct ratelimit_value {
	__u64 last_topup;
	__u64 tokens;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ratelimit_key);
	__type(value, struct ratelimit_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1024);
} RATELIMIT_MAP __section_maps_btf;

struct ratelimit_settings {
	/* A bucket will never have more than X amount of tokens, limits burt size */
	__u64 bucket_size;
	/* The amount of tokens added to a bucket for every topup */
	__u64 tokens_per_topup;
	/* The interval at which the topups happen */
	__u64 topup_interval_ns;
};

static inline bool ratelimit_check_and_take(struct ratelimit_key *key,
					    const struct ratelimit_settings *settings)
{
	struct ratelimit_value *value;
	struct ratelimit_value new_value;
	__u64 since_last_topup;
	__u64 now;
	__u64 interval;
	__u64 remainder;
	int ret;

	now = ktime_get_ns();

	/* Create a new bucket if we do not yet have one for the key */
	value = map_lookup_elem(&RATELIMIT_MAP, key);
	if (!value) {
		new_value.last_topup = now;
		new_value.tokens = settings->tokens_per_topup - 1;
		ret = map_update_elem(&RATELIMIT_MAP, key, &new_value, BPF_ANY);
		if (ret < 0)
			return false;
		return true;
	}

	/* Note, the updates below are racy, this causes a bit of inaccuracy but isn't fatal,
	 * a more accurare implementation would use atomic operations to update the bucket
	 * but this would be bad for performance.
	 */

	/* Topup the bucket if it has been at least more than 1 interval since we have done so */
	since_last_topup = now - value->last_topup;
	if (since_last_topup > settings->topup_interval_ns) {
		interval = since_last_topup / settings->topup_interval_ns;
		remainder = since_last_topup % settings->topup_interval_ns;
		/* Add tokens of every missed interval */
		value->tokens += interval * settings->tokens_per_topup;
		value->last_topup = now - remainder;
		/* Make sure to not overflow the bucket */
		if (value->tokens > settings->bucket_size)
			value->tokens = settings->bucket_size;
	}

	/* Take a token if there is at least one */
	if (value->tokens > 0) {
		value->tokens--;
		return true;
	}

	return false;
}

#endif
