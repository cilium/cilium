/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_TIME_CACHE_H_
#define __LIB_TIME_CACHE_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "time.h"

/* Per-CPU ktime cache for faster clock access. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} cilium_ktime_cache __section_maps_btf;

/* Currently supported clock types:
 *
 * - bpf_ktime_cache_set(ns)      -> CLOCK_MONOTONIC
 * - bpf_ktime_cache_set(boot_ns) -> CLOCK_BOOTTIME
 */
#define bpf_ktime_cache_set(clock)					     \
	({								     \
		__u32 __z = 0;						     \
		__u64 *__cache = map_lookup_elem(&cilium_ktime_cache, &__z); \
		__u64 __ktime = ktime_get_##clock();			     \
		if (always_succeeds(__cache))				     \
			*__cache = __ktime;				     \
		__ktime;						     \
	})

#define bpf_ktime_cache_get()						     \
	({								     \
		__u32 __z = 0;						     \
		__u64 *__cache = map_lookup_elem(&cilium_ktime_cache, &__z); \
		__u64 __ktime = 0;					     \
		if (always_succeeds(__cache))				     \
			__ktime = *__cache;				     \
		__ktime;						     \
	})

#endif /* __LIB_TIME_CACHE_H_ */
