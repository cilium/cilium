/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_TIME_H_
#define __LIB_TIME_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#define NSEC_PER_SEC	(1000ULL * 1000ULL * 1000UL)
#define NSEC_PER_MSEC	(1000ULL * 1000ULL)
#define NSEC_PER_USEC	(1000UL)

/* Monotonic clock, scalar format. */
#define bpf_ktime_get_sec()	\
	({ __u64 __x = ktime_get_ns() / NSEC_PER_SEC; __x; })
#define bpf_ktime_get_msec()	\
	({ __u64 __x = ktime_get_ns() / NSEC_PER_MSEC; __x; })
#define bpf_ktime_get_usec()	\
	({ __u64 __x = ktime_get_ns() / NSEC_PER_USEC; __x; })
#define bpf_ktime_get_nsec()	\
	({ __u64 __x = ktime_get_ns(); __x; })

/* Jiffies */
#define bpf_jiffies_to_sec(j)	\
	({ __u64 __x = (j) / KERNEL_HZ; __x; })
#define bpf_sec_to_jiffies(s)	\
	({ __u64 __x = (s) * KERNEL_HZ; __x; })

/* Per-CPU ktime cache for faster clock access. */
struct bpf_elf_map __section_maps cilium_ktime_cache = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u64),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 1,
};

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

#endif /* __LIB_TIME_H_ */
