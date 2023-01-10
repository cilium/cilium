/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

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

#endif /* __LIB_TIME_H_ */
