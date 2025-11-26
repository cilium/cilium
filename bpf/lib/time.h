/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>
#include <lib/static_data.h>

DECLARE_CONFIG(__u32, kernel_hz, "The number of times jiffies is incremented in one second.")
ASSIGN_CONFIG(__u32, kernel_hz, 250)

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
static __always_inline __u64 bpf_jiffies_to_sec(__u64 j)
{
	__u64 __x = j / CONFIG(kernel_hz);
	return __x;
}

static __always_inline __u64 bpf_sec_to_jiffies(__u64 s)
{
	__u64 __x = s * CONFIG(kernel_hz);
	return __x;
}
