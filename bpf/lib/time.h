/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#define NSEC_PER_SEC	(1000ULL * 1000ULL * 1000UL)

/* Monotonic clock, scalar format. */
#define bpf_ktime_get_sec()	\
	({ __u64 __x = ktime_get_ns() / NSEC_PER_SEC; __x; })

/* Jiffies */
#define bpf_sec_to_jiffies(s)	\
	({ __u64 __x = (s) * KERNEL_HZ; __x; })
