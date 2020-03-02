/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_TIME_H_
#define __LIB_TIME_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#define NSEC_PER_SEC	1000000000UL

/* Monotonic clock, scalar format. */
static __always_inline __u64 bpf_ktime_get_nsec(void)
{
	return ktime_get_ns();
}

static __always_inline __u32 bpf_ktime_get_sec(void)
{
	/* Ignores remainder subtraction as we'd do in
	 * ns_to_timespec(), but good enough here.
	 */
	return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
}

#endif /* __LIB_TIME_H_ */
