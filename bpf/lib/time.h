/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "static_data.h"

#define NSEC_PER_SEC	(1000ULL * 1000ULL * 1000UL)

NODE_CONFIG(bool, enable_jiffies, "Use jiffies (count of timer ticks since boot).");
NODE_CONFIG(__u32, kernel_hz, "Number of timer ticks per second.");

/* Monotonic clock, scalar format. */
static __always_inline __u64 bpf_ktime_get_sec(void)
{
	return ktime_get_ns() / NSEC_PER_SEC;
}

#define BPF_MONO_SCALER 8

static __always_inline __u64 bpf_mono_now(void)
{
	if (CONFIG(enable_jiffies))
		return jiffies64() >> BPF_MONO_SCALER;
	return bpf_ktime_get_sec();
}

static __always_inline __u32 bpf_sec_to_mono(__u32 s)
{
	if (CONFIG(enable_jiffies))
		return (__u32)(s * CONFIG(kernel_hz)) >> BPF_MONO_SCALER;
	return s;
}
