/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <lib/static_data.h>
#include <lib/time.h>

/* Moved out from time.h to avoid circular header dependency. */
#define BPF_MONO_SCALER 8

static __always_inline __u64 bpf_mono_now()
{
#ifdef ENABLE_JIFFIES
	if (CONFIG(kernel_hz) != 1)
		return jiffies >> BPF_MONO_SCALER;
#else
	return bpf_ktime_get_sec();
#endif
}

static __always_inline __u32 bpf_sec_to_mono(__u32 s)
{
#ifdef ENABLE_JIFFIES
	if (CONFIG(kernel_hz) != 1)
		return (__u32)bpf_sec_to_jiffies(s) >> BPF_MONO_SCALER;
#else
	return s;
#endif
}
