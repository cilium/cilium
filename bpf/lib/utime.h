/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "config_map.h"

/*
 * Number of bits to shift a monotonic 64-bit nanosecond clock for utime unit.
 * Dividing nanoseconds by 2^9 yields roughly half microsecond accuracy without
 * any loss when converting from seconds (as 1e9/2^9 is an integer), but avoids
 * expensive 64-bit divisions.  With this shift the range of an u64 is ~300000
 * years instead of ~600 years if left at nanoseconds.
 */
#define UTIME_SHIFT 9

/**
 * Return the current time in "utime" unit (512 ns per unit) that is directly
 * comparable to expirations times in bpf maps.
 */
static __always_inline __u64
utime_get_time()
{
	return (ktime_get_ns() >> UTIME_SHIFT) + config_get(RUNTIME_CONFIG_UTIME_OFFSET);
}
