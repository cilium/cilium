/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_UTIME_H_
#define __LIB_UTIME_H_

#include "common.h"
#include "maps.h"

/*
 * Number of bits to shift a monotonic 64-bit nanosecond clock for utime unit.
 * Dividing nanoseconds by 2^9 yields roughly half microsecond accuracy without
 * any loss when converting from seconds (as 1e9/2^9 is an integer), but avoids
 * expensive 64-bit divisions.  With this shift the range of an u64 is ~300000
 * years instead of ~600 years if left at nanoseconds.
 */
#define UTIME_SHIFT 9

static __always_inline __u64
_utime_get_offset()
{
	__u32 index = RUNTIME_CONFIG_UTIME_OFFSET;
	__u64 *offset;

	offset = map_lookup_elem(&CONFIG_MAP, &index);
	if (likely(offset))
		return *offset;

	return 0;
}

/**
 * Return the current time in "utime" unit (512 ns per unit) that is directly
 * comparable to expirations times in bpf maps.
 */
static __always_inline __u64
utime_get_time()
{
	return (ktime_get_ns() >> UTIME_SHIFT) + _utime_get_offset();
}
#endif
