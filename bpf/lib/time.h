/*
 *  Copyright (C) 2016-2020 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
