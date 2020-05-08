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

#ifdef BPF_HAVE_JIFFIES
# define BPF_MONO_SCALER	8
# define bpf_mono_now()		(jiffies >> BPF_MONO_SCALER)
# define bpf_sec_to_mono(s)	(bpf_sec_to_jiffies(s) >> BPF_MONO_SCALER)
#else
# define bpf_mono_now()		bpf_ktime_get_sec()
# define bpf_sec_to_mono(s)	(s)
#endif /* BPF_HAVE_JIFFIES */

#endif /* __LIB_TIME_H_ */
