/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef __BPF_FEATURES_SKB__
#define __BPF_FEATURES_SKB__

#include "features.h"

/* Only skb related features. */

#if HAVE_PROG_TYPE_HELPER(sched_cls, bpf_skb_change_tail)
# define BPF_HAVE_CHANGE_TAIL 1
#endif

#if HAVE_PROG_TYPE_HELPER(sched_cls, bpf_fib_lookup)
# define BPF_HAVE_FIB_LOOKUP 1
#endif

#endif /* __BPF_FEATURES_SKB__ */
