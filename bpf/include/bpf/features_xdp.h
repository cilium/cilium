/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef __BPF_FEATURES_XDP__
#define __BPF_FEATURES_XDP__

#include "features.h"

/* Only xdp related features. */

#if HAVE_PROG_TYPE_HELPER(xdp, bpf_fib_lookup)
# define BPF_HAVE_FIB_LOOKUP 1
#endif

#endif /* __BPF_FEATURES_XDP__ */
