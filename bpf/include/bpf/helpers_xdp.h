/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __BPF_HELPERS_XDP__
#define __BPF_HELPERS_XDP__

#include <linux/bpf.h>

#include "compiler.h"
#include "helpers.h"

/* Events for user space */
static int BPF_FUNC_REMAP(xdp_event_output, struct xdp_md *xdp, void *map,
			  __u64 index, const void *data, __u32 size) =
			 (void *)BPF_FUNC_perf_event_output;

#endif /* __BPF_HELPERS_XDP__ */
