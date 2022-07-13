/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_HELPERS_SOCK__
#define __BPF_HELPERS_SOCK__

#include <linux/bpf.h>

#include "helpers.h"

/* Only used helpers in Cilium go below. */

/* Events for user space */
static int BPF_FUNC_REMAP(sock_event_output, struct bpf_sock_addr *sock, void *map,
			  __u64 index, const void *data, __u32 size) =
			 (void *)BPF_FUNC_perf_event_output;

#endif /* __BPF_HELPERS_SOCK__ */

