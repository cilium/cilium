// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include <node_config.h>
#include <lib/static_data.h>

#include "lib/socket.h"

static __always_inline int probe_fib_lookup_with_flag(struct __ctx_buff *ctx, int flag)
{
	struct bpf_fib_lookup fib_params = {
		.family		= AF_INET,
		.ifindex	= ctx_get_ifindex(ctx),
		.ipv4_src	= 0,
		.ipv4_dst	= 0,
	};

	/* Returns -EINVAL if flags are invalid. */
	return fib_lookup(ctx, &fib_params, sizeof(fib_params), flag) == -EINVAL;
}

__section_entry
int probe_fib_lookup_skip_neigh(struct __ctx_buff *ctx)
{
	return probe_fib_lookup_with_flag(ctx, BPF_FIB_LOOKUP_SKIP_NEIGH);
}

__section_entry
int probe_fib_lookup_tbid(struct __ctx_buff *ctx)
{
	return probe_fib_lookup_with_flag(ctx, BPF_FIB_LOOKUP_TBID);
}

__section_entry
int probe_fib_lookup_src(struct __ctx_buff *ctx)
{
	return probe_fib_lookup_with_flag(ctx, BPF_FIB_LOOKUP_SRC);
}

BPF_LICENSE("Dual BSD/GPL");
