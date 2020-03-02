// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019-2020 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#include "lib/common.h"

__section("to-host")
int to_host(struct __ctx_buff *ctx)
{
	/* Upper 16 bits may carry proxy port number, clear it out */
	__u32 magic = ctx_load_meta(ctx, 0) & 0xFFFF;

	if (magic == MARK_MAGIC_TO_PROXY) {
		ctx->mark = ctx_load_meta(ctx, 0);
		ctx_store_meta(ctx, 0, 0);
	}

	return CTX_ACT_OK;
}

BPF_LICENSE("GPL");
