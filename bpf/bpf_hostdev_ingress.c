// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019-2020 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#include "lib/common.h"
#include "lib/dbg.h"

__section("to-host")
int to_host(struct __ctx_buff *ctx)
{
	__u32 magic = ctx_load_meta(ctx, 0);

	if ((magic & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT) {
		ctx->mark = magic;
		set_identity_mark(ctx, ctx_load_meta(ctx, 1));
	} else if ((magic & 0xFFFF) == MARK_MAGIC_TO_PROXY) {
		/* Upper 16 bits may carry proxy port number */
		__be16 port = magic >> 16;

		ctx->mark = magic;
		ctx_store_meta(ctx, 0, 0);
		ctx_change_type(ctx, PACKET_HOST);
		cilium_dbg_capture(ctx, DBG_CAPTURE_PROXY_POST, port);
	}

	return CTX_ACT_OK;
}

BPF_LICENSE("GPL");
