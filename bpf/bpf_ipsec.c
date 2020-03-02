// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019-2020 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#include "lib/common.h"
#include "lib/dbg.h"

__section("from-netdev")
int from_netdev(struct __ctx_buff *ctx)
{
	if ((ctx_load_meta(ctx, 0) & MARK_MAGIC_HOST_MASK) ==
	    MARK_MAGIC_ENCRYPT) {
		ctx->mark = ctx_load_meta(ctx, 0);
		set_identity(ctx, ctx_load_meta(ctx, 1));
	} else {
		/* Upper 16 bits may carry proxy port number, clear it out */
		__u32 magic = ctx_load_meta(ctx, 0) & 0xFFFF;

		if (magic == MARK_MAGIC_TO_PROXY) {
			__be16 port = ctx_load_meta(ctx, 0) >> 16;

			ctx->mark = ctx_load_meta(ctx, 0);
			ctx_change_type(ctx, PACKET_HOST);
			cilium_dbg_capture(ctx, DBG_CAPTURE_PROXY_POST, port);
		}
	}

	return CTX_ACT_OK;
}

BPF_LICENSE("GPL");
