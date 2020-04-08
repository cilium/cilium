// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019-2020 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#include "lib/common.h"
#include "lib/dbg.h"
#include "lib/proxy.h"
#include "lib/trace.h"

/* CB_PROXY_MAGIC overlaps with CB_ENCRYPT_MAGIC */
#define ENCRYPT_OR_PROXY_MAGIC 0

__section("to-host")
int to_host(struct __ctx_buff *ctx)
{
	__u32 magic = ctx_load_meta(ctx, ENCRYPT_OR_PROXY_MAGIC);
	int ret = CTX_ACT_OK;
	__u32 src_label = 0;
	bool traced = false;

	if ((magic & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT) {
		ctx->mark = magic; // CB_ENCRYPT_MAGIC
		src_label = ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY);
		set_identity_mark(ctx, src_label);
	} else if ((magic & 0xFFFF) == MARK_MAGIC_TO_PROXY) {
		/* Upper 16 bits may carry proxy port number */
		__be16 port = magic >> 16;

		ctx_store_meta(ctx, 0, CB_PROXY_MAGIC);
		ctx_redirect_to_proxy_first(ctx, port);
		/* We already traced this in the previous prog with
		 * more background context, skip trace here. */
		traced = true;
	}

	if (!traced)
		send_trace_notify(ctx, TRACE_TO_STACK, src_label, 0, 0,
				  CILIUM_IFINDEX, ret, 0);

	return ret;
}

BPF_LICENSE("GPL");
