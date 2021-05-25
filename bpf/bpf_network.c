// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019-2020 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#include "lib/common.h"
#include "lib/trace.h"
#include "lib/encrypt.h"

__section("from-network")
int from_network(struct __ctx_buff *ctx)
{
#ifdef ENABLE_IPSEC
	__u16 proto;

	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT) {
		send_trace_notify(ctx, TRACE_FROM_NETWORK, get_identity(ctx), 0, 0,
				  ctx->ingress_ifindex,
				  TRACE_REASON_ENCRYPTED, TRACE_PAYLOAD_LEN);
	} else
#endif
	{
		send_trace_notify(ctx, TRACE_FROM_NETWORK, 0, 0, 0,
				  ctx->ingress_ifindex, 0, TRACE_PAYLOAD_LEN);
	}

	bpf_clear_meta(ctx);

#ifdef ENABLE_IPSEC
	/* Pass unknown protocols to the stack */
	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;

	return do_decrypt(ctx, proto);
#else
	/* nop if IPSec is disabled */
	return CTX_ACT_OK;
#endif
}

BPF_LICENSE("GPL");
