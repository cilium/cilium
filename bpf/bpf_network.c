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
	int ret;
#ifdef ENABLE_IPSEC
	__u16 proto;
#endif

	bpf_clear_meta(ctx);

#ifdef ENABLE_IPSEC
	/* Pass unknown protocols to the stack */
	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;

	ret = do_decrypt(ctx, proto);
#else
	/* nop if IPSec is disabled */
	ret = CTX_ACT_OK;
#endif

/* We need to handle following possible packets come to this program
 *
 * 1. ESP packets coming from network (encrypted and not marked)
 * 2. Non-ESP packets coming from network (plain and not marked)
 * 3. Non-ESP packets coming from stack re-inserted by xfrm (plain
 *    and marked with MARK_MAGIC_DECRYPT, IPSec mode only)
 *
 * 1. will be traced with TRACE_REASON_ENCRYPTED, because
 * do_decrypt marks them with MARK_MAGIC_DECRYPT.
 *
 * 2. will be traced without TRACE_REASON_ENCRYPTED, because
 * do_decrypt does't touch to mark.
 *
 * 3. will be traced without TRACE_REASON_ENCRYPTED, because
 * do_decrypt clears the mark.
 *
 * Note that 1. contains the ESP packets someone else generated.
 * In that case, we trace it as "encrypted", but it doesn't mean
 * "encrypted by Cilium".
 *
 * We won't use TRACE_REASON_ENCRYPTED even if the packets are ESP,
 * because it doesn't matter for the non-IPSec mode.
 */
#ifdef ENABLE_IPSEC
	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT)
		send_trace_notify(ctx, TRACE_FROM_NETWORK, get_identity(ctx), 0, 0,
				  ctx->ingress_ifindex, TRACE_REASON_ENCRYPTED,
				  TRACE_PAYLOAD_LEN);
	else
#endif
		send_trace_notify(ctx, TRACE_FROM_NETWORK, 0, 0, 0,
				  ctx->ingress_ifindex, 0, TRACE_PAYLOAD_LEN);

	return ret;
}

BPF_LICENSE("GPL");
