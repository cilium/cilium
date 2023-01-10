// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#include "lib/common.h"
#include "lib/trace.h"
#include "lib/encrypt.h"

__section("from-network")
int cil_from_network(struct __ctx_buff *ctx)
{
	int ret = CTX_ACT_OK;

	__u16 proto __maybe_unused;
	enum trace_reason reason = TRACE_REASON_UNKNOWN;
	enum trace_point obs_point_to = TRACE_TO_STACK;
	enum trace_point obs_point_from = TRACE_FROM_NETWORK;

	bpf_clear_meta(ctx);

	/* This program should be attached to the tc-ingress of
	 * the network-facing device. Thus, as far as Cilium
	 * knows, no one touches to the ctx->mark before this
	 * program.
	 *
	 * One exception is the case the packets are re-insearted
	 * from the stack by xfrm. In that case, the packets should
	 * be marked with MARK_MAGIC_DECRYPT.
	 */
	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT)
		obs_point_from = TRACE_FROM_STACK;

#ifdef ENABLE_IPSEC
	/* Pass unknown protocols to the stack */
	if (!validate_ethertype(ctx, &proto))
		goto out;

	ret = do_decrypt(ctx, proto);
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
		reason = TRACE_REASON_ENCRYPTED;

	/* Only possible redirect in here is the one in the do_decrypt
	 * which redirects to cilium_host.
	 */
	if (ret == CTX_ACT_REDIRECT)
		obs_point_to = TRACE_TO_HOST;
#endif

out:
	send_trace_notify(ctx, obs_point_from, 0, 0, 0,
			  ctx->ingress_ifindex, reason, TRACE_PAYLOAD_LEN);

	send_trace_notify(ctx, obs_point_to, 0, 0, 0,
			  ctx->ingress_ifindex, reason, TRACE_PAYLOAD_LEN);

	return ret;
}

BPF_LICENSE("Dual BSD/GPL");
