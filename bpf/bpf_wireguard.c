// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ETH_HLEN 0
#define IS_BPF_WIREGUARD 1

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#include "lib/trace.h"
#include "lib/drop.h"
#include "lib/nodeport.h"

/* to-wireguard is attached as a tc egress filter to the cilium_wg0 device.
 */
__section_entry
int cil_to_wireguard(struct __ctx_buff *ctx)
{
	int __maybe_unused ret;
	__s8 __maybe_unused ext_err = 0;
	__u16 __maybe_unused proto = ctx_get_protocol(ctx);
	__u32 __maybe_unused src_sec_identity = UNKNOWN_ID;
	__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;

	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	if (magic == MARK_MAGIC_IDENTITY)
		src_sec_identity = get_identity(ctx);

	bpf_clear_meta(ctx);

#ifdef ENABLE_NODEPORT
	if (magic == MARK_MAGIC_OVERLAY)
		goto out;

	ret = handle_nat_fwd(ctx, 0, proto, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);

out:
#endif /* ENABLE_NODEPORT */

	return TC_ACT_OK;
}

BPF_LICENSE("Dual BSD/GPL");
