// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ETH_HLEN 0
#define IS_BPF_WIREGUARD 1

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <bpf/config/global.h>
#include <bpf/config/node.h>
#include <netdev_config.h>

/* WORLD_IPV{4,6}_ID varies based on dualstack being enabled. Real values are
 * written into node_config.h at runtime. */
#define SECLABEL WORLD_ID
#define SECLABEL_IPV4 WORLD_IPV4_ID
#define SECLABEL_IPV6 WORLD_IPV6_ID

#include "lib/trace.h"
#include "lib/drop.h"
#include "lib/nodeport.h"
#include "lib/nodeport_egress.h"

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

	ret = handle_nat_fwd(ctx, 0, src_sec_identity, proto, true, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  METRIC_EGRESS);

out:
#endif /* ENABLE_NODEPORT */

	send_trace_notify(ctx, TRACE_TO_CRYPTO, src_sec_identity, UNKNOWN_ID,
			  TRACE_EP_ID_UNKNOWN, THIS_INTERFACE_IFINDEX,
			  trace.reason, trace.monitor);

	return TC_ACT_OK;
}

BPF_LICENSE("Dual BSD/GPL");
