/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __QM_H_
#define __QM_H_

#include <bpf/ctx/ctx.h>

static inline void reset_queue_mapping(struct __ctx_buff *ctx __maybe_unused)
{
#if defined(RESET_QUEUES) && __ctx_is == __ctx_skb
	/* Workaround for GH-18311 where veth driver might have recorded
	 * veth's RX queue mapping instead of leaving it at 0. This can
	 * cause issues on the phys device where all traffic would only
	 * hit a single TX queue (given veth device had a single one and
	 * mapping was left at 1). Reset so that stack picks a fresh queue.
	 * Kernel fix is at 710ad98c363a ("veth: Do not record rx queue
	 * hint in veth_xmit").
	 */
	ctx->queue_mapping = 0;
#endif
}

#endif /* __QM_H_ */
