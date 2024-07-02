// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ETH_HLEN 0
#define IS_BPF_WIREGUARD 1

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>
#include "lib/mcast.h"

#include "lib/tailcall.h"
#include "lib/common.h"
#include "lib/edt.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/trace.h"
#include "lib/l3.h"
#include "lib/drop.h"
#include "lib/identity.h"
#include "lib/nodeport.h"
#include "lib/clustermesh.h"
#include "lib/egress_gateway.h"

/* to-wireguard is attached as a tc egress filter to the cilium_wg0 device.
 */
__section_entry
int cil_to_wireguard(struct __ctx_buff *ctx)
{
	__u16 proto;
	__s8 ext_err = 0;

	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	if (validate_ethertype(ctx, &proto))
		return handle_nat_fwd(ctx, 0, proto, &trace, &ext_err);

	return TC_ACT_OK;
}

BPF_LICENSE("Dual BSD/GPL");
