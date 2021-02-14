/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019-2021 Authors of Cilium */

#ifndef __EGRESS_GW_H_
#define __EGRESS_GW_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "eps.h"
#include "tailcall.h"
#include "nat.h"
#include "edt.h"
#include "lb.h"
#include "common.h"
#include "overloadable.h"
#include "conntrack.h"
#include "csum.h"
#include "encap.h"
#include "trace.h"

#ifdef ENABLE_EGRESS_GATEWAY

static __always_inline int handle_egress_nat_ipv4(struct __ctx_buff *ctx)
{
	struct egress_info *info;
	struct iphdr *ip4;
	void *data, *data_end;
	bool from_endpoint = true;
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	info = lookup_ip4_egress_endpoint(ip4->saddr, ip4->daddr);
	if (!info)
		return CTX_ACT_OK;

	target.addr = info->egress_ip;

	return snat_v4_process(ctx, NAT_DIR_EGRESS, &target, from_endpoint);
}

static __always_inline int egress_nat_fwd(struct __ctx_buff *ctx)
{
	int ret = CTX_ACT_OK;
		__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
	ret = handle_egress_nat_ipv4(ctx);
		break;
#endif /* ENABLE_IPV4 */
	default:
		break;
	}
	return ret;
}

#endif /* ENABLE_EGRESS_GATEWAY */
#endif /* __EGRESS_GW_H_ */
