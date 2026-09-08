// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_REMOTE_NODE_MASQUERADE 0
#define ENABLE_HYBRID_ROUTING 0
#include "hybrid_snat_skip_v4.h"

PKTGEN("tc", "hybrid_snat_v4_same_subnet_hybrid_disabled")
int hybrid_snat_v4_same_subnet_hybrid_disabled_pktgen(struct __ctx_buff *ctx)
{
	return hybrid_snat_v4_pktgen(ctx);
}

SETUP("tc", "hybrid_snat_v4_same_subnet_hybrid_disabled")
int hybrid_snat_v4_same_subnet_hybrid_disabled_setup(struct __ctx_buff *ctx)
{
	return hybrid_snat_v4_setup(ctx, 100, 100);
}

CHECK("tc", "hybrid_snat_v4_same_subnet_hybrid_disabled")
int hybrid_snat_v4_same_subnet_hybrid_disabled_check(const struct __ctx_buff *ctx)
{
	return hybrid_snat_v4_check(ctx, true);
}
