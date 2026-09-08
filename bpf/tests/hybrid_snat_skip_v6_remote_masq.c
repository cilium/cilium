// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_REMOTE_NODE_MASQUERADE 1
#define ENABLE_HYBRID_ROUTING 1
#include "hybrid_snat_skip_v6.h"

PKTGEN("tc", "hybrid_snat_v6_same_subnet_remote_masq")
int hybrid_snat_v6_same_subnet_remote_masq_pktgen(struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_pktgen(ctx);
}

SETUP("tc", "hybrid_snat_v6_same_subnet_remote_masq")
int hybrid_snat_v6_same_subnet_remote_masq_setup(struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_setup(ctx, 100, 100);
}

CHECK("tc", "hybrid_snat_v6_same_subnet_remote_masq")
int hybrid_snat_v6_same_subnet_remote_masq_check(const struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_check(ctx, true);
}
