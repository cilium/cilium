// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_REMOTE_NODE_MASQUERADE 0
#define ENABLE_HYBRID_ROUTING 1
#include "hybrid_snat_skip_v6.h"

PKTGEN("tc", "hybrid_snat_v6_same_subnet")
int hybrid_snat_v6_same_subnet_pktgen(struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_pktgen(ctx);
}

SETUP("tc", "hybrid_snat_v6_same_subnet")
int hybrid_snat_v6_same_subnet_setup(struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_setup(ctx, 100, 100);
}

CHECK("tc", "hybrid_snat_v6_same_subnet")
int hybrid_snat_v6_same_subnet_check(const struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_check(ctx, false);
}

PKTGEN("tc", "hybrid_snat_v6_different_subnet")
int hybrid_snat_v6_different_subnet_pktgen(struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_pktgen(ctx);
}

SETUP("tc", "hybrid_snat_v6_different_subnet")
int hybrid_snat_v6_different_subnet_setup(struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_setup(ctx, 100, 200);
}

CHECK("tc", "hybrid_snat_v6_different_subnet")
int hybrid_snat_v6_different_subnet_check(const struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_check(ctx, true);
}

PKTGEN("tc", "hybrid_snat_v6_zero_subnet")
int hybrid_snat_v6_zero_subnet_pktgen(struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_pktgen(ctx);
}

SETUP("tc", "hybrid_snat_v6_zero_subnet")
int hybrid_snat_v6_zero_subnet_setup(struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_setup(ctx, 0, 0);
}

CHECK("tc", "hybrid_snat_v6_zero_subnet")
int hybrid_snat_v6_zero_subnet_check(const struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_check(ctx, true);
}

PKTGEN("tc", "hybrid_snat_v6_source_subnet_missing")
int hybrid_snat_v6_source_subnet_missing_pktgen(struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_pktgen(ctx);
}

SETUP("tc", "hybrid_snat_v6_source_subnet_missing")
int hybrid_snat_v6_source_subnet_missing_setup(struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_setup(ctx, 0, 100);
}

CHECK("tc", "hybrid_snat_v6_source_subnet_missing")
int hybrid_snat_v6_source_subnet_missing_check(const struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_check(ctx, true);
}

PKTGEN("tc", "hybrid_snat_v6_destination_subnet_missing")
int hybrid_snat_v6_destination_subnet_missing_pktgen(struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_pktgen(ctx);
}

SETUP("tc", "hybrid_snat_v6_destination_subnet_missing")
int hybrid_snat_v6_destination_subnet_missing_setup(struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_setup(ctx, 100, 0);
}

CHECK("tc", "hybrid_snat_v6_destination_subnet_missing")
int hybrid_snat_v6_destination_subnet_missing_check(const struct __ctx_buff *ctx)
{
	return hybrid_snat_v6_check(ctx, true);
}
