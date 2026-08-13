// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_REMOTE_NODE_MASQUERADE 0
#include "hybrid_snat_skip_v4.h"

CHECK("tc", "hybrid_snat_v4_same_subnet")
int test_hybrid_snat_v4_same_subnet(struct __ctx_buff *ctx)
{
	test_init();
	assert(run_hybrid_snat_v4_test(ctx, 100, 100) == NAT_PUNT_TO_STACK);
	test_finish();
}

/* These cases continue past the hybrid routing decision. With an empty test
 * context, the later NAT path returns DROP_NAT_NOT_NEEDED, proving that the
 * subnet check did not punt them to the stack.
 */
CHECK("tc", "hybrid_snat_v4_different_subnet")
int test_hybrid_snat_v4_different_subnet(struct __ctx_buff *ctx)
{
	test_init();
	assert(run_hybrid_snat_v4_test(ctx, 100, 200) == DROP_NAT_NOT_NEEDED);
	test_finish();
}

CHECK("tc", "hybrid_snat_v4_zero_subnet")
int test_hybrid_snat_v4_zero_subnet(struct __ctx_buff *ctx)
{
	test_init();
	assert(run_hybrid_snat_v4_test(ctx, 0, 0) == DROP_NAT_NOT_NEEDED);
	test_finish();
}
