// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_REMOTE_NODE_MASQUERADE 1
#include "hybrid_snat_skip_v4.h"

CHECK("tc", "hybrid_snat_v4_same_subnet_remote_masq")
int test_hybrid_snat_v4_same_subnet_remote_masq(struct __ctx_buff *ctx)
{
	test_init();
	assert(run_hybrid_snat_v4_test(ctx, 100, 100) == NAT_NEEDED);
	test_finish();
}
