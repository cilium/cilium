// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include <node_config.h>

#include <lib/policy.h>

#include "lib/policy.h"

#define REMOTE_IDENTITY		112233

static __always_inline int
check_egress_policy(struct __ctx_buff *ctx, __u32 dst_id, __u8 proto, __be16 dport)
{
	__u8 match_type;
	__u8 audited;
	__s8 ext_err;
	__u16 proxy_port;
	__u32 cookie;

	return policy_can_egress(ctx, 0 /* ignored */, dst_id,
				 0 /* ICMP only */,
				 dport, proto, 0 /* ICMP only */,
				 &match_type, &audited, &ext_err, &proxy_port,
				 &cookie);
}

CHECK("tc", "network_policy_egress_allow")
int network_policy_egress_allow_check(struct __ctx_buff *ctx)
{
	test_init();

	TEST("deny by default", {
		int ret;

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);
	});

	/* Allow access to UDP port 80, at REMOTE_IDENTITY. */
	TEST("L3+L4 policy", {
		int ret;

		policy_add_egress_allow_l3_l4_entry(REMOTE_IDENTITY, IPPROTO_UDP,
						    __bpf_htons(80), 0);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);
		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(81));
		assert(ret == DROP_POLICY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);

		policy_delete_egress_l3_l4_entry(REMOTE_IDENTITY, IPPROTO_UDP,
						 __bpf_htons(80), 0);
	});

	/* Allow access to UDP ports 80-83, at REMOTE_IDENTITY. */
	TEST("L3 + partially wildcarded L4 policy", {
		int ret;

		policy_add_egress_allow_l3_l4_entry(REMOTE_IDENTITY, IPPROTO_UDP,
						    __bpf_htons(80), 2);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(79));
		assert(ret == DROP_POLICY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(81));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(82));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(83));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(84));
		assert(ret == DROP_POLICY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);

		policy_delete_egress_l3_l4_entry(REMOTE_IDENTITY, IPPROTO_UDP,
						 __bpf_htons(80), 2);
	});

	/* Allow access to all UDP ports, at REMOTE_IDENTITY. */
	TEST("L3 + wildcarded L4 policy", {
		int ret;

		policy_add_egress_allow_l3_l4_entry(REMOTE_IDENTITY, IPPROTO_UDP, 0, 0);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);

		policy_delete_egress_l3_l4_entry(REMOTE_IDENTITY, IPPROTO_UDP, 0, 0);
	});

	/* Allow full L3 access, at REMOTE_IDENTITY. */
	TEST("L3 policy", {
		int ret;

		policy_add_egress_allow_l3_entry(REMOTE_IDENTITY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		policy_delete_egress_l3_entry(REMOTE_IDENTITY);
	});

	/* Allow access to UDP port 80, at all dst endpoints. */
	TEST("L4-only policy", {
		int ret;

		policy_add_egress_allow_l4_entry(IPPROTO_UDP, __bpf_htons(80), 0);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);
		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(81));
		assert(ret == DROP_POLICY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);

		policy_delete_egress_l4_entry(IPPROTO_UDP, __bpf_htons(80), 0);
	});

	/* Allow access to UDP ports 80-83, at all dst endpoints. */
	TEST("partially wildcarded L4-only policy", {
		int ret;

		policy_add_egress_allow_l3_l4_entry(0, IPPROTO_UDP,
						    __bpf_htons(80), 2);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(79));
		assert(ret == DROP_POLICY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(81));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(82));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(83));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(84));
		assert(ret == DROP_POLICY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);

		policy_delete_egress_l3_l4_entry(0, IPPROTO_UDP,
						 __bpf_htons(80), 2);
	});

	/* Allow access to all UDP ports, at all dst endpoints. */
	TEST("wildcarded L4-only policy", {
		int ret;

		policy_add_egress_allow_l4_entry(IPPROTO_UDP, 0, 0);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);

		policy_delete_egress_l4_entry(IPPROTO_UDP, 0, 0);
	});

	/* Allow full L3 access, at all dst endpoints. */
	TEST("allow-all", {
		int ret;

		policy_add_egress_allow_all_entry();

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		policy_delete_egress_all_entry();
	});

	test_finish();
}
