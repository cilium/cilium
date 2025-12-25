// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include <bpf/config/node.h>

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

	TEST("L3+L4 policy", {
		int ret;

		policy_add_egress_allow_entry(REMOTE_IDENTITY, IPPROTO_UDP,
					      __bpf_htons(80));

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);
		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(81));
		assert(ret == DROP_POLICY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);

		policy_delete_egress_entry(REMOTE_IDENTITY, IPPROTO_UDP,
					   __bpf_htons(80));
	});

	TEST("wildcarded L4", {
		int ret;

		policy_add_egress_allow_entry(REMOTE_IDENTITY, IPPROTO_UDP, 0);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);

		policy_delete_egress_entry(REMOTE_IDENTITY, IPPROTO_UDP, 0);
	});

	TEST("wildcarded L3+L4", {
		int ret;

		policy_add_egress_allow_entry(REMOTE_IDENTITY, 0, 0);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		policy_delete_egress_entry(REMOTE_IDENTITY, 0, 0);
	});

	TEST("L3+L4 policy, any identity", {
		int ret;

		policy_add_egress_allow_entry(0, IPPROTO_UDP,
					      __bpf_htons(80));

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);
		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(81));
		assert(ret == DROP_POLICY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);

		policy_delete_egress_entry(0, IPPROTO_UDP,
					   __bpf_htons(80));
	});

	TEST("wildcarded L4, any-identity", {
		int ret;

		policy_add_egress_allow_entry(0, IPPROTO_UDP, 0);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);

		policy_delete_egress_entry(0, IPPROTO_UDP, 0);
	});

	TEST("wildcarded L3+L4, any identity [allow-all]", {
		int ret;

		policy_add_egress_allow_entry(0, 0, 0);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		policy_delete_egress_entry(0, 0, 0);
	});

	test_finish();
}
