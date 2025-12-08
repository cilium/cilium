// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include <node_config.h>

#define ENABLE_BPF_ARENA 1
#define EFFECTIVE_EP_ID 1
#undef IS_BPF_HOST
#undef HOST_ID

#include <lib/policy.h>
#include "lib/policy.h"

#define REMOTE_IDENTITY		112233
#define REMOTE_IDENTITY_2	445566
#define REMOTE_NODE_ID		6	/* Reserved identity for remote-node */
#define WORLD_IDENTITY		2	/* Reserved identity for world (external) */
#define HOST_IDENTITY		1	/* Reserved identity for host */
#define HEALTH_IDENTITY		4	/* Reserved identity for health */
#define CIDR_IDENTITY_1		0x01000001	/* Local/CIDR identity scope */
#define CIDR_IDENTITY_2		0x01000002
#define FQDN_IDENTITY_1		0x01000100

/* Unique handles for each test */
#define HANDLE_L3_L4        101
#define HANDLE_L4_ONLY      102
#define HANDLE_PRECEDENCE   103
#define HANDLE_L4_DENY      104
#define HANDLE_L3_ONLY      105
#define HANDLE_PROTO_ONLY   106
#define HANDLE_WILDCARD     107
#define HANDLE_RANGE        108
#define HANDLE_DENY_PREC    109
#define HANDLE_L4_MIX       110
#define HANDLE_AUTH         111
#define HANDLE_PROXY        112
#define HANDLE_MULTI        113
#define HANDLE_INGRESS      114
#define HANDLE_DENY_ALL     115
#define HANDLE_CIDR         116
#define HANDLE_CIDR_L4      117
#define HANDLE_FQDN         118
#define HANDLE_WORLD        119
#define HANDLE_HOST         120
#define HANDLE_HEALTH       121
#define HANDLE_REMOTE_NODE  122
#define HANDLE_MIXED        123

char ____license[] __section("license") = "Dual BSD/GPL";

static __always_inline int
check_egress_policy(struct __ctx_buff *ctx, __u32 dst_id, __u8 proto, __be16 dport)
{
	__u8 match_type;
	__u8 audited;
	__s8 ext_err;
	__u16 proxy_port;
	__u32 cookie;

	return policy_can_egress(ctx, 0 /* src_id ignored for arena */, dst_id,
				 0 /* ethertype */,
				 dport, proto, 0 /* l4_off */,
				 &match_type, &audited, &ext_err, &proxy_port,
				 &cookie);
}

CHECK("tc", "shared_policy_lookup")
int shared_policy_lookup_check(struct __ctx_buff *ctx)
{
	test_init();

	TEST("L3+L4 rule: specific identity + specific port", {
		int ret;

		policy_add_shared_entry(HANDLE_L3_L4, REMOTE_IDENTITY,
					1 /* egress */, IPPROTO_UDP,
					__bpf_htons(80), false /* allow */);
		policy_update_overlay(1, HANDLE_L3_L4);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(81));
		assert(ret == DROP_POLICY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY_2, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);
	});

	test_finish();
}

CHECK("tc", "l4_only_rule_test")
int l4_only_rule_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("L4-only rule: identity=0 matches any identity", {
		int ret;

		policy_add_shared_entry(HANDLE_L4_ONLY, 0 /* wildcard */,
					1 /* egress */, IPPROTO_UDP,
					__bpf_htons(8080), false /* allow */);
		policy_update_overlay(1, HANDLE_L4_ONLY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(8080));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY_2, IPPROTO_UDP,
					  __bpf_htons(8080));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(8081));
		assert(ret == DROP_POLICY);
	});

	test_finish();
}

CHECK("tc", "l3_l4_precedence_test")
int l3_l4_precedence_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Precedence: L3+L4 match should win over L4-only match", {
		int ret;

		policy_add_shared_entry(HANDLE_PRECEDENCE, 0 /* wildcard */,
					1 /* egress */, IPPROTO_TCP,
					__bpf_htons(9090), false /* allow */);

		struct shared_lpm_key key __attribute__((aligned(8)));
		memset(&key, 0, sizeof(key));
		key.lpm_key.prefixlen = SHARED_POLICY_FULL_PREFIX;
		key.rule_set_id = HANDLE_PRECEDENCE;
		key.sec_label = REMOTE_IDENTITY;
		key.egress = 1;
		key.protocol = IPPROTO_TCP;
		key.dport = __bpf_htons(9090);

		struct shared_lpm_value value __attribute__((aligned(8)));
		memset(&value, 0, sizeof(value));
		value.flags = (__u8)(1 | (LPM_FULL_PREFIX_BITS << 3)); // deny=1, full prefix

		map_update_elem(&cilium_policy_s, &key, &value, BPF_ANY);

		policy_update_overlay(1, HANDLE_PRECEDENCE);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(9090));
		assert(ret == DROP_POLICY_DENY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY_2, IPPROTO_TCP,
					  __bpf_htons(9090));
		assert(ret == CTX_ACT_OK);
	});

	test_finish();
}

CHECK("tc", "l4_only_deny_test")
int l4_only_deny_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("L4-only Deny: identity=0 deny blocks everyone", {
		int ret;

		policy_add_shared_entry(HANDLE_L4_DENY, 0 /* wildcard */,
					1 /* egress */, IPPROTO_UDP,
					__bpf_htons(666), true /* deny */);
		policy_update_overlay(1, HANDLE_L4_DENY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(666));
		assert(ret == DROP_POLICY_DENY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY_2, IPPROTO_UDP,
					  __bpf_htons(666));
		assert(ret == DROP_POLICY_DENY);
	});

	test_finish();
}

CHECK("tc", "l3_only_rule_test")
int l3_only_rule_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("L3-only rule: identity match, any port", {
		int ret;

		policy_add_shared_entry(HANDLE_L3_ONLY, REMOTE_IDENTITY,
					1 /* egress */, 0 /* any proto */,
					0 /* any port */, false /* allow */);
		policy_update_overlay(1, HANDLE_L3_ONLY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(53));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY_2, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY);
	});

	test_finish();
}

CHECK("tc", "protocol_only_rule_test")
int protocol_only_rule_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Protocol-only rule: any identity, specific protocol, any port", {
		int ret;

		policy_add_shared_entry(HANDLE_PROTO_ONLY, 0 /* wildcard */,
					1 /* egress */, IPPROTO_TCP,
					0 /* any port */, false /* allow */);
		policy_update_overlay(1, HANDLE_PROTO_ONLY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY_2, IPPROTO_TCP,
					  __bpf_htons(443));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(53));
		assert(ret == DROP_POLICY);
	});

	test_finish();
}

CHECK("tc", "wildcard_allow_all_test")
int wildcard_allow_all_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Wildcard allow-all: identity=0, proto=0, port=0", {
		int ret;

		policy_add_shared_entry(HANDLE_WILDCARD, 0 /* wildcard */,
					1 /* egress */, 0 /* any proto */,
					0 /* any port */, false /* allow */);
		policy_update_overlay(1, HANDLE_WILDCARD);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY_2, IPPROTO_UDP,
					  __bpf_htons(53));
		assert(ret == CTX_ACT_OK);
	});

	test_finish();
}

CHECK("tc", "port_range_test")
int port_range_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Port range: ports 8000-8015 via LPM prefix", {
		int ret;

		policy_add_shared_entry_full(HANDLE_RANGE, REMOTE_IDENTITY,
					     1 /* egress */, IPPROTO_TCP,
					     __bpf_htons(8000), 0xFFF0,
					     false /* allow */, 0, 0);
		policy_update_overlay(1, HANDLE_RANGE);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(8000));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(8015));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(8016));
		assert(ret == DROP_POLICY);
	});

	test_finish();
}

CHECK("tc", "deny_precedence_test")
int deny_precedence_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("L3 deny takes precedence over L4-only allow", {
		int ret;

		policy_add_shared_entry(HANDLE_DENY_PREC, 0 /* wildcard */,
					1 /* egress */, IPPROTO_TCP,
					__bpf_htons(80), false /* allow */);
		policy_add_shared_entry(HANDLE_DENY_PREC, REMOTE_IDENTITY,
					1 /* egress */, 0 /* any proto */,
					0 /* any port */, true /* deny */);
		policy_update_overlay(1, HANDLE_DENY_PREC);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == DROP_POLICY_DENY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY_2, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);
	});

	test_finish();
}

CHECK("tc", "l4_deny_over_l4_allow_test")
int l4_deny_over_l4_allow_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("L4-only deny and allow on different ports", {
		int ret;

		policy_add_shared_entry(HANDLE_L4_MIX, 0 /* wildcard */,
					1 /* egress */, IPPROTO_TCP,
					__bpf_htons(80), false /* allow */);
		policy_add_shared_entry(HANDLE_L4_MIX, 0 /* wildcard */,
					1 /* egress */, IPPROTO_TCP,
					__bpf_htons(443), true /* deny */);
		policy_update_overlay(1, HANDLE_L4_MIX);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(443));
		assert(ret == DROP_POLICY_DENY);
	});

	test_finish();
}

CHECK("tc", "auth_required_test")
int auth_required_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Auth-required policy", {
		int ret;

		policy_add_shared_entry_full(HANDLE_AUTH, REMOTE_IDENTITY,
					     1 /* egress */, IPPROTO_TCP,
					     __bpf_htons(443), 0xFFFF,
					     false /* allow */,
					     0x81, 0);
		policy_update_overlay(1, HANDLE_AUTH);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(443));
		assert(ret == DROP_POLICY_AUTH_REQUIRED);
	});

	test_finish();
}

CHECK("tc", "proxy_redirect_test")
int proxy_redirect_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Proxy redirect policy", {
		int ret;

		policy_add_shared_entry_full(HANDLE_PROXY, REMOTE_IDENTITY,
					     1 /* egress */, IPPROTO_TCP,
					     __bpf_htons(80), 0xFFFF,
					     false /* allow */,
					     0, __bpf_htons(15001));
		policy_update_overlay(1, HANDLE_PROXY);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == 15001);
	});

	test_finish();
}

CHECK("tc", "multiple_identities_test")
int multiple_identities_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Multiple L3+L4 rules", {
		int ret;

		policy_add_shared_entry(HANDLE_MULTI, REMOTE_IDENTITY,
					1 /* egress */, IPPROTO_TCP,
					__bpf_htons(80), false /* allow */);
		policy_add_shared_entry(HANDLE_MULTI, REMOTE_IDENTITY_2,
					1 /* egress */, IPPROTO_TCP,
					__bpf_htons(443), false /* allow */);
		policy_update_overlay(1, HANDLE_MULTI);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY_2, IPPROTO_TCP,
					  __bpf_htons(443));
		assert(ret == CTX_ACT_OK);
	});

	test_finish();
}

CHECK("tc", "wildcard_deny_all_test")
int wildcard_deny_all_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Wildcard deny-all", {
		int ret;

		policy_add_shared_entry(HANDLE_DENY_ALL, 0, 1, 0, 0, true);
		policy_update_overlay(1, HANDLE_DENY_ALL);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP, __bpf_htons(80));
		assert(ret == DROP_POLICY_DENY);
	});

	test_finish();
}

CHECK("tc", "cidr_policy_test")
int cidr_policy_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("CIDR-based policy", {
		int ret;

		policy_add_shared_entry(HANDLE_CIDR, CIDR_IDENTITY_1, 1, IPPROTO_TCP, __bpf_htons(443), false);
		policy_update_overlay(1, HANDLE_CIDR);

		ret = check_egress_policy(ctx, CIDR_IDENTITY_1, IPPROTO_TCP, __bpf_htons(443));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, CIDR_IDENTITY_2, IPPROTO_TCP, __bpf_htons(443));
		assert(ret == DROP_POLICY);
	});

	test_finish();
}

CHECK("tc", "cidr_l4_only_test")
int cidr_l4_only_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("CIDR combined with L4-only", {
		int ret;

		policy_add_shared_entry(HANDLE_CIDR_L4, 0, 1, IPPROTO_TCP, __bpf_htons(8443), false);
		policy_update_overlay(1, HANDLE_CIDR_L4);

		ret = check_egress_policy(ctx, CIDR_IDENTITY_1, IPPROTO_TCP, __bpf_htons(8443));
		assert(ret == CTX_ACT_OK);
	});

	test_finish();
}

CHECK("tc", "fqdn_policy_test")
int fqdn_policy_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("FQDN-based policy", {
		int ret;

		policy_add_shared_entry(HANDLE_FQDN, FQDN_IDENTITY_1, 1, IPPROTO_TCP, __bpf_htons(443), false);
		policy_update_overlay(1, HANDLE_FQDN);

		ret = check_egress_policy(ctx, FQDN_IDENTITY_1, IPPROTO_TCP, __bpf_htons(443));
		assert(ret == CTX_ACT_OK);
	});

	test_finish();
}

CHECK("tc", "world_identity_test")
int world_identity_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("World identity", {
		int ret;

		policy_add_shared_entry(HANDLE_WORLD, WORLD_IDENTITY, 1, IPPROTO_TCP, __bpf_htons(443), false);
		policy_update_overlay(1, HANDLE_WORLD);

		ret = check_egress_policy(ctx, WORLD_IDENTITY, IPPROTO_TCP, __bpf_htons(443));
		assert(ret == CTX_ACT_OK);
	});

	test_finish();
}

CHECK("tc", "host_identity_test")
int host_identity_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Host identity", {
		int ret;

		policy_add_shared_entry(HANDLE_HOST, HOST_IDENTITY, 1, 0, 0, false);
		policy_update_overlay(1, HANDLE_HOST);

		ret = check_egress_policy(ctx, HOST_IDENTITY, IPPROTO_TCP, __bpf_htons(10250));
		assert(ret == CTX_ACT_OK);
	});

	test_finish();
}

CHECK("tc", "health_identity_test")
int health_identity_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Health identity", {
		int ret;

		policy_add_shared_entry(HANDLE_HEALTH, HEALTH_IDENTITY, 1, IPPROTO_TCP, __bpf_htons(4240), false);
		policy_update_overlay(1, HANDLE_HEALTH);

		ret = check_egress_policy(ctx, HEALTH_IDENTITY, IPPROTO_TCP, __bpf_htons(4240));
		assert(ret == CTX_ACT_OK);
	});

	test_finish();
}

CHECK("tc", "remote_node_identity_test")
int remote_node_identity_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Remote-node identity", {
		int ret;

		policy_add_shared_entry(HANDLE_REMOTE_NODE, REMOTE_NODE_ID, 1, IPPROTO_TCP, __bpf_htons(6443), false);
		policy_update_overlay(1, HANDLE_REMOTE_NODE);

		ret = check_egress_policy(ctx, REMOTE_NODE_ID, IPPROTO_TCP, __bpf_htons(6443));
		assert(ret == CTX_ACT_OK);
	});

	test_finish();
}

CHECK("tc", "mixed_policy_test")
int mixed_policy_test(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Mixed policies", {
		int ret;

		policy_add_shared_entry(HANDLE_MIXED, REMOTE_IDENTITY, 1, IPPROTO_TCP, __bpf_htons(80), false);
		policy_add_shared_entry(HANDLE_MIXED, FQDN_IDENTITY_1, 1, IPPROTO_TCP, __bpf_htons(443), false);
		policy_update_overlay(1, HANDLE_MIXED);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_TCP, __bpf_htons(80));
		assert(ret == CTX_ACT_OK);

		ret = check_egress_policy(ctx, FQDN_IDENTITY_1, IPPROTO_TCP, __bpf_htons(443));
		assert(ret == CTX_ACT_OK);
	});

	test_finish();
}

CHECK("tc", "ingress_policy_test")
int ingress_policy_test(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	TEST("Ingress policy enforcement", {
		policy_add_shared_entry(HANDLE_INGRESS, REMOTE_IDENTITY,
					1 /* ingress */, IPPROTO_TCP,
					__bpf_htons(80), false /* allow */);
		policy_update_overlay(1, HANDLE_INGRESS);
	});

	test_finish();
}
