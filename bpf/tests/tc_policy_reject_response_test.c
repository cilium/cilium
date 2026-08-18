// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_IPV6

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(bool, policy_deny_response_enabled, true)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"
#include "lib/icmp.h"

#define CLIENT_IP v4_pod_one
#define TARGET_IP v4_ext_one

const __u8 v4_lxc_to_external[] = {
	SCAPY_BUF_BYTES(v4_lxc_to_external)
};

const __u8 v4_lxc_to_external_icmp_unreach[] = {
	SCAPY_BUF_BYTES(v4_lxc_to_external_icmp_unreach)
};

const __u8 v6_lxc_to_external[] = {
	SCAPY_BUF_BYTES(v6_lxc_to_external)
};

const __u8 v6_lxc_to_external_icmp_unreach[] = {
	SCAPY_BUF_BYTES(v6_lxc_to_external_icmp_unreach)
};

PKTGEN(PROG_TYPE, "policy_reject_response_v4")
int policy_reject_response_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, v4_lxc_to_external,
			sizeof(v4_lxc_to_external));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "policy_reject_response_v4")
int policy_reject_response_setup(struct __ctx_buff *ctx)
{
	/* Add endpoint for source */
	endpoint_v4_add_entry(CLIENT_IP, 0, 0, 0, 0, 0, NULL, NULL);

	/* Add ipcache entries */
	ipcache_v4_add_entry(CLIENT_IP, 0, 112233, 0, 0);
	ipcache_v4_add_entry(TARGET_IP, 0, 445566, 0, 0);

	/* Add policy that denies egress to target */
	policy_add_egress_deny_all_entry();

	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "policy_reject_response_v4")
int policy_reject_response_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v4_del_entry(CLIENT_IP);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Should redirect ICMP response back to interface */
	assert(*status_code == TC_ACT_REDIRECT);

	ASSERT_CTX_BUF_OFF("v4_lxc_to_external_icmp_unreach",
			   "Ether", ctx, sizeof(__u32),
			   v4_lxc_to_external_icmp_unreach,
			   sizeof(v4_lxc_to_external_icmp_unreach));

	test_finish();
}

/*
 * ICMPv6
 */
#define CLIENT_IPv6 v6_pod_one
#define TARGET_IPv6 v6_pod_two

static __always_inline int
validate_icmpv6_reply_return(const struct __ctx_buff *ctx, __u32 retval)
{
	struct validate_icmpv6_reply_args args = {
		.ctx = ctx,
		.buf_expected = v6_lxc_to_external_icmp_unreach,
		.buf_len = sizeof(v6_lxc_to_external_icmp_unreach),
		.dst_idx = 1,
		.retval = retval,
	};
	return validate_icmpv6_reply(&args);
}

PKTGEN(PROG_TYPE, "policy_reject_response_v6")
int policy_reject_response_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, v6_lxc_to_external,
			sizeof(v6_lxc_to_external));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "policy_reject_response_v6")
int policy_reject_response_v6_setup(struct __ctx_buff *ctx)
{
	/* Add endpoint for source */
	endpoint_v6_add_entry((union v6addr *)CLIENT_IPv6, 0, 0, 0, 0, NULL, NULL);

	/* Add ipcache entries */
	ipcache_v6_add_entry((union v6addr *)CLIENT_IPv6, 0, 112233, 0, 0);
	ipcache_v6_add_entry((union v6addr *)TARGET_IPv6, 0, 445566, 0, 0);

	/* Add policy that denies egress to target */
	policy_add_egress_deny_all_entry();

	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "policy_reject_response_v6")
int policy_reject_response_v6_check(const struct __ctx_buff *ctx)
{
	/* we should have a redirect of the packet on the same interface. */
	return validate_icmpv6_reply_return(ctx, TC_ACT_REDIRECT);
}

/*
 * Test that the ICMP error message goes back into the pod
 */
PKTGEN(PROG_TYPE, "policy_reject_response_v6_ingress")
int policy_reject_response_v6_ingress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, v6_lxc_to_external_icmp_unreach,
			sizeof(v6_lxc_to_external_icmp_unreach));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "policy_reject_response_v6_ingress")
int policy_reject_response_v6_ingress_setup(struct __ctx_buff *ctx)
{
	/* we have no allow policy for this packet so we expect it to be dropped. */
	return pod_receive_packet(ctx);
}

CHECK(PROG_TYPE, "policy_reject_response_v6_ingress")
int policy_reject_response_v6_ingress_check(const struct __ctx_buff *ctx)
{
	return validate_icmpv6_reply_return(ctx, TC_ACT_SHOT);
}
