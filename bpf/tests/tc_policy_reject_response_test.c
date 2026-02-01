// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

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

PKTGEN("tc", "policy_reject_response_v4")
int policy_reject_response_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  CLIENT_IP, TARGET_IP,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "policy_reject_response_v4")
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

CHECK("tc", "policy_reject_response_v4")
int policy_reject_response_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct icmphdr *icmp;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Should redirect ICMP response back to interface */
	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	/* Verify this is an ICMP response packet */
	if (l3->protocol != IPPROTO_ICMP)
		test_fatal("expected ICMP protocol, got %d", l3->protocol);

	/* Source should be swapped to target, destination should be client */
	if (l3->saddr != TARGET_IP)
		test_fatal("ICMP src should be target IP");

	if (l3->daddr != CLIENT_IP)
		test_fatal("ICMP dst should be client IP");

	icmp = (void *)l3 + sizeof(struct iphdr);

	if ((void *)icmp + sizeof(struct icmphdr) > data_end)
		test_fatal("ICMP header out of bounds");

	/* Verify ICMP error type and code for policy rejection */
	if (icmp->type != ICMP_DEST_UNREACH)
		test_fatal("expected ICMP_DEST_UNREACH, got type %d", icmp->type);

	if (icmp->code != ICMP_PKT_FILTERED)
		test_fatal("expected ICMP_PKT_FILTERED, got code %d", icmp->code);

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
		.src_mac = (__u8 *)mac_two,
		.dst_mac = (__u8 *)mac_one,
		.src_ip = (__u8 *)TARGET_IPv6,
		.dst_ip = (__u8 *)CLIENT_IPv6,
		.icmp_type = ICMPV6_DEST_UNREACH,
		.icmp_code = ICMPV6_ADM_PROHIBITED,
		.checksum = 0x9e17,
		.dst_idx = 1,
		.retval = retval,
	};
	return validate_icmpv6_reply(&args);
}

PKTGEN("tc", "policy_reject_response_v6")
int policy_reject_response_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)CLIENT_IPv6,
					  (__u8 *)TARGET_IPv6,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "policy_reject_response_v6")
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

CHECK("tc", "policy_reject_response_v6")
int policy_reject_response_v6_check(const struct __ctx_buff *ctx)
{
	/* we should have a redirect of the packet on the same interface. */
	return validate_icmpv6_reply_return(ctx, TC_ACT_REDIRECT);
}

/*
 * Test that the ICMP error message goes back into the pod
 */
PKTGEN("tc", "policy_reject_response_v6_ingress")
int policy_reject_response_v6_ingress_pktgen(struct __ctx_buff *ctx)
{
	/* Start with the initial request, and let SETUP() below rebuild it. */
	return policy_reject_response_v6_pktgen(ctx);
}

SETUP("tc", "policy_reject_response_v6_ingress")
int policy_reject_response_v6_ingress_setup(struct __ctx_buff *ctx)
{
	if (generate_icmp6_reply(ctx, ICMPV6_DEST_UNREACH, ICMPV6_ADM_PROHIBITED))
		return TEST_ERROR;
	/* we have no allow policy for this packet so we expect it to be dropped. */
	return pod_receive_packet(ctx);
}

CHECK("tc", "policy_reject_response_v6_ingress")
int policy_reject_response_v6_ingress_check(const struct __ctx_buff *ctx)
{
	return validate_icmpv6_reply_return(ctx, TC_ACT_SHOT);
}
