// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#include <bpf/config/node.h>
ASSIGN_CONFIG(bool, policy_deny_response_enabled, true)

#include <bpf_lxc.c>
#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[0] = &cil_from_container,
	},
};

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

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
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
