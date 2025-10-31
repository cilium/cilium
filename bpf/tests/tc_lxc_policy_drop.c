// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)

#define SERVER_IP		v4_pod_two
#define SERVER_PORT		__bpf_htons(222)

#define NODE_IP			v4_node_one

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one})

#include "lib/policy.h"

/* Test that a packet drop results in BPF metric counters increament.
 */
PKTGEN("tc", "tc_lxc_policy_drop")
int tc_lxc_policy_drop_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)server_mac,
					  CLIENT_IP, SERVER_IP,
					  CLIENT_PORT, SERVER_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

__u64 drop_count;

SETUP("tc", "tc_lxc_policy_drop")
int tc_lxc_policy_drop__setup(struct __ctx_buff *ctx)
{
	policy_add_egress_deny_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_policy_drop")
int tc_lxc_policy_drop_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	struct metrics_key key = {};

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	key.reason = (__u8)-DROP_POLICY_DENY;
	key.dir = METRIC_EGRESS;

	__u64 count = 1;
	assert_metrics_count(key, count);

	test_finish();
}
