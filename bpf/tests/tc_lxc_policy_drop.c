// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4 1
#define ENABLE_IPV6 1

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)

#define SERVER_IP		v4_pod_two
#define SERVER_PORT		__bpf_htons(222)

#define NODE_IP			v4_node_one

/* Use a CIDR identity whose lower 24 bits (0x00CAFF) are not a reserved
 * identity, so tail_ipv{4,6}_to_endpoint() skips the ipcache lookup and
 * relies on the full 32-bit identity preserved in ctx->mark.
 */
#define TEST_CIDR_IDENTITY	(CIDR_IDENTITY_RANGE_START + 0xCAFE)

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one})
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })

#include "lib/policy.h"

/* Test that a packet drop results in BPF metric counters increament.
 */
PKTGEN(PROG_TYPE, "tc_lxc_policy_drop")
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

SETUP(PROG_TYPE, "tc_lxc_policy_drop")
int tc_lxc_policy_drop__setup(struct __ctx_buff *ctx)
{
	policy_add_egress_deny_all_entry();

	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "tc_lxc_policy_drop")
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

	assert_metrics_count(key, 1);

	test_finish();
}

/* Test that cil_to_container preserves a 32-bit CIDR identity from ctx->mark
 * and allows ingress traffic matching a CIDR policy rule (IPv4).
 */
PKTGEN(PROG_TYPE, "tc_lxc_v4_ingress_cidr_policy")
int tc_lxc_v4_ingress_cidr_policy_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)server_mac,
					  v4_ext_one, v4_pod_one,
					  CLIENT_PORT, SERVER_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "tc_lxc_v4_ingress_cidr_policy")
int tc_lxc_v4_ingress_cidr_policy_setup(struct __ctx_buff *ctx)
{
	policy_add_ingress_allow_l3_l4_entry(TEST_CIDR_IDENTITY, IPPROTO_TCP,
					     SERVER_PORT, 0);
	set_identity_mark(ctx, TEST_CIDR_IDENTITY, MARK_MAGIC_IDENTITY);

	return pod_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_lxc_v4_ingress_cidr_policy")
int tc_lxc_v4_ingress_cidr_policy_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	policy_delete_ingress_l3_l4_entry(TEST_CIDR_IDENTITY, IPPROTO_TCP,
					  SERVER_PORT, 0);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	test_finish();
}

/* Test that cil_to_container preserves a 32-bit CIDR identity from ctx->mark
 * and allows ingress traffic matching a CIDR policy rule (IPv6).
 */
PKTGEN(PROG_TYPE, "tc_lxc_v6_ingress_cidr_policy")
int tc_lxc_v6_ingress_cidr_policy_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)server_mac,
					  (__u8 *)v6_ext_node_one, (__u8 *)v6_pod_one,
					  CLIENT_PORT, SERVER_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "tc_lxc_v6_ingress_cidr_policy")
int tc_lxc_v6_ingress_cidr_policy_setup(struct __ctx_buff *ctx)
{
	policy_add_ingress_allow_l3_l4_entry(TEST_CIDR_IDENTITY, IPPROTO_TCP,
					     SERVER_PORT, 0);
	set_identity_mark(ctx, TEST_CIDR_IDENTITY, MARK_MAGIC_IDENTITY);

	return pod_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_lxc_v6_ingress_cidr_policy")
int tc_lxc_v6_ingress_cidr_policy_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	policy_delete_ingress_l3_l4_entry(TEST_CIDR_IDENTITY, IPPROTO_TCP,
					  SERVER_PORT, 0);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	test_finish();
}
