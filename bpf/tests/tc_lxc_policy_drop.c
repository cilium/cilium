// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4 1

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)

#define SERVER_IP		v4_pod_two
#define SERVER_PORT		__bpf_htons(222)
#define SERVER_IDENTITY		445566

#define NODE_IP			v4_node_one

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(bool, enable_ipv4, true)
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one})

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

/* Test that a reply which the proxy sends on a downstream connection is not
 * handled as a new connection once the client's CT entry is gone: it passes
 * the client's ingress policy and doesn't create a CT entry in the reverse
 * direction. Only the bare proxy mark identifies such replies, a packet of an
 * upstream connection is still subject to ingress policy.
 */
static __always_inline int
proxy_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)server_mac, (__u8 *)client_mac,
					  SERVER_IP, CLIENT_IP,
					  SERVER_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->ack = 1;

	pktgen__finish(&builder);

	return 0;
}

static __always_inline int
proxy_setup(struct __ctx_buff *ctx, __u32 identity, bool from_bpf_host)
{
	policy_add_ingress_deny_all_entry();

	set_identity_mark(ctx, identity, MARK_MAGIC_PROXY_EGRESS);

	/* Without endpoint routes, bpf_host inherits the mark and delivers the
	 * packet through the policy tail-call.
	 */
	if (from_bpf_host) {
		inherit_identity_from_host(ctx, &identity);
		local_delivery_fill_meta(ctx, identity, false, false, true, false, 0);

		return pod_receive_packet_by_tailcall(ctx);
	}

	return pod_receive_packet(ctx);
}

static __always_inline int
proxy_check(const struct __ctx_buff *ctx, __u32 expected_status)
{
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.saddr = CLIENT_IP,
		.daddr = SERVER_IP,
		.sport = SERVER_PORT,
		.dport = CLIENT_PORT,
		.flags = TUPLE_F_IN,
	};
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == expected_status);

	if (map_lookup_elem(&cilium_ct4_global, &tuple))
		test_fatal("CT entry created in the reverse direction");

	test_finish();
}

#define PROXY_TEST(NAME, IDENTITY, FROM_BPF_HOST, STATUS)		\
PKTGEN(PROG_TYPE, #NAME)						\
int NAME##_pktgen(struct __ctx_buff *ctx)				\
{									\
	return proxy_pktgen(ctx);					\
}									\
									\
SETUP(PROG_TYPE, #NAME)							\
int NAME##_setup(struct __ctx_buff *ctx)				\
{									\
	return proxy_setup(ctx, IDENTITY, FROM_BPF_HOST);		\
}									\
									\
CHECK(PROG_TYPE, #NAME)							\
int NAME##_check(const struct __ctx_buff *ctx)				\
{									\
	return proxy_check(ctx, STATUS);				\
}

PROXY_TEST(tc_lxc_proxy_reply, UNKNOWN_ID, false, CTX_ACT_OK)
PROXY_TEST(tc_lxc_proxy_reply_tailcall, UNKNOWN_ID, true, CTX_ACT_OK)
PROXY_TEST(tc_lxc_proxy_upstream, SERVER_IDENTITY, false, CTX_ACT_DROP)
PROXY_TEST(tc_lxc_proxy_upstream_tailcall, SERVER_IDENTITY, true, CTX_ACT_DROP)
