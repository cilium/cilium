// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		tcp_src_one
#define CLIENT_ID		112233

#define POD_IP			v4_pod_two
#define POD_PORT		tcp_svc_one
#define POD_ID			445566

#define PROXY_PORT		bpf_htons(18000)

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *pod_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = POD_IP })
ASSIGN_CONFIG(__u32, security_label, POD_ID)

#include "lib/ipcache.h"
#include "lib/policy.h"

/* An L7 policy on ingress leaves proxy_redirect set on the pod's ingress CT
 * entry. Once the agent drops that policy, a connection reusing the same
 * 5-tuple must not have its reply redirected into the proxy.
 */

static __always_inline int
pktgen_to_pod(struct __ctx_buff *ctx, bool syn)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)pod_mac,
					  CLIENT_IP, POD_IP,
					  CLIENT_PORT, POD_PORT);
	if (!l4)
		return TEST_ERROR;

	if (!syn) {
		l4->syn = 0;
		l4->ack = 1;
	}

	pktgen__finish(&builder);

	return 0;
}

static __always_inline struct ct_entry *
lookup_ingress_ct_entry(void)
{
	struct ipv4_ct_tuple tuple = {
		.saddr   = POD_IP,
		.daddr   = CLIENT_IP,
		.dport   = POD_PORT,
		.sport   = CLIENT_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags   = TUPLE_F_IN,
	};

	return map_lookup_elem(&cilium_ct4_global, &tuple);
}

PKTGEN(PROG_TYPE, "stale_proxy_redirect_1_l7_syn")
int stale_proxy_redirect_1_l7_syn_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to_pod(ctx, true);
}

SETUP(PROG_TYPE, "stale_proxy_redirect_1_l7_syn")
int stale_proxy_redirect_1_l7_syn_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(CLIENT_IP, 0, CLIENT_ID, 0, 0);
	policy_add_entry(false, CLIENT_ID, IPPROTO_TCP, POD_PORT, 0, false,
			 PROXY_PORT);

	local_delivery_fill_meta(ctx, CLIENT_ID, false, false, false, false, 0);

	return pod_receive_packet_by_tailcall(ctx);
}

CHECK(PROG_TYPE, "stale_proxy_redirect_1_l7_syn")
int stale_proxy_redirect_1_l7_syn_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ct_entry *entry;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	if (ctx->mark != (MARK_MAGIC_TO_PROXY | (__u32)PROXY_PORT << 16))
		test_fatal("request not redirected to the proxy: 0x%lx", ctx->mark);

	entry = lookup_ingress_ct_entry();
	if (!entry)
		test_fatal("no ingress CT entry");

	if (!entry->proxy_redirect)
		test_fatal("proxy_redirect not set on the ingress CT entry");

	test_finish();
}

/* While the L7 policy holds, the client's next packet keeps the flag. */
PKTGEN(PROG_TYPE, "stale_proxy_redirect_2_l7_ack")
int stale_proxy_redirect_2_l7_ack_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to_pod(ctx, false);
}

SETUP(PROG_TYPE, "stale_proxy_redirect_2_l7_ack")
int stale_proxy_redirect_2_l7_ack_setup(struct __ctx_buff *ctx)
{
	local_delivery_fill_meta(ctx, CLIENT_ID, false, false, false, false, 0);

	return pod_receive_packet_by_tailcall(ctx);
}

CHECK(PROG_TYPE, "stale_proxy_redirect_2_l7_ack")
int stale_proxy_redirect_2_l7_ack_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ct_entry *entry;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	if (ctx->mark != (MARK_MAGIC_TO_PROXY | (__u32)PROXY_PORT << 16))
		test_fatal("ACK not redirected to the proxy: 0x%lx", ctx->mark);

	entry = lookup_ingress_ct_entry();
	if (!entry)
		test_fatal("no ingress CT entry");

	if (!entry->proxy_redirect)
		test_fatal("proxy_redirect cleared under the L7 policy");

	test_finish();
}

/* With the L7 policy gone, a packet from the ingress proxy keeps the flag. */
PKTGEN(PROG_TYPE, "stale_proxy_redirect_3_proxy_leg")
int stale_proxy_redirect_3_proxy_leg_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to_pod(ctx, false);
}

SETUP(PROG_TYPE, "stale_proxy_redirect_3_proxy_leg")
int stale_proxy_redirect_3_proxy_leg_setup(struct __ctx_buff *ctx)
{
	policy_delete_ingress_l3_l4_entry(CLIENT_ID, IPPROTO_TCP, POD_PORT, 0);
	policy_add_ingress_allow_all_entry();

	ctx->tc_index |= TC_INDEX_F_FROM_INGRESS_PROXY;
	local_delivery_fill_meta(ctx, CLIENT_ID, false, false, false, false, 0);

	return pod_receive_packet_by_tailcall(ctx);
}

CHECK(PROG_TYPE, "stale_proxy_redirect_3_proxy_leg")
int stale_proxy_redirect_3_proxy_leg_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ct_entry *entry;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	if (ctx->mark & MARK_MAGIC_TO_PROXY)
		test_fatal("proxy leg redirected to the proxy: 0x%lx", ctx->mark);

	entry = lookup_ingress_ct_entry();
	if (!entry)
		test_fatal("no ingress CT entry");

	if (!entry->proxy_redirect)
		test_fatal("proxy leg cleared proxy_redirect");

	test_finish();
}

/* The CT entry lives on, and a new connection reuses its 5-tuple. */
PKTGEN(PROG_TYPE, "stale_proxy_redirect_4_reused_syn")
int stale_proxy_redirect_4_reused_syn_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to_pod(ctx, true);
}

SETUP(PROG_TYPE, "stale_proxy_redirect_4_reused_syn")
int stale_proxy_redirect_4_reused_syn_setup(struct __ctx_buff *ctx)
{
	local_delivery_fill_meta(ctx, CLIENT_ID, false, false, false, false, 0);

	return pod_receive_packet_by_tailcall(ctx);
}

CHECK(PROG_TYPE, "stale_proxy_redirect_4_reused_syn")
int stale_proxy_redirect_4_reused_syn_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ct_entry *entry;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	if (ctx->mark & MARK_MAGIC_TO_PROXY)
		test_fatal("request redirected to the proxy: 0x%lx", ctx->mark);

	entry = lookup_ingress_ct_entry();
	if (!entry)
		test_fatal("no ingress CT entry");

	if (entry->proxy_redirect)
		test_fatal("stale proxy_redirect kept on the ingress CT entry");

	if (entry->src_sec_id != CLIENT_ID)
		test_fatal("src_sec_id lost: %lu", entry->src_sec_id);

	test_finish();
}

/* The pod answers, and its reply has to reach the stack. */
PKTGEN(PROG_TYPE, "stale_proxy_redirect_5_reply")
int stale_proxy_redirect_5_reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)pod_mac, (__u8 *)client_mac,
					  POD_IP, CLIENT_IP,
					  POD_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->ack = 1;

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "stale_proxy_redirect_5_reply")
int stale_proxy_redirect_5_reply_setup(struct __ctx_buff *ctx)
{
	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "stale_proxy_redirect_5_reply")
int stale_proxy_redirect_5_reply_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	if (ctx->mark & MARK_MAGIC_TO_PROXY)
		test_fatal("reply redirected to the proxy: 0x%lx", ctx->mark);

	test_finish();
}
