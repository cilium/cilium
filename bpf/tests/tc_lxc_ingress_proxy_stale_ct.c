// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1

/* A new connection reuses the tuple of an ingress CT entry that still has
 * proxy_redirect set from an earlier L7-proxied connection. Once the L7 rule
 * is gone, the SYN must be delivered without the proxy, the entry must drop
 * proxy_redirect, and the server's SYN-ACK must not be sent to the proxy.
 *
 * Each case is two steps. The SYN step seeds the CT entry and the policy and
 * sends the client's SYN to the server. The SYN-ACK step sends the server's
 * reply against the entry the SYN step left behind.
 */

#define CLIENT_IP		v4_pod_one
#define CLIENT_IPV6		v6_pod_one
#define CLIENT_PORT		__bpf_htons(60856)
#define CLIENT_IDENTITY		112233

#define SERVER_IP		v4_pod_two
#define SERVER_IPV6		v6_pod_two
#define SERVER_PORT		__bpf_htons(8080)
#define SERVER_IDENTITY		445566

#define PROXY_PORT		__bpf_htons(15001)

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = SERVER_IP })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_two_addr })

#include "lib/clear.h"
#include "lib/ipcache.h"
#include "lib/policy.h"

static __always_inline int
build_v4(struct __ctx_buff *ctx, bool to_server)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	if (to_server)
		l4 = pktgen__push_ipv4_tcp_packet(&builder,
						  (__u8 *)client_mac, (__u8 *)server_mac,
						  CLIENT_IP, SERVER_IP,
						  CLIENT_PORT, SERVER_PORT);
	else
		l4 = pktgen__push_ipv4_tcp_packet(&builder,
						  (__u8 *)server_mac, (__u8 *)client_mac,
						  SERVER_IP, CLIENT_IP,
						  SERVER_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;
	l4->ack = to_server ? 0 : 1;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
build_v6(struct __ctx_buff *ctx, bool to_server)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	if (to_server)
		l4 = pktgen__push_ipv6_tcp_packet(&builder,
						  (__u8 *)client_mac, (__u8 *)server_mac,
						  (__u8 *)CLIENT_IPV6, (__u8 *)SERVER_IPV6,
						  CLIENT_PORT, SERVER_PORT);
	else
		l4 = pktgen__push_ipv6_tcp_packet(&builder,
						  (__u8 *)server_mac, (__u8 *)client_mac,
						  (__u8 *)SERVER_IPV6, (__u8 *)CLIENT_IPV6,
						  SERVER_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;
	l4->ack = to_server ? 0 : 1;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline struct ct_entry *lookup_v4(void)
{
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.saddr = SERVER_IP,
		.daddr = CLIENT_IP,
		.sport = CLIENT_PORT,
		.dport = SERVER_PORT,
		.flags = TUPLE_F_IN,
	};

	return map_lookup_elem(&cilium_ct4_global, &tuple);
}

static __always_inline struct ct_entry *lookup_v6(void)
{
	struct ipv6_ct_tuple tuple __align_stack_8 = {
		.nexthdr = IPPROTO_TCP,
		.saddr = *(union v6addr *)SERVER_IPV6,
		.daddr = *(union v6addr *)CLIENT_IPV6,
		.sport = CLIENT_PORT,
		.dport = SERVER_PORT,
		.flags = TUPLE_F_IN,
	};

	return map_lookup_elem(&cilium_ct6_global, &tuple);
}

/* Seed an ingress entry with proxy_redirect set, install the ingress rule
 * with proxy_port, and deliver the SYN the way ipv4_local_delivery() does.
 */
static __always_inline int
setup_syn_v4(struct __ctx_buff *ctx, bool closed, __be16 proxy_port)
{
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.saddr = SERVER_IP,
		.daddr = CLIENT_IP,
		.sport = CLIENT_PORT,
		.dport = SERVER_PORT,
		.flags = TUPLE_F_IN,
	};
	struct ct_state state = {
		.src_sec_id = CLIENT_IDENTITY,
		.proxy_redirect = 1,
	};
	struct ct_entry *entry;

	clear_map(&cilium_ct4_global);
	ipcache_v4_add_entry(CLIENT_IP, 0, CLIENT_IDENTITY, 0, 0);
	ipcache_v4_add_entry(SERVER_IP, 0, SERVER_IDENTITY, 0, 0);
	policy_add_entry(false, CLIENT_IDENTITY, IPPROTO_TCP, SERVER_PORT, 0,
			 false, proxy_port);

	ct_create4(&cilium_ct4_global, NULL, &tuple, ctx, CT_INGRESS, &state, NULL);
	entry = map_lookup_elem(&cilium_ct4_global, &tuple);
	if (!entry)
		return TEST_ERROR;

	entry->rx_closing = closed;
	entry->tx_closing = closed;

	local_delivery_fill_meta(ctx, CLIENT_IDENTITY, false, false, false, false, 0);
	return pod_receive_packet_by_tailcall(ctx);
}

static __always_inline int
setup_syn_v6(struct __ctx_buff *ctx, bool closed, __be16 proxy_port)
{
	struct ipv6_ct_tuple tuple __align_stack_8 = {
		.nexthdr = IPPROTO_TCP,
		.saddr = *(union v6addr *)SERVER_IPV6,
		.daddr = *(union v6addr *)CLIENT_IPV6,
		.sport = CLIENT_PORT,
		.dport = SERVER_PORT,
		.flags = TUPLE_F_IN,
	};
	struct ct_state state = {
		.src_sec_id = CLIENT_IDENTITY,
		.proxy_redirect = 1,
	};
	struct ct_entry *entry;

	clear_map(&cilium_ct6_global);
	ipcache_v6_add_entry((union v6addr *)CLIENT_IPV6, 0, CLIENT_IDENTITY, 0, 0);
	ipcache_v6_add_entry((union v6addr *)SERVER_IPV6, 0, SERVER_IDENTITY, 0, 0);
	policy_add_entry(false, CLIENT_IDENTITY, IPPROTO_TCP, SERVER_PORT, 0,
			 false, proxy_port);

	ct_create6(&cilium_ct6_global, NULL, &tuple, ctx, CT_INGRESS, &state, NULL);
	entry = map_lookup_elem(&cilium_ct6_global, &tuple);
	if (!entry)
		return TEST_ERROR;

	entry->rx_closing = closed;
	entry->tx_closing = closed;

	local_delivery_fill_meta(ctx, CLIENT_IDENTITY, false, false, false, false, 0);
	return pod_receive_packet_by_tailcall(ctx);
}

static __always_inline bool to_proxy(const struct __ctx_buff *ctx)
{
	return (ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_TO_PROXY;
}

static __always_inline int
check_syn(const struct __ctx_buff *ctx, const struct ct_entry *entry, bool proxy)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code = data;

	test_init();

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	assert(*status_code == CTX_ACT_OK);

	if (to_proxy(ctx) != proxy)
		test_fatal("SYN to proxy is %d, want %d, mark=%x",
			   to_proxy(ctx), proxy, ctx->mark);

	if (!entry)
		test_fatal("no ingress CT entry");

	if (entry->proxy_redirect != proxy)
		test_fatal("CT entry proxy_redirect is %d, want %d",
			   entry->proxy_redirect, proxy);

	test_finish();
}

static __always_inline int
check_synack(const struct __ctx_buff *ctx, bool proxy)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code = data;

	test_init();

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	assert(*status_code == CTX_ACT_OK);

	if (to_proxy(ctx) != proxy)
		test_fatal("SYN-ACK to proxy is %d, want %d, mark=%x",
			   to_proxy(ctx), proxy, ctx->mark);

	test_finish();
}

/* Closed entry, L4-only policy. The SYN reopens the entry. */

PKTGEN(PROG_TYPE, "01_v4_closed_1_syn")
int v4_closed_syn_pktgen(struct __ctx_buff *ctx)
{
	return build_v4(ctx, true);
}

SETUP(PROG_TYPE, "01_v4_closed_1_syn")
int v4_closed_syn_setup(struct __ctx_buff *ctx)
{
	return setup_syn_v4(ctx, true, 0);
}

CHECK(PROG_TYPE, "01_v4_closed_1_syn")
int v4_closed_syn_check(const struct __ctx_buff *ctx)
{
	return check_syn(ctx, lookup_v4(), false);
}

PKTGEN(PROG_TYPE, "01_v4_closed_2_synack")
int v4_closed_synack_pktgen(struct __ctx_buff *ctx)
{
	return build_v4(ctx, false);
}

SETUP(PROG_TYPE, "01_v4_closed_2_synack")
int v4_closed_synack_setup(struct __ctx_buff *ctx)
{
	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "01_v4_closed_2_synack")
int v4_closed_synack_check(const struct __ctx_buff *ctx)
{
	return check_synack(ctx, false);
}

/* Live entry, L4-only policy. The SYN gets CT_ESTABLISHED. */

PKTGEN(PROG_TYPE, "02_v4_live_1_syn")
int v4_live_syn_pktgen(struct __ctx_buff *ctx)
{
	return build_v4(ctx, true);
}

SETUP(PROG_TYPE, "02_v4_live_1_syn")
int v4_live_syn_setup(struct __ctx_buff *ctx)
{
	return setup_syn_v4(ctx, false, 0);
}

CHECK(PROG_TYPE, "02_v4_live_1_syn")
int v4_live_syn_check(const struct __ctx_buff *ctx)
{
	return check_syn(ctx, lookup_v4(), false);
}

PKTGEN(PROG_TYPE, "02_v4_live_2_synack")
int v4_live_synack_pktgen(struct __ctx_buff *ctx)
{
	return build_v4(ctx, false);
}

SETUP(PROG_TYPE, "02_v4_live_2_synack")
int v4_live_synack_setup(struct __ctx_buff *ctx)
{
	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "02_v4_live_2_synack")
int v4_live_synack_check(const struct __ctx_buff *ctx)
{
	return check_synack(ctx, false);
}

/* Live entry, L7 policy. Both packets still go to the proxy. */

PKTGEN(PROG_TYPE, "03_v4_l7_1_syn")
int v4_l7_syn_pktgen(struct __ctx_buff *ctx)
{
	return build_v4(ctx, true);
}

SETUP(PROG_TYPE, "03_v4_l7_1_syn")
int v4_l7_syn_setup(struct __ctx_buff *ctx)
{
	return setup_syn_v4(ctx, false, PROXY_PORT);
}

CHECK(PROG_TYPE, "03_v4_l7_1_syn")
int v4_l7_syn_check(const struct __ctx_buff *ctx)
{
	return check_syn(ctx, lookup_v4(), true);
}

PKTGEN(PROG_TYPE, "03_v4_l7_2_synack")
int v4_l7_synack_pktgen(struct __ctx_buff *ctx)
{
	return build_v4(ctx, false);
}

SETUP(PROG_TYPE, "03_v4_l7_2_synack")
int v4_l7_synack_setup(struct __ctx_buff *ctx)
{
	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "03_v4_l7_2_synack")
int v4_l7_synack_check(const struct __ctx_buff *ctx)
{
	return check_synack(ctx, true);
}

PKTGEN(PROG_TYPE, "04_v6_closed_1_syn")
int v6_closed_syn_pktgen(struct __ctx_buff *ctx)
{
	return build_v6(ctx, true);
}

SETUP(PROG_TYPE, "04_v6_closed_1_syn")
int v6_closed_syn_setup(struct __ctx_buff *ctx)
{
	return setup_syn_v6(ctx, true, 0);
}

CHECK(PROG_TYPE, "04_v6_closed_1_syn")
int v6_closed_syn_check(const struct __ctx_buff *ctx)
{
	return check_syn(ctx, lookup_v6(), false);
}

PKTGEN(PROG_TYPE, "04_v6_closed_2_synack")
int v6_closed_synack_pktgen(struct __ctx_buff *ctx)
{
	return build_v6(ctx, false);
}

SETUP(PROG_TYPE, "04_v6_closed_2_synack")
int v6_closed_synack_setup(struct __ctx_buff *ctx)
{
	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "04_v6_closed_2_synack")
int v6_closed_synack_check(const struct __ctx_buff *ctx)
{
	return check_synack(ctx, false);
}

PKTGEN(PROG_TYPE, "05_v6_live_1_syn")
int v6_live_syn_pktgen(struct __ctx_buff *ctx)
{
	return build_v6(ctx, true);
}

SETUP(PROG_TYPE, "05_v6_live_1_syn")
int v6_live_syn_setup(struct __ctx_buff *ctx)
{
	return setup_syn_v6(ctx, false, 0);
}

CHECK(PROG_TYPE, "05_v6_live_1_syn")
int v6_live_syn_check(const struct __ctx_buff *ctx)
{
	return check_syn(ctx, lookup_v6(), false);
}

PKTGEN(PROG_TYPE, "05_v6_live_2_synack")
int v6_live_synack_pktgen(struct __ctx_buff *ctx)
{
	return build_v6(ctx, false);
}

SETUP(PROG_TYPE, "05_v6_live_2_synack")
int v6_live_synack_setup(struct __ctx_buff *ctx)
{
	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "05_v6_live_2_synack")
int v6_live_synack_check(const struct __ctx_buff *ctx)
{
	return check_synack(ctx, false);
}

PKTGEN(PROG_TYPE, "06_v6_l7_1_syn")
int v6_l7_syn_pktgen(struct __ctx_buff *ctx)
{
	return build_v6(ctx, true);
}

SETUP(PROG_TYPE, "06_v6_l7_1_syn")
int v6_l7_syn_setup(struct __ctx_buff *ctx)
{
	return setup_syn_v6(ctx, false, PROXY_PORT);
}

CHECK(PROG_TYPE, "06_v6_l7_1_syn")
int v6_l7_syn_check(const struct __ctx_buff *ctx)
{
	return check_syn(ctx, lookup_v6(), true);
}

PKTGEN(PROG_TYPE, "06_v6_l7_2_synack")
int v6_l7_synack_pktgen(struct __ctx_buff *ctx)
{
	return build_v6(ctx, false);
}

SETUP(PROG_TYPE, "06_v6_l7_2_synack")
int v6_l7_synack_setup(struct __ctx_buff *ctx)
{
	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "06_v6_l7_2_synack")
int v6_l7_synack_check(const struct __ctx_buff *ctx)
{
	return check_synack(ctx, true);
}
