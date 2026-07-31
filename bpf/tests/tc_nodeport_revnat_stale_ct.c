// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define ENABLE_NODEPORT		1

/* GH#47396: a stale NodePort CT entry shares its tuple with a live flow. */

#define CLIENT_IP		v4_pod_one
#define CLIENT_IPV6		v6_pod_one
#define CLIENT_PORT		__bpf_htons(53758)

#define FRONTEND_IP		v4_node_one
#define FRONTEND_IPV6		v6_node_one
#define FRONTEND_PORT		__bpf_htons(4000)

#define BACKEND_IP		v4_pod_two
#define BACKEND_IPV6		v6_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define DEFAULT_IFACE		24
#define REVNAT_ID		109

#define fib_lookup mock_fib_lookup

static __always_inline long
mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		__maybe_unused int plen, __maybe_unused __u32 flags)
{
	params->ifindex = DEFAULT_IFACE;

	return BPF_FIB_LKUP_RET_SUCCESS;
}

#include "lib/bpf_host.h"
#include "lib/clear.h"
#include "lib/lb.h"

ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)

enum ingress_entry {
	INGRESS_LIVE,
	INGRESS_HALF_CLOSED,
	INGRESS_CLOSED,
	INGRESS_PROXY,
};

static __always_inline int build_reply_v4(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_four, (__u8 *)mac_three,
					  BACKEND_IP, CLIENT_IP,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 0;
	l4->ack = 1;

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int build_reply_v6(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_four, (__u8 *)mac_three,
					  (__u8 *)BACKEND_IPV6, (__u8 *)CLIENT_IPV6,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 0;
	l4->ack = 1;

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
setup_v4(struct __ctx_buff *ctx, bool out_closed, enum ingress_entry in)
{
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.saddr = BACKEND_IP,
		.daddr = CLIENT_IP,
		.sport = CLIENT_PORT,
		.dport = BACKEND_PORT,
		.flags = TUPLE_F_OUT,
	};
	struct ct_state out_state = {
		.node_port = 1,
		.rev_nat_index = REVNAT_ID,
	};
	struct ct_state in_state = {
		.proxy_redirect = in == INGRESS_PROXY,
	};
	struct ct_entry *entry;

	clear_map(&cilium_ct4_global);
	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, REVNAT_ID);

	ct_create4(&cilium_ct4_global, NULL, &tuple, ctx, CT_EGRESS, &out_state, NULL);
	entry = map_lookup_elem(&cilium_ct4_global, &tuple);
	if (!entry)
		return TEST_ERROR;

	entry->tx_closing = 1;
	entry->rx_closing = out_closed;

	tuple.flags = TUPLE_F_IN;
	ct_create4(&cilium_ct4_global, NULL, &tuple, ctx, CT_INGRESS, &in_state, NULL);
	entry = map_lookup_elem(&cilium_ct4_global, &tuple);
	if (!entry)
		return TEST_ERROR;

	entry->rx_closing = in == INGRESS_HALF_CLOSED || in == INGRESS_CLOSED;
	entry->tx_closing = in == INGRESS_CLOSED;

	return netdev_send_packet(ctx);
}

static __always_inline int
setup_v6(struct __ctx_buff *ctx, bool out_closed, enum ingress_entry in)
{
	struct ipv6_ct_tuple tuple __align_stack_8 = {
		.nexthdr = IPPROTO_TCP,
		.saddr = *(union v6addr *)BACKEND_IPV6,
		.daddr = *(union v6addr *)CLIENT_IPV6,
		.sport = CLIENT_PORT,
		.dport = BACKEND_PORT,
		.flags = TUPLE_F_OUT,
	};
	struct ct_state out_state = {
		.node_port = 1,
		.rev_nat_index = REVNAT_ID,
	};
	struct ct_state in_state = {
		.proxy_redirect = in == INGRESS_PROXY,
	};
	struct ct_entry *entry;

	clear_map(&cilium_ct6_global);
	lb_v6_add_service((union v6addr *)FRONTEND_IPV6, FRONTEND_PORT, IPPROTO_TCP,
			  1, REVNAT_ID);

	ct_create6(&cilium_ct6_global, NULL, &tuple, ctx, CT_EGRESS, &out_state, NULL);
	entry = map_lookup_elem(&cilium_ct6_global, &tuple);
	if (!entry)
		return TEST_ERROR;

	entry->tx_closing = 1;
	entry->rx_closing = out_closed;

	tuple.flags = TUPLE_F_IN;
	ct_create6(&cilium_ct6_global, NULL, &tuple, ctx, CT_INGRESS, &in_state, NULL);
	entry = map_lookup_elem(&cilium_ct6_global, &tuple);
	if (!entry)
		return TEST_ERROR;

	entry->rx_closing = in == INGRESS_HALF_CLOSED || in == INGRESS_CLOSED;
	entry->tx_closing = in == INGRESS_CLOSED;

	return netdev_send_packet(ctx);
}

static __always_inline int
check_v4(const struct __ctx_buff *ctx, __be32 saddr, __be16 sport)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code = data;
	struct iphdr *l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	struct tcphdr *l4 = (void *)(l3 + 1);

	test_init();

	if ((void *)(l4 + 1) > data_end)
		test_fatal("packet out of bounds");

	assert(*status_code == CTX_ACT_OK);
	assert(l3->saddr == saddr);
	assert(l4->source == sport);

	test_finish();
}

static __always_inline int
check_v6(const struct __ctx_buff *ctx, const union v6addr *saddr, __be16 sport)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code = data;
	struct ipv6hdr *l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	struct tcphdr *l4 = (void *)(l3 + 1);

	test_init();

	if ((void *)(l4 + 1) > data_end)
		test_fatal("packet out of bounds");

	assert(*status_code == CTX_ACT_OK);
	assert(ipv6_addr_equals((union v6addr *)&l3->saddr, saddr));
	assert(l4->source == sport);

	test_finish();
}

PKTGEN(PROG_TYPE, "01_v4_stale_out_live_in")
int v4_stale_out_live_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v4(ctx);
}

SETUP(PROG_TYPE, "01_v4_stale_out_live_in")
int v4_stale_out_live_in_setup(struct __ctx_buff *ctx)
{
	return setup_v4(ctx, true, INGRESS_LIVE);
}

CHECK(PROG_TYPE, "01_v4_stale_out_live_in")
int v4_stale_out_live_in_check(const struct __ctx_buff *ctx)
{
	return check_v4(ctx, BACKEND_IP, BACKEND_PORT);
}

PKTGEN(PROG_TYPE, "02_v4_half_closed_out_half_closed_in")
int v4_half_closed_out_half_closed_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v4(ctx);
}

SETUP(PROG_TYPE, "02_v4_half_closed_out_half_closed_in")
int v4_half_closed_out_half_closed_in_setup(struct __ctx_buff *ctx)
{
	return setup_v4(ctx, false, INGRESS_HALF_CLOSED);
}

CHECK(PROG_TYPE, "02_v4_half_closed_out_half_closed_in")
int v4_half_closed_out_half_closed_in_check(const struct __ctx_buff *ctx)
{
	return check_v4(ctx, FRONTEND_IP, FRONTEND_PORT);
}

PKTGEN(PROG_TYPE, "03_v4_stale_out_half_closed_in")
int v4_stale_out_half_closed_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v4(ctx);
}

SETUP(PROG_TYPE, "03_v4_stale_out_half_closed_in")
int v4_stale_out_half_closed_in_setup(struct __ctx_buff *ctx)
{
	return setup_v4(ctx, true, INGRESS_HALF_CLOSED);
}

CHECK(PROG_TYPE, "03_v4_stale_out_half_closed_in")
int v4_stale_out_half_closed_in_check(const struct __ctx_buff *ctx)
{
	return check_v4(ctx, BACKEND_IP, BACKEND_PORT);
}

PKTGEN(PROG_TYPE, "04_v4_stale_out_closed_in")
int v4_stale_out_closed_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v4(ctx);
}

SETUP(PROG_TYPE, "04_v4_stale_out_closed_in")
int v4_stale_out_closed_in_setup(struct __ctx_buff *ctx)
{
	return setup_v4(ctx, true, INGRESS_CLOSED);
}

CHECK(PROG_TYPE, "04_v4_stale_out_closed_in")
int v4_stale_out_closed_in_check(const struct __ctx_buff *ctx)
{
	return check_v4(ctx, FRONTEND_IP, FRONTEND_PORT);
}

PKTGEN(PROG_TYPE, "05_v4_stale_out_proxy_in")
int v4_stale_out_proxy_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v4(ctx);
}

SETUP(PROG_TYPE, "05_v4_stale_out_proxy_in")
int v4_stale_out_proxy_in_setup(struct __ctx_buff *ctx)
{
	return setup_v4(ctx, true, INGRESS_PROXY);
}

CHECK(PROG_TYPE, "05_v4_stale_out_proxy_in")
int v4_stale_out_proxy_in_check(const struct __ctx_buff *ctx)
{
	return check_v4(ctx, FRONTEND_IP, FRONTEND_PORT);
}

PKTGEN(PROG_TYPE, "06_v6_stale_out_live_in")
int v6_stale_out_live_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v6(ctx);
}

SETUP(PROG_TYPE, "06_v6_stale_out_live_in")
int v6_stale_out_live_in_setup(struct __ctx_buff *ctx)
{
	return setup_v6(ctx, true, INGRESS_LIVE);
}

CHECK(PROG_TYPE, "06_v6_stale_out_live_in")
int v6_stale_out_live_in_check(const struct __ctx_buff *ctx)
{
	return check_v6(ctx, (union v6addr *)BACKEND_IPV6, BACKEND_PORT);
}

PKTGEN(PROG_TYPE, "07_v6_half_closed_out_half_closed_in")
int v6_half_closed_out_half_closed_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v6(ctx);
}

SETUP(PROG_TYPE, "07_v6_half_closed_out_half_closed_in")
int v6_half_closed_out_half_closed_in_setup(struct __ctx_buff *ctx)
{
	return setup_v6(ctx, false, INGRESS_HALF_CLOSED);
}

CHECK(PROG_TYPE, "07_v6_half_closed_out_half_closed_in")
int v6_half_closed_out_half_closed_in_check(const struct __ctx_buff *ctx)
{
	return check_v6(ctx, (union v6addr *)FRONTEND_IPV6, FRONTEND_PORT);
}

PKTGEN(PROG_TYPE, "08_v6_stale_out_half_closed_in")
int v6_stale_out_half_closed_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v6(ctx);
}

SETUP(PROG_TYPE, "08_v6_stale_out_half_closed_in")
int v6_stale_out_half_closed_in_setup(struct __ctx_buff *ctx)
{
	return setup_v6(ctx, true, INGRESS_HALF_CLOSED);
}

CHECK(PROG_TYPE, "08_v6_stale_out_half_closed_in")
int v6_stale_out_half_closed_in_check(const struct __ctx_buff *ctx)
{
	return check_v6(ctx, (union v6addr *)BACKEND_IPV6, BACKEND_PORT);
}

PKTGEN(PROG_TYPE, "09_v6_stale_out_closed_in")
int v6_stale_out_closed_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v6(ctx);
}

SETUP(PROG_TYPE, "09_v6_stale_out_closed_in")
int v6_stale_out_closed_in_setup(struct __ctx_buff *ctx)
{
	return setup_v6(ctx, true, INGRESS_CLOSED);
}

CHECK(PROG_TYPE, "09_v6_stale_out_closed_in")
int v6_stale_out_closed_in_check(const struct __ctx_buff *ctx)
{
	return check_v6(ctx, (union v6addr *)FRONTEND_IPV6, FRONTEND_PORT);
}

PKTGEN(PROG_TYPE, "10_v6_stale_out_proxy_in")
int v6_stale_out_proxy_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v6(ctx);
}

SETUP(PROG_TYPE, "10_v6_stale_out_proxy_in")
int v6_stale_out_proxy_in_setup(struct __ctx_buff *ctx)
{
	return setup_v6(ctx, true, INGRESS_PROXY);
}

CHECK(PROG_TYPE, "10_v6_stale_out_proxy_in")
int v6_stale_out_proxy_in_check(const struct __ctx_buff *ctx)
{
	return check_v6(ctx, (union v6addr *)FRONTEND_IPV6, FRONTEND_PORT);
}
