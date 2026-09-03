// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT

/* A completed NodePort/HostPort flow leaves a fully closed TUPLE_F_OUT CT
 * entry whose post-DNAT 5-tuple collides with a new direct connection to the
 * same backend, which keys TUPLE_F_IN. Assert that to-netdev prefers the live
 * TUPLE_F_IN entry and skips the reverse NAT (issue 47396), and that the
 * narrower cases keep the existing behaviour.
 */

#define CLIENT_IP		v4_pod_one
#define CLIENT_IPV6		v6_pod_one
#define CLIENT_PORT		__bpf_htons(53758)

/* Stands in for the HostPort frontend of the backend pod. */
#define FRONTEND_IP		v4_node_one
#define FRONTEND_IPV6		v6_node_one
#define FRONTEND_PORT		__bpf_htons(4000)

#define BACKEND_IP		v4_pod_two
#define BACKEND_IPV6		v6_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define DEFAULT_IFACE		24

#define REVNAT_ID		109

#define fib_lookup mock_fib_lookup

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *backend_mac = mac_four;

long mock_fib_lookup(__maybe_unused struct __ctx_buff * volatile ctx,
		     struct bpf_fib_lookup *params, __maybe_unused int plen,
		     __maybe_unused __u32 flags)
{
	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;

	/* Stay on the ingress interface, so that the packet is not redirected. */
	params->ifindex = DEFAULT_IFACE;
	__bpf_memcpy_builtin(params->smac, (__u8 *)node_mac, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);

	return 0;
}

#include "lib/bpf_host.h"

#include "lib/clear.h"
#include "lib/lb.h"

ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)

/* Set port ranges to have deterministic source port selection */
#include "nodeport_defaults.h"

/* Build the reply that the backend sends to the client. */
static __always_inline int build_reply_v4(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)backend_mac, (__u8 *)node_mac,
					  BACKEND_IP, CLIENT_IP,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 0;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int build_reply_v6(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)backend_mac, (__u8 *)node_mac,
					  (__u8 *)BACKEND_IPV6, (__u8 *)CLIENT_IPV6,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 0;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* Seed the CT state that the reply will be matched against:
 * a node_port TUPLE_F_OUT entry, closed as requested, plus optionally a live
 * TUPLE_F_IN entry on the very same 5-tuple.
 */
static __always_inline int
setup_v4(struct __ctx_buff *ctx, bool fully_closed, bool add_live_in)
{
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.saddr = BACKEND_IP,
		.daddr = CLIENT_IP,
		.sport = CLIENT_PORT,
		.dport = BACKEND_PORT,
		.flags = TUPLE_F_OUT,
	};
	struct ct_state nodeport_state = {
		.node_port = 1,
		.rev_nat_index = REVNAT_ID,
	};
	struct ct_state direct_state = {};
	struct ct_entry *entry;

	clear_map(&cilium_metrics);
	clear_map(&cilium_ct4_global);

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, REVNAT_ID);

	if (ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx, CT_EGRESS,
		       &nodeport_state, NULL))
		return TEST_ERROR;

	entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!entry)
		return TEST_ERROR;

	entry->rx_closing = 1;
	entry->tx_closing = fully_closed ? 1 : 0;

	if (add_live_in) {
		tuple.flags = TUPLE_F_IN;

		if (ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx, CT_INGRESS,
			       &direct_state, NULL))
			return TEST_ERROR;
	}

	return netdev_send_packet(ctx);
}

static __always_inline int
setup_v6(struct __ctx_buff *ctx, bool fully_closed, bool add_live_in)
{
	union v6addr frontend_ip = {};
	struct ipv6_ct_tuple tuple __align_stack_8 = {
		.nexthdr = IPPROTO_TCP,
		.sport = CLIENT_PORT,
		.dport = BACKEND_PORT,
		.flags = TUPLE_F_OUT,
	};
	struct ct_state nodeport_state = {
		.node_port = 1,
		.rev_nat_index = REVNAT_ID,
	};
	struct ct_state direct_state = {};
	struct ct_entry *entry;

	ipv6_addr_copy(&frontend_ip, (const union v6addr *)FRONTEND_IPV6);
	ipv6_addr_copy(&tuple.saddr, (const union v6addr *)BACKEND_IPV6);
	ipv6_addr_copy(&tuple.daddr, (const union v6addr *)CLIENT_IPV6);

	clear_map(&cilium_metrics);
	clear_map(&cilium_ct6_global);

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_TCP, 1, REVNAT_ID);

	if (ct_create6(get_ct_map6(&tuple), NULL, &tuple, ctx, CT_EGRESS,
		       &nodeport_state, NULL))
		return TEST_ERROR;

	entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	if (!entry)
		return TEST_ERROR;

	entry->rx_closing = 1;
	entry->tx_closing = fully_closed ? 1 : 0;

	if (add_live_in) {
		tuple.flags = TUPLE_F_IN;

		if (ct_create6(get_ct_map6(&tuple), NULL, &tuple, ctx, CT_INGRESS,
			       &direct_state, NULL))
			return TEST_ERROR;
	}

	return netdev_send_packet(ctx);
}

static __always_inline int
check_v4(const struct __ctx_buff *ctx, bool revnated)
{
	struct metrics_key key = {
		.reason = REASON_LB_REVNAT_SKIP_STALE,
		.dir = METRIC_EGRESS,
	};
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->daddr != CLIENT_IP)
		test_fatal("dst IP has changed");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port has changed");

	if (revnated) {
		if (l3->saddr != FRONTEND_IP)
			test_fatal("src IP hasn't been RevNATed to frontend IP");

		if (l4->source != FRONTEND_PORT)
			test_fatal("src port hasn't been RevNATed to frontend port");

		assert_metrics_count(key, 0);
	} else {
		if (l3->saddr != BACKEND_IP)
			test_fatal("src IP has been RevNATed via a stale CT entry");

		if (l4->source != BACKEND_PORT)
			test_fatal("src port has been RevNATed via a stale CT entry");

		assert_metrics_count(key, 1);
	}

	test_finish();
}

static __always_inline int
check_v6(const struct __ctx_buff *ctx, bool revnated)
{
	struct metrics_key key = {
		.reason = REASON_LB_REVNAT_SKIP_STALE,
		.dir = METRIC_EGRESS,
	};
	union v6addr frontend_ip = {};
	union v6addr backend_ip = {};
	union v6addr client_ip = {};
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	struct ethhdr *l2;

	test_init();

	ipv6_addr_copy(&frontend_ip, (const union v6addr *)FRONTEND_IPV6);
	ipv6_addr_copy(&backend_ip, (const union v6addr *)BACKEND_IPV6);
	ipv6_addr_copy(&client_ip, (const union v6addr *)CLIENT_IPV6);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &client_ip))
		test_fatal("dst IP has changed");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port has changed");

	if (revnated) {
		if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &frontend_ip))
			test_fatal("src IP hasn't been RevNATed to frontend IP");

		if (l4->source != FRONTEND_PORT)
			test_fatal("src port hasn't been RevNATed to frontend port");

		assert_metrics_count(key, 0);
	} else {
		if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &backend_ip))
			test_fatal("src IP has been RevNATed via a stale CT entry");

		if (l4->source != BACKEND_PORT)
			test_fatal("src port has been RevNATed via a stale CT entry");

		assert_metrics_count(key, 1);
	}

	test_finish();
}

/* Case (a): fully closed node_port TUPLE_F_OUT entry colliding with a live
 * TUPLE_F_IN entry. The reply belongs to the live connection, so it must
 * egress unmodified.
 */
PKTGEN("tc", "01_v4_stale_out_live_in")
int v4_stale_out_live_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v4(ctx);
}

SETUP("tc", "01_v4_stale_out_live_in")
int v4_stale_out_live_in_setup(struct __ctx_buff *ctx)
{
	return setup_v4(ctx, true, true);
}

CHECK("tc", "01_v4_stale_out_live_in")
int v4_stale_out_live_in_check(const struct __ctx_buff *ctx)
{
	return check_v4(ctx, false);
}

/* Case (b): the node_port TUPLE_F_OUT entry is only half closed, so it is
 * still alive and owns the reply even though a TUPLE_F_IN entry exists.
 */
PKTGEN("tc", "02_v4_half_closed_out_live_in")
int v4_half_closed_out_live_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v4(ctx);
}

SETUP("tc", "02_v4_half_closed_out_live_in")
int v4_half_closed_out_live_in_setup(struct __ctx_buff *ctx)
{
	return setup_v4(ctx, false, true);
}

CHECK("tc", "02_v4_half_closed_out_live_in")
int v4_half_closed_out_live_in_check(const struct __ctx_buff *ctx)
{
	return check_v4(ctx, true);
}

/* Case (c): fully closed node_port TUPLE_F_OUT entry with no competing
 * TUPLE_F_IN entry. Nothing else can own the reply, so keep reverse NATing it.
 */
PKTGEN("tc", "03_v4_stale_out_no_in")
int v4_stale_out_no_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v4(ctx);
}

SETUP("tc", "03_v4_stale_out_no_in")
int v4_stale_out_no_in_setup(struct __ctx_buff *ctx)
{
	return setup_v4(ctx, true, false);
}

CHECK("tc", "03_v4_stale_out_no_in")
int v4_stale_out_no_in_check(const struct __ctx_buff *ctx)
{
	return check_v4(ctx, true);
}

PKTGEN("tc", "04_v6_stale_out_live_in")
int v6_stale_out_live_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v6(ctx);
}

SETUP("tc", "04_v6_stale_out_live_in")
int v6_stale_out_live_in_setup(struct __ctx_buff *ctx)
{
	return setup_v6(ctx, true, true);
}

CHECK("tc", "04_v6_stale_out_live_in")
int v6_stale_out_live_in_check(const struct __ctx_buff *ctx)
{
	return check_v6(ctx, false);
}

PKTGEN("tc", "05_v6_half_closed_out_live_in")
int v6_half_closed_out_live_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v6(ctx);
}

SETUP("tc", "05_v6_half_closed_out_live_in")
int v6_half_closed_out_live_in_setup(struct __ctx_buff *ctx)
{
	return setup_v6(ctx, false, true);
}

CHECK("tc", "05_v6_half_closed_out_live_in")
int v6_half_closed_out_live_in_check(const struct __ctx_buff *ctx)
{
	return check_v6(ctx, true);
}

PKTGEN("tc", "06_v6_stale_out_no_in")
int v6_stale_out_no_in_pktgen(struct __ctx_buff *ctx)
{
	return build_reply_v6(ctx);
}

SETUP("tc", "06_v6_stale_out_no_in")
int v6_stale_out_no_in_setup(struct __ctx_buff *ctx)
{
	return setup_v6(ctx, true, false);
}

CHECK("tc", "06_v6_stale_out_no_in")
int v6_stale_out_no_in_check(const struct __ctx_buff *ctx)
{
	return check_v6(ctx, true);
}
