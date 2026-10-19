// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define ENABLE_NODEPORT		1

/* GH#47396: replies on a tuple that has both a node_port TUPLE_F_OUT entry
 * and a TUPLE_F_IN entry. With a local backend, a NodePort connection has
 * both entries, so most of these must keep being RevDNATed. r21-r24 cover a
 * direct connection reusing the tuple of a closed NodePort one.
 */

#define CLIENT_IP		v4_ext_one
#define CLIENT_IPV6		v6_ext_node_one
#define CLIENT_PORT		__bpf_htons(53758)

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_IPV6		v6_svc_one
#define FRONTEND_PORT		__bpf_htons(30080)

#define BACKEND_IP		v4_pod_one
#define BACKEND_IPV6		v6_pod_one
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

#include "nodeport_defaults.h"

/* Client FIN sets tx_closing on OUT, backend FIN sets rx_closing. */
enum out_state {
	OUT_SYN,		/* new NodePort flow, only the client SYN seen */
	OUT_LIVE,		/* established */
	OUT_HALF,		/* client FIN seen (tx_closing) */
	OUT_RX_HALF,		/* backend FIN seen (rx_closing) */
	OUT_CLOSED,		/* both FINs seen */
};

/* Client FIN sets rx_closing on IN, backend FIN sets tx_closing. */
enum in_state {
	IN_NONE,
	IN_LIVE,		/* established, same NodePort flow (normal) */
	IN_HALF,		/* client FIN seen (rx_closing) */
	IN_TX_HALF,		/* backend FIN seen (tx_closing) */
	IN_CLOSED,		/* both FINs seen */
	IN_PROXY,		/* live, redirected to the L7 proxy */
	IN_DIRECT_SYN,		/* new direct flow, only the client SYN seen */
};

enum reply_kind {
	REPLY_ACK,
	REPLY_FIN_ACK,
	REPLY_UDP,
	REPLY_SYN_ACK,
};

static __always_inline void set_tcp_flags(struct tcphdr *l4, enum reply_kind kind)
{
	l4->syn = kind == REPLY_SYN_ACK;
	l4->fin = kind == REPLY_FIN_ACK;
	l4->ack = 1;
}

/* Reply from the local backend to the client. */
static __always_inline int build_reply_v4(struct __ctx_buff *ctx, enum reply_kind kind)
{
	struct pktgen builder;
	void *data;

	pktgen__init(&builder, ctx);

	if (kind == REPLY_UDP) {
		if (!pktgen__push_ipv4_udp_packet(&builder,
						  (__u8 *)backend_mac, (__u8 *)node_mac,
						  BACKEND_IP, CLIENT_IP,
						  BACKEND_PORT, CLIENT_PORT))
			return TEST_ERROR;
	} else {
		struct tcphdr *l4;

		l4 = pktgen__push_ipv4_tcp_packet(&builder,
						  (__u8 *)backend_mac, (__u8 *)node_mac,
						  BACKEND_IP, CLIENT_IP,
						  BACKEND_PORT, CLIENT_PORT);
		if (!l4)
			return TEST_ERROR;
		set_tcp_flags(l4, kind);
	}

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int build_reply_v6(struct __ctx_buff *ctx, enum reply_kind kind)
{
	struct pktgen builder;
	void *data;

	pktgen__init(&builder, ctx);

	if (kind == REPLY_UDP) {
		if (!pktgen__push_ipv6_udp_packet(&builder,
						  (__u8 *)backend_mac, (__u8 *)node_mac,
						  (__u8 *)BACKEND_IPV6, (__u8 *)CLIENT_IPV6,
						  BACKEND_PORT, CLIENT_PORT))
			return TEST_ERROR;
	} else {
		struct tcphdr *l4;

		l4 = pktgen__push_ipv6_tcp_packet(&builder,
						  (__u8 *)backend_mac, (__u8 *)node_mac,
						  (__u8 *)BACKEND_IPV6, (__u8 *)CLIENT_IPV6,
						  BACKEND_PORT, CLIENT_PORT);
		if (!l4)
			return TEST_ERROR;
		set_tcp_flags(l4, kind);
	}

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline void shape_out(struct ct_entry *e, enum out_state out)
{
	e->seen_non_syn = out != OUT_SYN;
	e->tx_closing = out == OUT_HALF || out == OUT_CLOSED;
	e->rx_closing = out == OUT_RX_HALF || out == OUT_CLOSED;
}

static __always_inline void shape_in(struct ct_entry *e, enum in_state in)
{
	e->seen_non_syn = in != IN_DIRECT_SYN;
	e->rx_closing = in == IN_HALF || in == IN_CLOSED;
	e->tx_closing = in == IN_TX_HALF || in == IN_CLOSED;
}

/* Create OUT (and optionally IN), then send the backend's reply. */
static __always_inline int
setup_v4(struct __ctx_buff *ctx, __u8 proto, enum out_state out, enum in_state in)
{
	struct ipv4_ct_tuple tuple = {
		.nexthdr = proto,
		.saddr = BACKEND_IP,
		.daddr = CLIENT_IP,
		.sport = CLIENT_PORT,
		.dport = BACKEND_PORT,
		.flags = TUPLE_F_OUT,
	};
	struct ct_state np_state = {
		.node_port = 1,
		.rev_nat_index = REVNAT_ID,
	};
	struct ct_state in_state = {
		.proxy_redirect = in == IN_PROXY,
	};
	struct ct_entry *entry;

	clear_map(&cilium_metrics);
	clear_map(&cilium_ct4_global);

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, proto, 1, REVNAT_ID);

	if (ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx, CT_EGRESS,
		       &np_state, NULL))
		return TEST_ERROR;
	entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!entry)
		return TEST_ERROR;
	shape_out(entry, out);

	if (in != IN_NONE) {
		tuple.flags = TUPLE_F_IN;
		if (ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx, CT_INGRESS,
			       &in_state, NULL))
			return TEST_ERROR;
		entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
		if (!entry)
			return TEST_ERROR;
		shape_in(entry, in);
	}

	return netdev_send_packet(ctx);
}

static __always_inline int
setup_v6(struct __ctx_buff *ctx, __u8 proto, enum out_state out, enum in_state in)
{
	union v6addr frontend_ip = {};
	struct ipv6_ct_tuple tuple __align_stack_8 = {
		.nexthdr = proto,
		.sport = CLIENT_PORT,
		.dport = BACKEND_PORT,
		.flags = TUPLE_F_OUT,
	};
	struct ct_state np_state = {
		.node_port = 1,
		.rev_nat_index = REVNAT_ID,
	};
	struct ct_state in_state = {
		.proxy_redirect = in == IN_PROXY,
	};
	struct ct_entry *entry;

	ipv6_addr_copy(&frontend_ip, (const union v6addr *)FRONTEND_IPV6);
	ipv6_addr_copy(&tuple.saddr, (const union v6addr *)BACKEND_IPV6);
	ipv6_addr_copy(&tuple.daddr, (const union v6addr *)CLIENT_IPV6);

	clear_map(&cilium_metrics);
	clear_map(&cilium_ct6_global);

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, proto, 1, REVNAT_ID);

	if (ct_create6(get_ct_map6(&tuple), NULL, &tuple, ctx, CT_EGRESS,
		       &np_state, NULL))
		return TEST_ERROR;
	entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	if (!entry)
		return TEST_ERROR;
	shape_out(entry, out);

	if (in != IN_NONE) {
		tuple.flags = TUPLE_F_IN;
		if (ct_create6(get_ct_map6(&tuple), NULL, &tuple, ctx, CT_INGRESS,
			       &in_state, NULL))
			return TEST_ERROR;
		entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
		if (!entry)
			return TEST_ERROR;
		shape_in(entry, in);
	}

	return netdev_send_packet(ctx);
}

/* Reply must have the frontend as source. */
static __always_inline int check_revnat_v4(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code;
	struct iphdr *l3;
	__be16 *ports;

	test_init();

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	/* sport/dport sit at the same offset for TCP and UDP */
	ports = (void *)l3 + sizeof(struct iphdr);
	if ((void *)ports + 2 * sizeof(__be16) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != FRONTEND_IP)
		test_fatal("src IP was not RevDNATed to the frontend");
	if (ports[0] != FRONTEND_PORT)
		test_fatal("src port was not RevDNATed to the frontend");
	if (l3->daddr != CLIENT_IP)
		test_fatal("dst IP has changed");
	if (ports[1] != CLIENT_PORT)
		test_fatal("dst port has changed");

	test_finish();
}

static __always_inline int check_revnat_v6(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	union v6addr frontend_ip = {}, client_ip = {};
	__u32 *status_code;
	struct ipv6hdr *l3;
	__be16 *ports;

	test_init();

	ipv6_addr_copy(&frontend_ip, (const union v6addr *)FRONTEND_IPV6);
	ipv6_addr_copy(&client_ip, (const union v6addr *)CLIENT_IPV6);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	ports = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)ports + 2 * sizeof(__be16) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &frontend_ip))
		test_fatal("src IP was not RevDNATed to the frontend");
	if (ports[0] != FRONTEND_PORT)
		test_fatal("src port was not RevDNATed to the frontend");
	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &client_ip))
		test_fatal("dst IP has changed");
	if (ports[1] != CLIENT_PORT)
		test_fatal("dst port has changed");

	test_finish();
}

/* Reply must keep the backend as source. */
static __always_inline int check_no_revnat_v4(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code;
	struct iphdr *l3;
	__be16 *ports;

	test_init();

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	ports = (void *)l3 + sizeof(struct iphdr);
	if ((void *)ports + 2 * sizeof(__be16) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != BACKEND_IP)
		test_fatal("src IP was RevDNATed through the stale NodePort entry");
	if (ports[0] != BACKEND_PORT)
		test_fatal("src port was RevDNATed through the stale NodePort entry");
	if (l3->daddr != CLIENT_IP)
		test_fatal("dst IP has changed");
	if (ports[1] != CLIENT_PORT)
		test_fatal("dst port has changed");

	test_finish();
}

static __always_inline int check_no_revnat_v6(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	union v6addr backend_ip = {}, client_ip = {};
	__u32 *status_code;
	struct ipv6hdr *l3;
	__be16 *ports;

	test_init();

	ipv6_addr_copy(&backend_ip, (const union v6addr *)BACKEND_IPV6);
	ipv6_addr_copy(&client_ip, (const union v6addr *)CLIENT_IPV6);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	ports = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)ports + 2 * sizeof(__be16) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &backend_ip))
		test_fatal("src IP was RevDNATed through the stale NodePort entry");
	if (ports[0] != BACKEND_PORT)
		test_fatal("src port was RevDNATed through the stale NodePort entry");
	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &client_ip))
		test_fatal("dst IP has changed");
	if (ports[1] != CLIENT_PORT)
		test_fatal("dst port has changed");

	test_finish();
}

#define STALE_CT_TEST(NAME, FAM, KIND, PROTO, OUT, IN, CHECK_FN)		\
PKTGEN(PROG_TYPE, #NAME)							\
int NAME##_pktgen(struct __ctx_buff *ctx)					\
{										\
	return build_reply_##FAM(ctx, KIND);					\
}										\
SETUP(PROG_TYPE, #NAME)								\
int NAME##_setup(struct __ctx_buff *ctx)					\
{										\
	return setup_##FAM(ctx, PROTO, OUT, IN);				\
}										\
CHECK(PROG_TYPE, #NAME)								\
int NAME##_check(const struct __ctx_buff *ctx)					\
{										\
	return CHECK_FN##_##FAM(ctx);						\
}

#define REVNAT_TEST(NAME, FAM, KIND, PROTO, OUT, IN)				\
	STALE_CT_TEST(NAME, FAM, KIND, PROTO, OUT, IN, check_revnat)

#define NO_REVNAT_TEST(NAME, FAM, KIND, PROTO, OUT, IN)				\
	STALE_CT_TEST(NAME, FAM, KIND, PROTO, OUT, IN, check_no_revnat)

/* 01: established connection */
REVNAT_TEST(r01_v4_live_out_live_in, v4, REPLY_ACK, IPPROTO_TCP, OUT_LIVE, IN_LIVE)

/* 00: handshake */
REVNAT_TEST(r00_v4_syn_out_syn_in_synack, v4, REPLY_SYN_ACK, IPPROTO_TCP, OUT_SYN, IN_DIRECT_SYN)

/* 02: established connection, no IN entry */
REVNAT_TEST(r02_v4_live_out_no_in, v4, REPLY_ACK, IPPROTO_TCP, OUT_LIVE, IN_NONE)

/* 03: backend ACKs the client's FIN */
REVNAT_TEST(r03_v4_half_out_half_in_ack, v4, REPLY_ACK, IPPROTO_TCP, OUT_HALF, IN_HALF)
/* 04: backend FIN after the client's. IN is updated before OUT. */
REVNAT_TEST(r04_v4_half_out_closed_in_fin, v4, REPLY_FIN_ACK, IPPROTO_TCP, OUT_HALF, IN_CLOSED)

/* 05: client FIN hit OUT but not IN yet */
REVNAT_TEST(r05_v4_half_out_live_in, v4, REPLY_ACK, IPPROTO_TCP, OUT_HALF, IN_LIVE)

/* 06: backend retransmits its FIN */
REVNAT_TEST(r06_v4_closed_out_closed_in_fin, v4, REPLY_FIN_ACK, IPPROTO_TCP, OUT_CLOSED, IN_CLOSED)

/* 07: backend retransmits its FIN, no IN entry */
REVNAT_TEST(r07_v4_closed_out_no_in_fin, v4, REPLY_FIN_ACK, IPPROTO_TCP, OUT_CLOSED, IN_NONE)

/* 08a: backend closed first, ACKs client data */
REVNAT_TEST(r08a_v4_rxhalf_out_txhalf_in_ack, v4, REPLY_ACK, IPPROTO_TCP, OUT_RX_HALF, IN_TX_HALF)

/* 08: backend closed first, final ACK (also re-sent from TIME-WAIT) */
REVNAT_TEST(r08_v4_closed_out_closed_in_ack, v4, REPLY_ACK, IPPROTO_TCP, OUT_CLOSED, IN_CLOSED)

/* 09: IN is redirected to the L7 proxy */
REVNAT_TEST(r09_v4_closed_out_proxy_in, v4, REPLY_ACK, IPPROTO_TCP, OUT_CLOSED, IN_PROXY)

/* 10: UDP */
REVNAT_TEST(r10_v4_udp_live_out_live_in, v4, REPLY_UDP, IPPROTO_UDP, OUT_LIVE, IN_LIVE)

/* GH#47396: the client reuses the source port of a closed NodePort
 * connection to connect to the pod directly. The client's TIME_WAIT socket
 * doesn't block this, since the destination differs. The backend's socket
 * has the same tuple, and answers the new SYN from TIME_WAIT with a SYN-ACK.
 */

/* 21: backend SYN-ACK */
NO_REVNAT_TEST(r21_v4_closed_out_direct_syn_in_synack, v4, REPLY_SYN_ACK,
	       IPPROTO_TCP, OUT_CLOSED, IN_DIRECT_SYN)

/* 22: backend data */
NO_REVNAT_TEST(r22_v4_closed_out_direct_live_in_ack, v4, REPLY_ACK,
	       IPPROTO_TCP, OUT_CLOSED, IN_LIVE)

/* IPv6 */

REVNAT_TEST(r10b_v6_syn_out_syn_in_synack, v6, REPLY_SYN_ACK, IPPROTO_TCP, OUT_SYN, IN_DIRECT_SYN)
REVNAT_TEST(r11_v6_live_out_live_in, v6, REPLY_ACK, IPPROTO_TCP, OUT_LIVE, IN_LIVE)
REVNAT_TEST(r12_v6_live_out_no_in, v6, REPLY_ACK, IPPROTO_TCP, OUT_LIVE, IN_NONE)
REVNAT_TEST(r13_v6_half_out_half_in_ack, v6, REPLY_ACK, IPPROTO_TCP, OUT_HALF, IN_HALF)
REVNAT_TEST(r14_v6_half_out_closed_in_fin, v6, REPLY_FIN_ACK, IPPROTO_TCP, OUT_HALF, IN_CLOSED)
REVNAT_TEST(r15_v6_half_out_live_in, v6, REPLY_ACK, IPPROTO_TCP, OUT_HALF, IN_LIVE)
REVNAT_TEST(r16_v6_closed_out_closed_in_fin, v6, REPLY_FIN_ACK, IPPROTO_TCP, OUT_CLOSED, IN_CLOSED)
REVNAT_TEST(r17_v6_closed_out_no_in_fin, v6, REPLY_FIN_ACK, IPPROTO_TCP, OUT_CLOSED, IN_NONE)
REVNAT_TEST(r18a_v6_rxhalf_out_txhalf_in_ack, v6, REPLY_ACK, IPPROTO_TCP, OUT_RX_HALF, IN_TX_HALF)
REVNAT_TEST(r18_v6_closed_out_closed_in_ack, v6, REPLY_ACK, IPPROTO_TCP, OUT_CLOSED, IN_CLOSED)
REVNAT_TEST(r19_v6_closed_out_proxy_in, v6, REPLY_ACK, IPPROTO_TCP, OUT_CLOSED, IN_PROXY)
REVNAT_TEST(r20_v6_udp_live_out_live_in, v6, REPLY_UDP, IPPROTO_UDP, OUT_LIVE, IN_LIVE)
NO_REVNAT_TEST(r23_v6_closed_out_direct_syn_in_synack, v6, REPLY_SYN_ACK,
	       IPPROTO_TCP, OUT_CLOSED, IN_DIRECT_SYN)
NO_REVNAT_TEST(r24_v6_closed_out_direct_live_in_ack, v6, REPLY_ACK,
	       IPPROTO_TCP, OUT_CLOSED, IN_LIVE)
