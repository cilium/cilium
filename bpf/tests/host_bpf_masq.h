// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4			1
#define ENABLE_IPV6			1

#define ENABLE_MASQUERADE_IPV4		1
#define ENABLE_MASQUERADE_IPV6		1

#define ENABLE_NODEPORT			1

#define NODE_IP				v4_node_one
#define NODE_IP_V6			v6_node_one
#define NODE_PORT			bpf_htons(50000)

#define SERVER_IP			v4_ext_one
#define SERVER_IP_V6			v6_ext_node_one
#define SERVER_PORT			bpf_htons(80)

#include <bpf/config/node.h>

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "lib/bpf_host.h"

ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, { .be32 = NODE_IP})
ASSIGN_CONFIG(union v6addr, nat_ipv6_masquerade, { .addr = v6_node_one_addr})

ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

#include "lib/endpoint.h"
#include "lib/ipcache.h"

/* Host-originating UDP should be tracked by BPF Masq. */
PKTGEN("tc", "host_bpf_masq_v4_1_udp")
int host_bpf_masq_v4_1_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   NODE_IP, SERVER_IP,
					   NODE_PORT, SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "host_bpf_masq_v4_1_udp")
int host_bpf_masq_v4_1_udp_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(NODE_IP, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      0, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(NODE_IP, 0, HOST_ID, 0, 0);
	ipcache_v4_add_world_entry();

	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_bpf_masq_v4_1_udp")
int host_bpf_masq_v4_1_udp_check(const struct __ctx_buff *ctx)
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

	/* Check whether BPF MASQ created a CT entry */
	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = SERVER_IP,
		.dport   = SERVER_PORT,
		.sport   = NODE_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	assert(ct_entry->packets == 1);

	test_finish();
}

PKTGEN("tc", "host_bpf_masq_v6_1_udp")
int host_bpf_masq_v6_1_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv6_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   (__u8 *)NODE_IP_V6, (__u8 *)SERVER_IP_V6,
					   NODE_PORT, SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "host_bpf_masq_v6_1_udp")
int host_bpf_masq_v6_1_udp_setup(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)NODE_IP_V6, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry((union v6addr *)NODE_IP_V6, 0, HOST_ID, 0, 0);
	ipcache_v6_add_world_entry();

	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_bpf_masq_v6_1_udp")
int host_bpf_masq_v6_1_udp_check(const struct __ctx_buff *ctx)
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

	/* Check whether BPF MASQ created a CT entry */
	struct ipv6_ct_tuple tuple = {
		.dport   = SERVER_PORT,
		.sport   = NODE_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags = TUPLE_F_OUT,
	};
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)NODE_IP_V6);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)SERVER_IP_V6);

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	assert(ct_entry->packets == 1);

	test_finish();
}

/* Host-originating IPIP should be skipped by BPF Masq. */
PKTGEN("tc", "host_bpf_masq_v4_2_ipip")
int host_bpf_masq_v4_2_ipip_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *ip4;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	ip4 = pktgen__push_ipv4_packet(&builder,
				       (__u8 *)node_mac, (__u8 *)server_mac,
				       NODE_IP, SERVER_IP);
	if (!ip4)
		return TEST_ERROR;

	ip4->protocol = IPPROTO_IPIP;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "host_bpf_masq_v4_2_ipip")
int host_bpf_masq_v4_2_ipip_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_bpf_masq_v4_2_ipip")
int host_bpf_masq_v4_2_ipip_check(const struct __ctx_buff *ctx)
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

	test_finish();
}

PKTGEN("tc", "host_bpf_masq_v6_2_ipip")
int host_bpf_masq_v6_2_ipip_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6hdr *ip6;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	ip6 = pktgen__push_ipv6_packet(&builder,
				       (__u8 *)node_mac, (__u8 *)server_mac,
				       (__u8 *)NODE_IP_V6, (__u8 *)SERVER_IP_V6);
	if (!ip6)
		return TEST_ERROR;

	ip6->nexthdr = IPPROTO_IPIP;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "host_bpf_masq_v6_2_ipip")
int host_bpf_masq_v6_2_ipip_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_bpf_masq_v6_2_ipip")
int host_bpf_masq_v6_2_ipip_check(const struct __ctx_buff *ctx)
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

	test_finish();
}

/* Host-originating unhandled ICMP should be dropped by BPF Masq. */
PKTGEN("tc", "host_bpf_masq_v4_3_icmp_unhandled")
int host_bpf_masq_v4_3_icmp_unhandled_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmphdr *icmp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	icmp = pktgen__push_ipv4_icmp_packet(&builder,
					     (__u8 *)node_mac, (__u8 *)server_mac,
					     NODE_IP, SERVER_IP,
					     ICMP_TIMESTAMP);
	if (!icmp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "host_bpf_masq_v4_3_icmp_unhandled")
int host_bpf_masq_v4_3_icmp_unhandledp_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_bpf_masq_v4_3_icmp_unhandled")
int host_bpf_masq_v4_3_icmp_timestamp_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_DROP);

	test_finish();
}

PKTGEN("tc", "host_bpf_masq_v6_3_icmp_unhandled")
int host_bpf_masq_v6_3_icmp_unhandled_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *icmp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	icmp = pktgen__push_ipv6_icmp6_packet(&builder,
					      (__u8 *)node_mac, (__u8 *)server_mac,
					      (__u8 *)NODE_IP_V6, (__u8 *)SERVER_IP_V6,
					      ICMPV6_PARAMPROB);
	if (!icmp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "host_bpf_masq_v6_3_icmp_unhandled")
int host_bpf_masq_v6_3_icmp_unhandled_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_bpf_masq_v6_3_icmp_unhandled")
int host_bpf_masq_v6_3_icmp_unhandled_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_DROP);

	test_finish();
}

/* Host-originating ICMP ECHO should be tracked by BPF Masq. */
PKTGEN("tc", "host_bpf_masq_v4_4_icmp_echo")
int host_bpf_masq_v4_4_icmp_echo_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmphdr *icmp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	icmp = pktgen__push_ipv4_icmp_packet(&builder,
					     (__u8 *)node_mac, (__u8 *)server_mac,
					     NODE_IP, SERVER_IP,
					     ICMP_ECHO);
	if (!icmp)
		return TEST_ERROR;

	icmp->un.echo.id = bpf_htons(nat_min_egress() - 1);

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "host_bpf_masq_v4_4_icmp_echo")
int host_bpf_masq_v4_4_icmp_echo_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_bpf_masq_v4_4_icmp_echo")
int host_bpf_masq_v4_4_icmp_echo_check(const struct __ctx_buff *ctx)
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

	/* Check whether BPF MASQ created a CT entry */
	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = SERVER_IP,
		.dport   = 0,
		.sport   = bpf_htons(nat_min_egress() - 1),
		.nexthdr = IPPROTO_ICMP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	assert(ct_entry->packets == 1);

	test_finish();
}

PKTGEN("tc", "host_bpf_masq_v6_4_icmp_echo")
int host_bpf_masq_v6_4_icmp_echo_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *icmp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	icmp = pktgen__push_ipv6_icmp6_packet(&builder,
					      (__u8 *)node_mac, (__u8 *)server_mac,
					      (__u8 *)NODE_IP_V6, (__u8 *)SERVER_IP_V6,
					      ICMPV6_ECHO_REQUEST);
	if (!icmp)
		return TEST_ERROR;

	icmp->icmp6_dataun.u_echo.identifier = bpf_htons(nat_min_egress() - 1);

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "host_bpf_masq_v6_4_icmp_echo")
int host_bpf_masq_v6_4_icmp_echo_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_bpf_masq_v6_4_icmp_echo")
int host_bpf_masq_v6_4_icmp_echo_check(const struct __ctx_buff *ctx)
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

	/* Check whether BPF MASQ created a CT entry */
	struct ipv6_ct_tuple tuple = {
		.dport   = 0,
		.sport   = bpf_htons(nat_min_egress() - 1),
		.nexthdr = IPPROTO_ICMPV6,
		.flags = TUPLE_F_OUT,
	};
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)NODE_IP_V6);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)SERVER_IP_V6);

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	assert(ct_entry->packets == 1);

	test_finish();
}

/* NO_SNAT endpoints should not be masqueraded */
PKTGEN("tc", "host_bpf_masq_v4_5_no_snat_ep_udp")
int host_bpf_masq_v4_5_no_snat_ep_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	pktgen__init(&builder, ctx);

	/* generate packet from local endpoint to world */
	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   v4_pod_one, SERVER_IP,
					   bpf_htons(12345), SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "host_bpf_masq_v4_5_no_snat_ep_udp")
int host_bpf_masq_v4_5_no_snat_ep_udp_setup(struct __ctx_buff *ctx)
{
	/* mark the source IP as a local endpoint with NO_SNAT flag */
	endpoint_v4_add_entry(v4_pod_one, 0, 0, ENDPOINT_F_NO_SNAT_V4, 0, 0, NULL, NULL);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_bpf_masq_v4_5_no_snat_ep_udp")
int host_bpf_masq_v4_5_no_snat_ep_udp_check(const struct __ctx_buff *ctx)
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

	/* traverse data to find the packet */
	data += sizeof(__u32);
	if (data + sizeof(struct ethhdr) > data_end)
		test_fatal("ctx doesn't fit ethhdr");
	data += sizeof(struct ethhdr);
	if (data + sizeof(struct iphdr) > data_end)
		test_fatal("ctx doesn't fit iphdr");
	struct iphdr *ip4 = data;
	/* source IP should stay the same */
	assert(ip4->saddr == v4_pod_one);
	test_finish();
}

PKTGEN("tc", "host_bpf_masq_v6_5_no_snat_ep_udp")
int host_bpf_masq_v6_5_no_snat_ep_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	pktgen__init(&builder, ctx);

	/* generate packet from local endpoint to world */
	udp = pktgen__push_ipv6_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   (__u8 *)v6_pod_one, (__u8 *)SERVER_IP_V6,
					   bpf_htons(12345), SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "host_bpf_masq_v6_5_no_snat_ep_udp")
int host_bpf_masq_v6_5_no_snat_ep_udp_setup(struct __ctx_buff *ctx)
{
	/* mark the source IP as a local endpoint with NO_SNAT flag */
	endpoint_v6_add_entry((union v6addr *)v6_pod_one,
			      0,
			      0,
			      ENDPOINT_F_NO_SNAT_V6,
			      0,
			      NULL,
			      NULL);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_bpf_masq_v6_5_no_snat_ep_udp")
int host_bpf_masq_v6_5_no_snat_ep_udp_check(const struct __ctx_buff *ctx)
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

	data += sizeof(__u32);
	if (data + sizeof(struct ethhdr) > data_end)
		test_fatal("ctx doesn't fit ethhdr");
	data += sizeof(struct ethhdr);
	if (data + sizeof(struct ipv6hdr) > data_end)
		test_fatal("ctx doesn't fit ipv6hdr");
	/* source IP should stay the same */
	struct ipv6hdr *ip6 = data;
	{
		const __u8 expected_v6_pod_one[16] = v6_pod_one_addr;

		assert(!memcmp(&ip6->saddr, expected_v6_pod_one, 16));
	}

	test_finish();
}

/* Regular endpoints (without NO_SNAT) should be masqueraded */
PKTGEN("tc", "host_bpf_masq_v4_6_snat_ep_udp")
int host_bpf_masq_v4_6_snat_ep_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	pktgen__init(&builder, ctx);

	/* generate packet from local endpoint to world */
	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   v4_pod_one, SERVER_IP,
					   bpf_htons(12345), SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "host_bpf_masq_v4_6_snat_ep_udp")
int host_bpf_masq_v4_6_snat_ep_udp_setup(struct __ctx_buff *ctx)
{
	/* mark the source IP as a local endpoint without NO_SNAT flag */
	endpoint_v4_add_entry(v4_pod_one, 0, 0, 0, 0, 0, NULL, NULL);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_bpf_masq_v4_6_snat_ep_udp")
int host_bpf_masq_v4_6_snat_ep_udp_check(const struct __ctx_buff *ctx)
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

	data += sizeof(__u32);
	if (data + sizeof(struct ethhdr) > data_end)
		test_fatal("ctx doesn't fit ethhdr");
	data += sizeof(struct ethhdr);
	if (data + sizeof(struct iphdr) > data_end)
		test_fatal("ctx doesn't fit iphdr");
	struct iphdr *ip4 = data;
	/* source IP should be masqueraded to NODE_IP */
	assert(ip4->saddr == NODE_IP);
	test_finish();
}

PKTGEN("tc", "host_bpf_masq_v6_6_snat_ep_udp")
int host_bpf_masq_v6_6_snat_ep_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	pktgen__init(&builder, ctx);

	/* generate packet from local endpoint to world */
	udp = pktgen__push_ipv6_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   (__u8 *)v6_pod_one, (__u8 *)SERVER_IP_V6,
					   bpf_htons(12345), SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "host_bpf_masq_v6_6_snat_ep_udp")
int host_bpf_masq_v6_6_snat_ep_udp_setup(struct __ctx_buff *ctx)
{
	/* mark the source IP as a local endpoint without NO_SNAT flag */
	endpoint_v6_add_entry((union v6addr *)v6_pod_one, 0, 0, 0, 0, NULL, NULL);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_bpf_masq_v6_6_snat_ep_udp")
int host_bpf_masq_v6_6_snat_ep_udp_check(const struct __ctx_buff *ctx)
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

	data += sizeof(__u32);
	if (data + sizeof(struct ethhdr) > data_end)
		test_fatal("ctx doesn't fit ethhdr");
	data += sizeof(struct ethhdr);
	if (data + sizeof(struct ipv6hdr) > data_end)
		test_fatal("ctx doesn't fit ipv6hdr");
	/* source IP should be masqueraded to NODE_IP_V6 */
	struct ipv6hdr *ip6 = data;
	{
		const __u8 expected_node_ip_v6[16] = v6_node_one_addr;

		assert(!memcmp(&ip6->saddr, expected_node_ip_v6, 16));
	}

	test_finish();
}
