// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define SERVICE_NO_BACKEND_RESPONSE
#define ENABLE_MASQUERADE_IPV4		1
#define ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY

#define CLIENT_IP		v4_ext_one
#define ICMP_ID			__bpf_htons(0x1234)

#define FRONTEND_IP		v4_svc_two
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

static volatile const __u8 *client_mac = mac_one;
/* this matches the default node_config.h: */
static volatile const __u8 lb_mac[ETH_ALEN] = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 };

#include <bpf_host.c>

ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, (union v4addr) { .be32 = FRONTEND_IP })

#include "lib/ipcache.h"
#include "lib/lb.h"

#define FROM_NETDEV	0
#define TO_NETDEV	1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
		[TO_NETDEV] = &cil_to_netdev,
	},
};

/* Test that ICMP echo requests to service IPs generate ICMP echo replies */
PKTGEN("tc", "tc_nodeport_lb4_icmp_echo_request")
int nodeport_lb4_icmp_echo_request_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmphdr *icmphdr;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = FRONTEND_IP;

	/* Push ICMP header */
	icmphdr = pktgen__push_icmphdr(&builder);
	if (!icmphdr)
		return TEST_ERROR;

	icmphdr->type = ICMP_ECHO;
	icmphdr->code = 0;
	icmphdr->un.echo.id = ICMP_ID;
	icmphdr->un.echo.sequence = __bpf_htons(1);

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb4_icmp_echo_request")
int nodeport_lb4_icmp_echo_request_setup(struct __ctx_buff *ctx)
{
	/* add a service entry for the frontend IP/port */
	struct lb4_key lb_svc_key = {};
	struct lb4_service lb_svc_value = {};
	struct lb4_backend lb_backend = {};

	lb_svc_key.address = FRONTEND_IP;
	lb_svc_key.dport = 0; /* ICMP doesn't have ports */
	lb_svc_key.proto = IPPROTO_ICMP;

	lb_svc_value.count = 1;
	lb_svc_value.rev_nat_index = 1;

	map_update_elem(&cilium_lb4_services_v2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* add a backend for the service */
	lb_backend.address = BACKEND_IP;
	lb_backend.port = BACKEND_PORT;

	map_update_elem(&cilium_lb4_backends_v3, &lb_svc_value.backend_id, &lb_backend, BPF_ANY);

	/* add a reverse NAT entry for the service */
	struct lb4_reverse_nat lb_rev_nat = {};
	lb_rev_nat.address = FRONTEND_IP;
	lb_rev_nat.port = FRONTEND_PORT;

	map_update_elem(&cilium_lb4_reverse_nat, &lb_svc_value.rev_nat_index,
			&lb_rev_nat, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_lb4_icmp_echo_request")
int nodeport_lb4_icmp_echo_request_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct icmphdr *icmphdr;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	test_log("Status code: %d, expected: %d (CTX_ACT_REDIRECT)", *status_code, CTX_ACT_REDIRECT);
	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	assert(l2->h_proto == bpf_htons(ETH_P_IP));

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	assert(l3->protocol == IPPROTO_ICMP);

	icmphdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if ((void *)icmphdr + sizeof(struct icmphdr) > data_end)
		test_fatal("icmphdr out of bounds");

	/* Verify this is an ICMP echo reply */
	test_log("ICMP type: %d, expected: %d (ICMP_ECHOREPLY)", icmphdr->type, ICMP_ECHOREPLY);
	assert(icmphdr->type == ICMP_ECHOREPLY);

	/* Verify the ICMP ID is preserved */
	assert(icmphdr->un.echo.id == ICMP_ID);

	/* Verify IP addresses are swapped */
	test_log("Reply src IP: 0x%x, expected: 0x%x (FRONTEND_IP)", bpf_ntohl(l3->saddr), bpf_ntohl(FRONTEND_IP));
	test_log("Reply dst IP: 0x%x, expected: 0x%x (CLIENT_IP)", bpf_ntohl(l3->daddr), bpf_ntohl(CLIENT_IP));
	assert(l3->saddr == FRONTEND_IP);
	assert(l3->daddr == CLIENT_IP);

	/* Verify MAC addresses are swapped */
	test_log("Checking MAC address swapping: src should be lb_mac, dst should be client_mac");
	assert(memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) == 0);
	assert(memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) == 0);
	test_log("MAC address swapping verified successfully");

	test_finish();
}

/* Test that non-ICMP echo requests to services are load balanced normally */
PKTGEN("tc", "tc_nodeport_lb4_icmp_other")
int nodeport_lb4_icmp_other_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmphdr *icmphdr;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = FRONTEND_IP;

	/* Push ICMP header with destination unreachable type */
	icmphdr = pktgen__push_icmphdr(&builder);
	if (!icmphdr)
		return TEST_ERROR;

	icmphdr->type = ICMP_DEST_UNREACH;
	icmphdr->code = ICMP_PORT_UNREACH;
	icmphdr->un.gateway = 0;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb4_icmp_other")
int nodeport_lb4_icmp_other_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_lb4_icmp_other")
int nodeport_lb4_icmp_other_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct icmphdr *icmphdr;

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

	assert(l2->h_proto == bpf_htons(ETH_P_IP));

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	assert(l3->protocol == IPPROTO_ICMP);

	icmphdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if ((void *)icmphdr + sizeof(struct icmphdr) > data_end)
		test_fatal("icmphdr out of bounds");

	/* Verify this is NOT an ICMP echo reply - other ICMP types should not be handled */
	assert(icmphdr->type != ICMP_ECHOREPLY);

	/* Non-echo ICMP should be dropped or pass through unchanged */
	assert(icmphdr->type == ICMP_DEST_UNREACH);

	test_finish();
}