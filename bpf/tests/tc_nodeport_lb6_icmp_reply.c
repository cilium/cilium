// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define SERVICE_NO_BACKEND_RESPONSE
#define ENABLE_MASQUERADE_IPV6		1

#define CLIENT_IP		v6_node_one
#define ICMP_ID			__bpf_htons(0x5678)

#define FRONTEND_IP		v6_node_two
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v6_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

static volatile const __u8 *client_mac = mac_one;
/* this matches the default node_config.h: */
static volatile const __u8 lb_mac[ETH_ALEN] = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 };

#include <bpf_host.c>

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

/* Test that ICMPv6 echo requests to service IPs generate ICMPv6 echo replies */
PKTGEN("tc", "tc_nodeport_lb6_icmp_echo_request")
int nodeport_lb6_icmp_echo_request_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *icmp6hdr;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* Push IPv6 header */
	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;

	memcpy(&l3->saddr, (__u8 *)&CLIENT_IP, 16);
	memcpy(&l3->daddr, (__u8 *)&FRONTEND_IP, 16);

	/* Push ICMPv6 header */
	icmp6hdr = pktgen__push_icmp6hdr(&builder);
	if (!icmp6hdr)
		return TEST_ERROR;

	icmp6hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
	icmp6hdr->icmp6_code = 0;
	icmp6hdr->icmp6_identifier = ICMP_ID;
	icmp6hdr->icmp6_sequence = __bpf_htons(1);

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb6_icmp_echo_request")
int nodeport_lb6_icmp_echo_request_setup(struct __ctx_buff *ctx)
{
	/* add a service entry for the frontend IP/port */
	struct lb6_key lb_svc_key __align_stack_8 = {};
	struct lb6_service lb_svc_value __align_stack_8 = {};
	struct lb6_backend lb_backend __align_stack_8 = {};

	memcpy(&lb_svc_key.address, (__u8 *)&FRONTEND_IP, 16);
	lb_svc_key.dport = 0; /* ICMPv6 doesn't have ports */
	lb_svc_key.proto = IPPROTO_ICMPV6;

	lb_svc_value.count = 1;
	lb_svc_value.rev_nat_index = 1;

	map_update_elem(&cilium_lb6_services_v2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* add a backend for the service */
	memcpy(&lb_backend.address, (__u8 *)&BACKEND_IP, 16);
	lb_backend.port = BACKEND_PORT;

	map_update_elem(&cilium_lb6_backends_v3, &lb_svc_value.backend_id, &lb_backend, BPF_ANY);

	/* add a reverse NAT entry for the service */
	struct lb6_reverse_nat lb_rev_nat __align_stack_8 = {};
	memcpy(&lb_rev_nat.address, (__u8 *)&FRONTEND_IP, 16);
	lb_rev_nat.port = FRONTEND_PORT;

	map_update_elem(&cilium_lb6_reverse_nat, &lb_svc_value.rev_nat_index,
			&lb_rev_nat, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_lb6_icmp_echo_request")
int nodeport_lb6_icmp_echo_request_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct icmp6hdr *icmp6hdr;

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

	assert(l2->h_proto == bpf_htons(ETH_P_IPV6));

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	assert(l3->nexthdr == IPPROTO_ICMPV6);

	icmp6hdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
	if ((void *)icmp6hdr + sizeof(struct icmp6hdr) > data_end)
		test_fatal("icmp6hdr out of bounds");

	/* Verify this is an ICMPv6 echo reply */
	test_log("ICMPv6 type: %d, expected: %d (ICMPV6_ECHO_REPLY)", icmp6hdr->icmp6_type, ICMPV6_ECHO_REPLY);
	assert(icmp6hdr->icmp6_type == ICMPV6_ECHO_REPLY);

	/* Verify the ICMP ID is preserved */
	assert(icmp6hdr->icmp6_identifier == ICMP_ID);

	/* Verify IP addresses are swapped */
	test_log("Checking IPv6 address swapping: src should be FRONTEND_IP, dst should be CLIENT_IP");
	assert(memcmp(&l3->saddr, (__u8 *)&FRONTEND_IP, 16) == 0);
	assert(memcmp(&l3->daddr, (__u8 *)&CLIENT_IP, 16) == 0);
	test_log("IPv6 address swapping verified successfully");

	/* Verify MAC addresses are swapped */
	test_log("Checking MAC address swapping: src should be lb_mac, dst should be client_mac");
	assert(memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) == 0);
	assert(memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) == 0);
	test_log("MAC address swapping verified successfully");

	test_finish();
}

/* Test that non-ICMPv6 echo requests to services are load balanced normally */
PKTGEN("tc", "tc_nodeport_lb6_icmp_other")
int nodeport_lb6_icmp_other_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *icmp6hdr;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* Push IPv6 header */
	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;

	memcpy(&l3->saddr, (__u8 *)&CLIENT_IP, 16);
	memcpy(&l3->daddr, (__u8 *)&FRONTEND_IP, 16);

	/* Push ICMPv6 header with destination unreachable type */
	icmp6hdr = pktgen__push_icmp6hdr(&builder);
	if (!icmp6hdr)
		return TEST_ERROR;

	icmp6hdr->icmp6_type = ICMPV6_DEST_UNREACH;
	icmp6hdr->icmp6_code = ICMPV6_PORT_UNREACH;
	icmp6hdr->icmp6_dataun.un_data32[0] = 0;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb6_icmp_other")
int nodeport_lb6_icmp_other_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_lb6_icmp_other")
int nodeport_lb6_icmp_other_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct icmp6hdr *icmp6hdr;

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

	assert(l2->h_proto == bpf_htons(ETH_P_IPV6));

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	assert(l3->nexthdr == IPPROTO_ICMPV6);

	icmp6hdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
	if ((void *)icmp6hdr + sizeof(struct icmp6hdr) > data_end)
		test_fatal("icmp6hdr out of bounds");

	/* Verify this is NOT an ICMPv6 echo reply - other ICMP types should not be handled */
	assert(icmp6hdr->icmp6_type != ICMPV6_ECHO_REPLY);

	/* Non-echo ICMP should be dropped or pass through unchanged */
	assert(icmp6hdr->icmp6_type == ICMPV6_DEST_UNREACH);

	test_finish();
}