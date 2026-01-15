// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6		1
#define ENABLE_NODEPORT		1
#define ENABLE_DSR		1
#define ENABLE_DSR_BYUSER	1
#define ENCAP_IFINDEX		42

#define CLIENT_IP		v6_pod_one
#define CLIENT_PORT		__bpf_htons(12345)

#define REMOTE_NODE_IP		v6_node_two
#define LOCAL_NODE_IP		v6_node_one
#define NODEPORT_PORT_DSR	__bpf_htons(30080)
#define NODEPORT_PORT_SNAT	__bpf_htons(30081)

#define BACKEND_IP_LOCAL	v6_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define BACKEND_IFACE		25
#define BACKEND_EP_ID		127

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *backend_mac = mac_four;

__section_entry
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return CTX_ACT_OK;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[BACKEND_EP_ID] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

#include "lib/bpf_lxc.h"

/* Set the LXC source address to be the address of the client pod */
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })
ASSIGN_CONFIG(union v6addr, service_loopback_ipv6, { .addr = v6_svc_loopback })

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"
#include "nodeport_defaults.h"

/*
 * Test: DSR service - Pod -> Remote NodePort -> Local backend
 * - NodePort service is configured with SVC_FLAG_FWD_MODE_DSR
 * - Client pod sends packet to remote node's NodePort
 * - Wildcard lookup should match and DNAT to local backend
 */
PKTGEN("tc", "tc_lxc_hybrid6_dsr_service_dnat")
int lxc_hybrid6_dsr_service_dnat_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  (__u8 *)CLIENT_IP, (__u8 *)REMOTE_NODE_IP,
					  CLIENT_PORT, NODEPORT_PORT_DSR);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_hybrid6_dsr_service_dnat")
int lxc_hybrid6_dsr_service_dnat_setup(struct __ctx_buff *ctx)
{
	union v6addr remote_node_ip = {};
	union v6addr backend_ip = {};
	union v6addr zero_addr = {};
	__u16 revnat_id = 1;

	ipv6_addr_copy(&remote_node_ip, (const union v6addr *)REMOTE_NODE_IP);
	ipv6_addr_copy(&backend_ip, (const union v6addr *)BACKEND_IP_LOCAL);

	ipcache_v6_add_entry(&remote_node_ip, 0, REMOTE_NODE_ID, 0, 0);

	/* Add DSR service with SVC_FLAG_FWD_MODE_DSR */
	lb_v6_add_service_with_flags(&zero_addr, NODEPORT_PORT_DSR, IPPROTO_TCP, 1, revnat_id,
				     SVC_FLAG_ROUTABLE, SVC_FLAG_FWD_MODE_DSR);
	lb_v6_add_backend(&zero_addr, NODEPORT_PORT_DSR, 1, 125,
			  &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);

	endpoint_v6_add_entry(&backend_ip, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry(&backend_ip, 0, 112234, 0, 0);

	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_hybrid6_dsr_service_dnat")
int lxc_hybrid6_dsr_service_dnat_check(const struct __ctx_buff *ctx)
{
	union v6addr remote_node_ip = {};
	union v6addr backend_ip = {};
	union v6addr client_ip = {};
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct ipv6hdr *l3;

	test_init();

	ipv6_addr_copy(&remote_node_ip, (const union v6addr *)REMOTE_NODE_IP);
	ipv6_addr_copy(&backend_ip, (const union v6addr *)BACKEND_IP_LOCAL);
	ipv6_addr_copy(&client_ip, (const union v6addr *)CLIENT_IP);

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

	/* DSR service: packet SHOULD be DNATed to local backend */
	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip))
		test_fatal("src IP has changed unexpectedly");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed unexpectedly");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip))
		test_fatal("dst IP hasn't been DNATed to local backend IP");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been DNATed to backend port");

	struct ipv6_ct_tuple tuple __align_stack_8 = {
		.nexthdr = IPPROTO_TCP,
		.sport = CLIENT_PORT,
		.dport = BACKEND_PORT,
		.flags = TUPLE_F_OUT,
	};
	ipv6_addr_copy(&tuple.saddr, &backend_ip);
	ipv6_addr_copy(&tuple.daddr, &client_ip);

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	if (!ipv6_addr_equals(&ct_entry->nat_addr, &remote_node_ip))
		test_fatal("CT entry has incorrect nat_addr");

	if (ct_entry->nat_port != NODEPORT_PORT_DSR)
		test_fatal("CT entry has incorrect nat_port");

	test_finish();
}

/*
 * Test: non-DSR (SNAT) service - Pod -> Remote NodePort -> No DNAT
 * - NodePort service is configured WITHOUT SVC_FLAG_FWD_MODE_DSR
 * - Client pod sends packet to remote node's NodePort
 * - Wildcard lookup should be SKIPPED (nodeport_uses_dsr6 returns false)
 * - Packet should go to original destination (remote node) without DNAT
 */
PKTGEN("tc", "tc_lxc_hybrid6_snat_service_no_dnat")
int lxc_hybrid6_snat_service_no_dnat_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  (__u8 *)CLIENT_IP, (__u8 *)REMOTE_NODE_IP,
					  CLIENT_PORT, NODEPORT_PORT_SNAT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_hybrid6_snat_service_no_dnat")
int lxc_hybrid6_snat_service_no_dnat_setup(struct __ctx_buff *ctx)
{
	union v6addr remote_node_ip = {};
	union v6addr backend_ip = {};
	union v6addr zero_addr = {};
	__u16 revnat_id = 2;

	ipv6_addr_copy(&remote_node_ip, (const union v6addr *)REMOTE_NODE_IP);
	ipv6_addr_copy(&backend_ip, (const union v6addr *)BACKEND_IP_LOCAL);

	ipcache_v6_add_entry(&remote_node_ip, 0, REMOTE_NODE_ID, 0, 0);

	/* Add non-DSR (SNAT) service WITHOUT SVC_FLAG_FWD_MODE_DSR */
	lb_v6_add_service_with_flags(&zero_addr, NODEPORT_PORT_SNAT, IPPROTO_TCP, 1, revnat_id,
				     SVC_FLAG_ROUTABLE, 0);
	lb_v6_add_backend(&zero_addr, NODEPORT_PORT_SNAT, 1, 126,
			  &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);

	endpoint_v6_add_entry(&backend_ip, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry(&backend_ip, 0, 112234, 0, 0);

	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_hybrid6_snat_service_no_dnat")
int lxc_hybrid6_snat_service_no_dnat_check(const struct __ctx_buff *ctx)
{
	union v6addr remote_node_ip = {};
	union v6addr client_ip = {};
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct ipv6hdr *l3;

	test_init();

	ipv6_addr_copy(&remote_node_ip, (const union v6addr *)REMOTE_NODE_IP);
	ipv6_addr_copy(&client_ip, (const union v6addr *)CLIENT_IP);

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

	/* non-DSR service: packet should NOT be DNATed
	 * nodeport_uses_dsr6() returns false, so wildcard lookup is skipped
	 */
	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip))
		test_fatal("src IP has changed unexpectedly");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed unexpectedly");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &remote_node_ip))
		test_fatal("dst IP should still be remote node (non-DSR skips wildcard)");

	if (l4->dest != NODEPORT_PORT_SNAT)
		test_fatal("dst port should still be nodeport (non-DSR skips wildcard)");

	test_finish();
}
