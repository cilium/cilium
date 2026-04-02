// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4		1
#define ENABLE_NODEPORT		1
#define ENCAP_IFINDEX		42

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(12345)

#define HOST_NODE_IP		v4_node_three
#define LOCAL_NODE_IP		v4_node_one

/* HostPort must be outside the NodePort range (30000-32767) */
#define HOSTPORT_PORT		__bpf_htons(8080)

#define BACKEND_IP_LOCAL	v4_pod_two
#define BACKEND_PORT		__bpf_htons(80)

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
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = CLIENT_IP })

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"
#include "nodeport_defaults.h"

/*
 * Test: Pod -> Host HostPort -> Local backend
 * - Client pod sends packet to a local host address (HOST_ID) on a HostPort
 * - The destination has HOST_ID identity in ipcache
 * - Port is outside NodePort range so NodePort wildcard lookup misses
 * - HostPort wildcard lookup should match and perform DNAT
 */
PKTGEN("tc", "tc_lxc_v4_host_hostport_local_backend")
int lxc_v4_host_hostport_local_backend_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  CLIENT_IP, HOST_NODE_IP,
					  CLIENT_PORT, HOSTPORT_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_v4_host_hostport_local_backend")
int lxc_v4_host_hostport_local_backend_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	ipcache_v4_add_entry(HOST_NODE_IP, 0, HOST_ID, 0, 0);

	lb_v4_add_hostport_service(0, HOSTPORT_PORT, IPPROTO_TCP, 1, revnat_id, 0);
	lb_v4_add_backend(0, HOSTPORT_PORT, 1, 125,
			  BACKEND_IP_LOCAL, BACKEND_PORT, IPPROTO_TCP, 0);

	endpoint_v4_add_entry(BACKEND_IP_LOCAL, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(BACKEND_IP_LOCAL, 0, 112234, 0, 0);

	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_v4_host_hostport_local_backend")
int lxc_v4_host_hostport_local_backend_check(const struct __ctx_buff *ctx)
{
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

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed unexpectedly");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed unexpectedly");

	if (l3->daddr != BACKEND_IP_LOCAL)
		test_fatal("dst IP hasn't been DNATed to local backend IP");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been DNATed to backend port");

	struct ipv4_ct_tuple tuple = {
		.saddr = BACKEND_IP_LOCAL,
		.daddr = CLIENT_IP,
		.sport = CLIENT_PORT,
		.dport = BACKEND_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	if (ct_entry->nat_addr.p4 != HOST_NODE_IP)
		test_fatal("CT entry has incorrect nat_addr");

	if (ct_entry->nat_port != HOSTPORT_PORT)
		test_fatal("CT entry has incorrect nat_port");

	test_finish();
}

/*
 * Test: Pod -> Host HostPort (NodePort range) -> No match
 * - Client pod sends packet to HOST_ID address on a port INSIDE NodePort range
 * - HostPort wildcard lookup should NOT match (port in NodePort range is rejected)
 * - Packet should pass through without DNAT
 */
PKTGEN("tc", "tc_lxc_v4_hostport_nodeport_range_no_match")
int lxc_v4_hostport_nodeport_range_no_match_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	/* Use a port inside NodePort range */
	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  CLIENT_IP, HOST_NODE_IP,
					  CLIENT_PORT, __bpf_htons(30080));
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_v4_hostport_nodeport_range_no_match")
int lxc_v4_hostport_nodeport_range_no_match_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	ipcache_v4_add_entry(HOST_NODE_IP, 0, HOST_ID, 0, 0);

	/* Register a hostport service on a port inside NodePort range.
	 * The wildcard hostport lookup should reject this because the port
	 * falls inside the NodePort range.
	 */
	lb_v4_add_hostport_service(0, __bpf_htons(30080), IPPROTO_TCP, 1, revnat_id, 0);
	lb_v4_add_backend(0, __bpf_htons(30080), 1, 126,
			  BACKEND_IP_LOCAL, BACKEND_PORT, IPPROTO_TCP, 0);

	endpoint_v4_add_entry(BACKEND_IP_LOCAL, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);

	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_v4_hostport_nodeport_range_no_match")
int lxc_v4_hostport_nodeport_range_no_match_check(const struct __ctx_buff *ctx)
{
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

	/* Packet should NOT be DNATed — port is in NodePort range,
	 * so hostport wildcard lookup rejects it.
	 */
	if (l3->daddr != HOST_NODE_IP)
		test_fatal("dst IP should remain unchanged (no DNAT expected)");

	if (l4->dest != __bpf_htons(30080))
		test_fatal("dst port should remain unchanged (no DNAT expected)");

	test_finish();
}
