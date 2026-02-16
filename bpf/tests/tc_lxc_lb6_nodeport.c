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
#define CLIENT_PORT_DSR		__bpf_htons(12346)

#define REMOTE_NODE_IP		v6_node_two
#define LOCAL_NODE_IP		v6_node_one
#define NODEPORT_PORT		__bpf_htons(30080)
#define NODEPORT_PORT_HAIRPIN	__bpf_htons(30081)
#define NODEPORT_PORT_UDP	__bpf_htons(30082)
#define NODEPORT_PORT_DSR	__bpf_htons(30083)

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
 * Test: Pod -> Remote NodePort -> Local backend
 * - Client pod sends packet to remote node's NodePort (non-DSR)
 * - LB selects a backend on the local node (same node as client)
 * - Packet should be DNATed to local backend IP and port
 * - Connection tracking entry should be created with
 * - nat_addr = REMOTE_NODE_IP and nat_port = NODEPORT_PORT
 */
PKTGEN("tc", "tc_lxc_v6_remote_nodeport_local_backend")
int lxc_v6_remote_nodeport_local_backend_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  (__u8 *)CLIENT_IP, (__u8 *)REMOTE_NODE_IP,
					  CLIENT_PORT, NODEPORT_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_v6_remote_nodeport_local_backend")
int lxc_v6_remote_nodeport_local_backend_setup(struct __ctx_buff *ctx)
{
	union v6addr remote_node_ip = {};
	union v6addr backend_ip = {};
	union v6addr zero_addr = {};
	__u16 revnat_id = 1;

	ipv6_addr_copy(&remote_node_ip, (const union v6addr *)REMOTE_NODE_IP);
	ipv6_addr_copy(&backend_ip, (const union v6addr *)BACKEND_IP_LOCAL);

	ipcache_v6_add_entry(&remote_node_ip, 0, REMOTE_NODE_ID, 0, 0);

	lb_v6_add_service(&zero_addr, NODEPORT_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&zero_addr, NODEPORT_PORT, 1, 125,
			  &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);

	endpoint_v6_add_entry(&backend_ip, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry(&backend_ip, 0, 112234, 0, 0);

	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_v6_remote_nodeport_local_backend")
int lxc_v6_remote_nodeport_local_backend_check(const struct __ctx_buff *ctx)
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

	if (ct_entry->nat_port != NODEPORT_PORT)
		test_fatal("CT entry has incorrect nat_port");

	test_finish();
}

/*
 * Test: Reply from local backend -> Client pod
 * - Backend sends reply packet to client
 * - Client pod's cil_to_container receives it
 * - RevNAT applied: src IP/port changed to REMOTE_NODE_IP:NODEPORT_PORT
 */
PKTGEN("tc", "tc_lxc_v6_remote_nodeport_local_backend_reply")
int lxc_v6_remote_nodeport_local_backend_reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)backend_mac, (__u8 *)client_mac,
					  (__u8 *)BACKEND_IP_LOCAL, (__u8 *)CLIENT_IP,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_v6_remote_nodeport_local_backend_reply")
int lxc_v6_remote_nodeport_local_backend_reply_setup(struct __ctx_buff *ctx)
{
	union v6addr client_ip = {};

	ipv6_addr_copy(&client_ip, (const union v6addr *)CLIENT_IP);

	endpoint_v6_add_entry(&client_ip, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)client_mac, (__u8 *)node_mac);

	return pod_receive_packet(ctx);
}

CHECK("tc", "tc_lxc_v6_remote_nodeport_local_backend_reply")
int lxc_v6_remote_nodeport_local_backend_reply_check(const struct __ctx_buff *ctx)
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

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &remote_node_ip))
		test_fatal("src IP hasn't been RevNATed to remote node IP");

	if (l4->source != NODEPORT_PORT)
		test_fatal("src port hasn't been RevNATed to nodeport");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &client_ip))
		test_fatal("dst IP has changed unexpectedly");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port has changed unexpectedly");

	test_finish();
}

/*
 * Test: Pod -> Remote NodePort -> Local backend
 * - Client pod sends packet to remote node's NodePort (with DSR)
 * - LB selects a backend on the local node (same node as client)
 * - Packet should be DNATed to local backend IP and port
 * - Connection tracking entry should be created with
 * - nat_addr = REMOTE_NODE_IP and nat_port = NODEPORT_PORT_DSR
 */
PKTGEN("tc", "tc_lxc_v6_remote_nodeport_dsr_local_backend")
int lxc_v6_remote_nodeport_dsr_local_backend_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  (__u8 *)CLIENT_IP, (__u8 *)REMOTE_NODE_IP,
					  CLIENT_PORT_DSR, NODEPORT_PORT_DSR);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_v6_remote_nodeport_dsr_local_backend")
int lxc_v6_remote_nodeport_dsr_local_backend_setup(struct __ctx_buff *ctx)
{
	union v6addr remote_node_ip = {};
	union v6addr backend_ip = {};
	union v6addr zero_addr = {};
	__u16 revnat_id = 2;

	ipv6_addr_copy(&remote_node_ip, (const union v6addr *)REMOTE_NODE_IP);
	ipv6_addr_copy(&backend_ip, (const union v6addr *)BACKEND_IP_LOCAL);

	ipcache_v6_add_entry(&remote_node_ip, 0, REMOTE_NODE_ID, 0, 0);

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

CHECK("tc", "tc_lxc_v6_remote_nodeport_dsr_local_backend")
int lxc_v6_remote_nodeport_dsr_local_backend_check(const struct __ctx_buff *ctx)
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

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip))
		test_fatal("src IP has changed unexpectedly");

	if (l4->source != CLIENT_PORT_DSR)
		test_fatal("src port has changed unexpectedly");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip))
		test_fatal("dst IP hasn't been DNATed to local backend IP");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been DNATed to backend port");

	struct ipv6_ct_tuple tuple __align_stack_8 = {
		.nexthdr = IPPROTO_TCP,
		.sport = CLIENT_PORT_DSR,
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
 * Test: Reply from local backend -> Client pod
 * - Backend sends reply packet to client
 * - Client pod's cil_to_container receives it
 * - RevNAT applied: src IP/port changed to REMOTE_NODE_IP:NODEPORT_PORT_DSR
 */
PKTGEN("tc", "tc_lxc_v6_remote_nodeport_dsr_local_backend_reply")
int lxc_v6_remote_nodeport_dsr_local_backend_reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)backend_mac, (__u8 *)client_mac,
					  (__u8 *)BACKEND_IP_LOCAL, (__u8 *)CLIENT_IP,
					  BACKEND_PORT, CLIENT_PORT_DSR);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_v6_remote_nodeport_dsr_local_backend_reply")
int lxc_v6_remote_nodeport_dsr_local_backend_reply_setup(struct __ctx_buff *ctx)
{
	union v6addr client_ip = {};

	ipv6_addr_copy(&client_ip, (const union v6addr *)CLIENT_IP);

	endpoint_v6_add_entry(&client_ip, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)client_mac, (__u8 *)node_mac);

	return pod_receive_packet(ctx);
}

CHECK("tc", "tc_lxc_v6_remote_nodeport_dsr_local_backend_reply")
int lxc_v6_remote_nodeport_dsr_local_backend_reply_check(const struct __ctx_buff *ctx)
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

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &remote_node_ip))
		test_fatal("src IP hasn't been RevNATed to remote node IP");

	if (l4->source != NODEPORT_PORT_DSR)
		test_fatal("src port hasn't been RevNATed to nodeport");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &client_ip))
		test_fatal("dst IP has changed unexpectedly");

	if (l4->dest != CLIENT_PORT_DSR)
		test_fatal("dst port has changed unexpectedly");

	test_finish();
}

/*
 * Test: Pod -> Remote NodePort -> Self (hairpin)
 * - Client pod sends packet to remote node's NodePort
 * - LB selects the client pod itself as the backend (loopback)
 * - Packet should be DNATed to CLIENT_IP:BACKEND_PORT
 * - Source should be SNATed to loopback IP to avoid routing issues
 */
PKTGEN("tc", "tc_lxc_v6_remote_nodeport_hairpin")
int lxc_v6_remote_nodeport_hairpin_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  (__u8 *)CLIENT_IP, (__u8 *)REMOTE_NODE_IP,
					  CLIENT_PORT, NODEPORT_PORT_HAIRPIN);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_v6_remote_nodeport_hairpin")
int lxc_v6_remote_nodeport_hairpin_setup(struct __ctx_buff *ctx)
{
	union v6addr remote_node_ip = {};
	union v6addr client_ip = {};
	union v6addr zero_addr = {};
	__u16 revnat_id = 3;

	ipv6_addr_copy(&remote_node_ip, (const union v6addr *)REMOTE_NODE_IP);
	ipv6_addr_copy(&client_ip, (const union v6addr *)CLIENT_IP);

	ipcache_v6_add_entry(&remote_node_ip, 0, REMOTE_NODE_ID, 0, 0);

	lb_v6_add_service(&zero_addr, NODEPORT_PORT_HAIRPIN, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&zero_addr, NODEPORT_PORT_HAIRPIN, 1, 126,
			  &client_ip, BACKEND_PORT, IPPROTO_TCP, 0);

	endpoint_v6_add_entry(&client_ip, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)client_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry(&client_ip, 0, 112233, 0, 0);

	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_v6_remote_nodeport_hairpin")
int lxc_v6_remote_nodeport_hairpin_check(const struct __ctx_buff *ctx)
{
	union v6addr client_ip = {};
	union v6addr svc_loopback = { .addr = v6_svc_loopback };
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct ipv6hdr *l3;

	test_init();

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

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &client_ip))
		test_fatal("dst IP hasn't been DNATed to client IP (hairpin)");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been DNATed to backend port");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &svc_loopback))
		test_fatal("src IP hasn't been SNATed to loopback IP for hairpin");

	union v6addr remote_node_ip = {};

	ipv6_addr_copy(&remote_node_ip, (const union v6addr *)REMOTE_NODE_IP);

	struct ipv6_ct_tuple tuple __align_stack_8 = {
		.nexthdr = IPPROTO_TCP,
		.sport = CLIENT_PORT,
		.dport = BACKEND_PORT,
		.flags = TUPLE_F_OUT,
	};
	ipv6_addr_copy(&tuple.saddr, &client_ip);
	ipv6_addr_copy(&tuple.daddr, &svc_loopback);

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	if (!ipv6_addr_equals(&ct_entry->nat_addr, &remote_node_ip))
		test_fatal("CT entry has incorrect nat_addr");

	if (ct_entry->nat_port != NODEPORT_PORT_HAIRPIN)
		test_fatal("CT entry has incorrect nat_port");

	test_finish();
}

/*
 * Test: Hairpin reply - Backend (self) -> Client pod
 * - After hairpin, the pod replies to loopback IP
 * - RevNAT applied: src IP/port changed to REMOTE_NODE_IP:NODEPORT_PORT_HAIRPIN
 */
PKTGEN("tc", "tc_lxc_v6_remote_nodeport_hairpin_reply")
int lxc_v6_remote_nodeport_hairpin_reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;
	static volatile const __u8 svc_loopback[] = v6_svc_loopback;

	pktgen__init(&builder, ctx);

	/* Reply from backend (self) to loopback IP */
	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  (__u8 *)CLIENT_IP, (__u8 *)svc_loopback,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_v6_remote_nodeport_hairpin_reply")
int lxc_v6_remote_nodeport_hairpin_reply_setup(struct __ctx_buff *ctx)
{
	union v6addr client_ip = {};

	ipv6_addr_copy(&client_ip, (const union v6addr *)CLIENT_IP);

	endpoint_v6_add_entry(&client_ip, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)client_mac, (__u8 *)node_mac);

	return pod_receive_packet(ctx);
}

CHECK("tc", "tc_lxc_v6_remote_nodeport_hairpin_reply")
int lxc_v6_remote_nodeport_hairpin_reply_check(const struct __ctx_buff *ctx)
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

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &remote_node_ip))
		test_fatal("src IP hasn't been RevNATed to remote node IP");

	if (l4->source != NODEPORT_PORT_HAIRPIN)
		test_fatal("src port hasn't been RevNATed to nodeport");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &client_ip))
		test_fatal("dst IP has changed unexpectedly");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port has changed unexpectedly");

	test_finish();
}

/*
 * Test: Existing connection - first UDP packet (without NodePort service)
 * - Client pod sends UDP packet to remote node's NodePort
 * - No NodePort service exists yet
 * - Packet should NOT be DNATed (goes to remote node directly)
 * - CT entry is created for this connection
 */
PKTGEN("tc", "tc_lxc_v6_existing_conn_udp_first")
int lxc_v6_existing_conn_udp_first_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_udp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  (__u8 *)CLIENT_IP, (__u8 *)REMOTE_NODE_IP,
					  CLIENT_PORT, NODEPORT_PORT_UDP);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_v6_existing_conn_udp_first")
int lxc_v6_existing_conn_udp_first_setup(struct __ctx_buff *ctx)
{
	/* Add ipcache entry for remote node, but NO NodePort service */
	ipcache_v6_add_entry((union v6addr *)REMOTE_NODE_IP, 0, REMOTE_NODE_ID, 0, 0);

	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_v6_existing_conn_udp_first")
int lxc_v6_existing_conn_udp_first_check(const struct __ctx_buff *ctx)
{
	union v6addr remote_node_ip = {};
	union v6addr client_ip = {};
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
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
	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	/* Packet should NOT be DNATed - destination should still be remote node */
	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip))
		test_fatal("src IP has changed unexpectedly");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &remote_node_ip))
		test_fatal("dst IP should still be remote node IP (no DNAT)");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed unexpectedly");

	if (l4->dest != NODEPORT_PORT_UDP)
		test_fatal("dst port should still be nodeport (no DNAT)");

	/* Verify CT entry was created */
	struct ipv6_ct_tuple tuple __align_stack_8 = {
		.nexthdr = IPPROTO_UDP,
		.sport = CLIENT_PORT,
		.dport = NODEPORT_PORT_UDP,
		.flags = TUPLE_F_OUT,
	};
	ipv6_addr_copy(&tuple.saddr, &remote_node_ip);
	ipv6_addr_copy(&tuple.daddr, &client_ip);

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found - CT entry should be created");

	test_finish();
}

/*
 * Test: Existing connection - second UDP packet (with NodePort service added)
 * - Same UDP connection as previous test
 * - NodePort service is NOW added
 * - Packet should still NOT be DNATed because CT entry already exists
 * - This verifies the CT check prevents wildcard lookup for existing connections
 */
PKTGEN("tc", "tc_lxc_v6_existing_conn_udp_second")
int lxc_v6_existing_conn_udp_second_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	/* Same packet as first test */
	l4 = pktgen__push_ipv6_udp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  (__u8 *)CLIENT_IP, (__u8 *)REMOTE_NODE_IP,
					  CLIENT_PORT, NODEPORT_PORT_UDP);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_v6_existing_conn_udp_second")
int lxc_v6_existing_conn_udp_second_setup(struct __ctx_buff *ctx)
{
	union v6addr zero_addr = {};
	__u16 revnat_id = 10;

	/* NOW add the wildcard NodePort service with local backend */
	lb_v6_add_service(&zero_addr, NODEPORT_PORT_UDP, IPPROTO_UDP, 1, revnat_id);
	lb_v6_add_backend(&zero_addr, NODEPORT_PORT_UDP, 1, 130,
			  (union v6addr *)BACKEND_IP_LOCAL, BACKEND_PORT, IPPROTO_UDP, 0);

	endpoint_v6_add_entry((union v6addr *)BACKEND_IP_LOCAL, BACKEND_IFACE, BACKEND_EP_ID,
			      0, 0, (__u8 *)backend_mac, (__u8 *)node_mac);

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_v6_existing_conn_udp_second")
int lxc_v6_existing_conn_udp_second_check(const struct __ctx_buff *ctx)
{
	union v6addr remote_node_ip = {};
	union v6addr client_ip = {};
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
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
	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	/* Even though NodePort service exists now, packet should NOT be DNATed
	 * because CT entry already exists from the first packet.
	 * The CT check should skip wildcard lookup for existing connections.
	 */
	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip))
		test_fatal("src IP has changed unexpectedly");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &remote_node_ip))
		test_fatal("dst IP should still be remote node IP (CT check should skip wildcard)");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed unexpectedly");

	if (l4->dest != NODEPORT_PORT_UDP)
		test_fatal("dst port should still be nodeport (CT check should skip wildcard)");

	test_finish();
}
