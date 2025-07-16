// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define ENABLE_NODEPORT 1


#define ENABLE_HOST_SERVICES_TCP 1
#define ENABLE_HOST_SERVICES_UDP 1

#include <bpf_host.c>

#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(bool, drop_traffic_to_virtual_ips, true)



#define CLUSTER_IP_V4 v4_svc_one
#define CLUSTER_IP_V6 v6_svc_one

#define SERVICE_PORT tcp_svc_one
#define NON_SERVICE_PORT __bpf_htons(8080)

#define CLIENT_IP_V4 v4_ext_one
#define CLIENT_IP_V6 v6_ext_node_one
#define CLIENT_PORT __bpf_htons(111)

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[0] = &cil_from_netdev,
	},
};

/* Test that packets to ClusterIP on non-service ports are dropped */
PKTGEN("tc", "test_drop_clusterip_packet_v4")
int test_drop_clusterip_packet_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  CLIENT_IP_V4, CLUSTER_IP_V4,
					  CLIENT_PORT, NON_SERVICE_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "test_drop_clusterip_packet_v4")
int test_drop_clusterip_packet_v4_setup(struct __ctx_buff *ctx)
{
	/* Create a ClusterIP service with wildcard entry */
	lb_v4_add_service_with_flags(CLUSTER_IP_V4, SERVICE_PORT, IPPROTO_TCP, 1, 1, 0, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "test_drop_clusterip_packet_v4")
int test_drop_clusterip_packet_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	/* Verify packet was for the right destination */
	assert(l3->daddr == CLUSTER_IP_V4);
	assert(l4->dest == NON_SERVICE_PORT);

	test_finish();
}

/* Test that packets to ClusterIP on non-service ports are dropped (IPv6) */
PKTGEN("tc", "test_drop_clusterip_packet_v6")
int test_drop_clusterip_packet_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)CLIENT_IP_V6, (__u8 *)CLUSTER_IP_V6,
					  CLIENT_PORT, NON_SERVICE_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "test_drop_clusterip_packet_v6")
int test_drop_clusterip_packet_v6_setup(struct __ctx_buff *ctx)
{
	/* Create a ClusterIP service with wildcard entry */
	lb_v6_add_service_with_flags((union v6addr *)&CLUSTER_IP_V6, SERVICE_PORT, IPPROTO_TCP, 1, 1, 0, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "test_drop_clusterip_packet_v6")
int test_drop_clusterip_packet_v6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	/* Verify packet was for the right destination */
	assert(memcmp(&l3->daddr, (void *)&CLUSTER_IP_V6, sizeof(l3->daddr)) == 0);
	assert(l4->dest == NON_SERVICE_PORT);

	test_finish();
}
