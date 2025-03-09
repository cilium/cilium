// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4		1
#define TUNNEL_MODE		1
#define ENCAP_IFINDEX		42
#define ENABLE_NODEPORT		1
#define ENABLE_MASQUERADE_IPV4	1

#define DISABLE_LOOPBACK_LB

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)
#define CLIENT_NODE_IP		v4_node_one

#define SERVER_IP		v4_node_two
#define SERVER_PORT		__bpf_htons(8080)

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "bpf_host.c"

ASSIGN_CONFIG(__u32, interface_ifindex, 25)
ASSIGN_CONFIG(__u32, nat_ipv4_masquerade, CLIENT_NODE_IP)

#include "lib/endpoint.h"
#include "lib/ipcache.h"

#define TO_NETDEV	0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_NETDEV] = &cil_to_netdev,
	},
};

/* Send packet for pod-to-remote-node connection. Expectation is that the
 * packet is SNATed with the CLIENT_NODE_IP.
 */
PKTGEN("tc", "tc_masq_1")
int tc_masq_1_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)server_mac,
					  CLIENT_IP, SERVER_IP,
					  CLIENT_PORT, SERVER_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_masq_1")
int tc_masq_1_setup(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	struct ct_entry entry = {};
	int ret;

	/* emulate the pod's CT entry, as created by bpf_lxc on egress: */
	tuple.flags = TUPLE_F_OUT;
	tuple.nexthdr = IPPROTO_UDP;
	tuple.saddr = SERVER_IP;
	tuple.daddr = CLIENT_IP;
	tuple.sport = CLIENT_PORT;
	tuple.dport = SERVER_PORT;

	ret = map_update_elem(get_ct_map4(&tuple), &tuple, &entry, BPF_ANY);
	if (IS_ERR(ret))
		return TEST_ERROR;

	/* add local client */
	endpoint_v4_add_entry(CLIENT_IP, 0, 0, 0, 0, 0, NULL, NULL);

	/* add remote server (old style) */
	ipcache_v4_add_entry_with_flags(SERVER_IP, 0, REMOTE_NODE_ID, 0, 0, false);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_masq_1")
int tc_masq_1_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
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
	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != CLIENT_NODE_IP)
		test_fatal("first packet was not SNATed");

	test_finish();
}

/* Send another packet, but this time use an IPcache entry in the new format.
 * Missing SNAT indicates disrupted connection.
 */
PKTGEN("tc", "tc_masq_2")
int tc_masq_2_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)server_mac,
					  CLIENT_IP, SERVER_IP,
					  CLIENT_PORT, SERVER_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_masq_2")
int tc_masq_2_setup(struct __ctx_buff *ctx)
{
	/* update remote server (new style) */
	ipcache_v4_add_entry_with_flags(SERVER_IP, 0, REMOTE_NODE_ID, SERVER_IP, 0, true);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_masq_2")
int tc_masq_2_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
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
	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != CLIENT_NODE_IP)
		test_fatal("second packet was not SNATed");

	test_finish();
}
