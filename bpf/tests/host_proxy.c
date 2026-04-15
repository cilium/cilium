// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_HOST_FIREWALL		1
#define ENABLE_IPV4			1

#define NODE_IP				v4_node_one
#define NODE_PORT			bpf_htons(50000)
#define NODE_PROXY_PORT			bpf_htons(50001)

#define TPROXY_PORT			bpf_htons(11111)

#define SERVER_IP			v4_ext_one
#define SERVER_PORT			bpf_htons(53)

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "lib/bpf_host.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"

static __always_inline
int host_proxy_v4_udp_pktgen(struct __ctx_buff *ctx, __be16 node_port)
{
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   NODE_IP, SERVER_IP,
					   node_port, SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

PKTGEN("tc", "host_proxy_v4_1_udp")
int host_proxy_v4_1_udp_pktgen(struct __ctx_buff *ctx)
{
	return host_proxy_v4_udp_pktgen(ctx, NODE_PORT);
}

SETUP("tc", "host_proxy_v4_1_udp")
int host_proxy_v4_1_udp_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(NODE_IP, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      0, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(NODE_IP, 0, HOST_ID, 0, 0);
	ipcache_v4_add_world_entry();
	policy_add_entry(true, WORLD_ID, IPPROTO_UDP, SERVER_PORT, 0, false, TPROXY_PORT);

	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_proxy_v4_1_udp")
int host_proxy_v4_1_udp_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	/* Check whether BPF created a CT entry */
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
	assert(ct_entry->proxy_redirect);

	test_finish();
}

PKTGEN("tc", "host_proxy_v4_2_udp")
int host_proxy_v4_2_udp_pktgen(struct __ctx_buff *ctx)
{
	return host_proxy_v4_udp_pktgen(ctx, NODE_PROXY_PORT);
}

SETUP("tc", "host_proxy_v4_2_udp")
int host_proxy_v4_2_udp_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, HOST_ID, MARK_MAGIC_PROXY_EGRESS);

	return netdev_send_packet(ctx);
}

CHECK("tc", "host_proxy_v4_2_udp")
int host_proxy_v4_2_udp_check(const struct __ctx_buff *ctx)
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

	/* Check whether BPF created a CT entry */
	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = SERVER_IP,
		.dport   = SERVER_PORT,
		.sport   = NODE_PROXY_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	assert(ct_entry->packets == 1);
	assert(!ct_entry->proxy_redirect);

	/* Check that the original CT entry was not hit */
	tuple.sport = NODE_PORT;
	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	assert(ct_entry->packets == 1);

	policy_delete_entry(true, WORLD_ID, IPPROTO_UDP, SERVER_PORT, 0);

	test_finish();
}
