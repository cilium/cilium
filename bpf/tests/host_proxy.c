// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_HOST_FIREWALL		1
#define ENABLE_IPV4			1
#define ENABLE_IPV6			1

#define NODE_IP				v4_node_one
#define NODE_IP6			v6_node_one
#define NODE_PORT			bpf_htons(50000)
#define NODE_PROXY_PORT			bpf_htons(50001)
#define PROXY_UPSTREAM_PORT		bpf_htons(50100)

#define TPROXY_PORT			bpf_htons(11111)

#define SERVER_IP			v4_ext_one
#define SERVER_PORT			bpf_htons(53)

#define BACKEND_IP			v4_ext_two
#define BACKEND_IP6			v6_ext_node_one
#define BACKEND_PORT			bpf_htons(80)

#define POD_SEC_IDENTITY		112233

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;
static volatile const __u8 *backend_mac = mac_two;

#include "lib/bpf_host.h"

ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

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

/* Send a request from cilium_host to a backend, emulating an envoy proxy
 * upstream socket: the source IP is a host IP but the packet mark carries
 * a non-reserved pod identity (MARK_MAGIC_PROXY_INGRESS). The host
 * firewall egress path must still create a CT entry so the reply from
 * the backend bypasses host ingress policy -- without it, the reply
 * SYN,ACK misses in ipv4_host_policy_ingress_lookup and default-denies.
 */
PKTGEN("tc", "host_proxy_v4_3_upstream_fwd")
int host_proxy_v4_3_upstream_fwd_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *tcp;

	pktgen__init(&builder, ctx);

	tcp = pktgen__push_ipv4_tcp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)backend_mac,
					   NODE_IP, BACKEND_IP,
					   PROXY_UPSTREAM_PORT, BACKEND_PORT);
	if (!tcp)
		return TEST_ERROR;

	tcp->syn = 1;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "host_proxy_v4_3_upstream_fwd")
int host_proxy_v4_3_upstream_fwd_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, POD_SEC_IDENTITY, MARK_MAGIC_PROXY_INGRESS);

	return host_send_packet(ctx);
}

CHECK("tc", "host_proxy_v4_3_upstream_fwd")
int host_proxy_v4_3_upstream_fwd_check(const struct __ctx_buff *ctx)
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

	/* The host firewall egress path must have created a CT entry. The
	 * entry is stored in TUPLE_F_OUT layout with the original
	 * destination as the tuple's saddr (CT tuple convention).
	 */
	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = BACKEND_IP,
		.dport   = BACKEND_PORT,
		.sport   = PROXY_UPSTREAM_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags   = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry created for proxy-upstream forward SYN");

	assert(ct_entry->packets == 1);

	test_finish();
}

/* Reply SYN,ACK from the backend arriving via the netdev. Without the CT
 * entry created by the forward test above, the host firewall ingress
 * lookup would default-deny this packet. Verify that it is accepted and
 * that the CT entry's packet count is incremented.
 */
PKTGEN("tc", "host_proxy_v4_4_upstream_reply")
int host_proxy_v4_4_upstream_reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *tcp;

	pktgen__init(&builder, ctx);

	tcp = pktgen__push_ipv4_tcp_packet(&builder,
					   (__u8 *)backend_mac, (__u8 *)node_mac,
					   BACKEND_IP, NODE_IP,
					   BACKEND_PORT, PROXY_UPSTREAM_PORT);
	if (!tcp)
		return TEST_ERROR;

	tcp->syn = 1;
	tcp->ack = 1;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "host_proxy_v4_4_upstream_reply")
int host_proxy_v4_4_upstream_reply_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK("tc", "host_proxy_v4_4_upstream_reply")
int host_proxy_v4_4_upstream_reply_check(const struct __ctx_buff *ctx)
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

	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = BACKEND_IP,
		.dport   = BACKEND_PORT,
		.sport   = PROXY_UPSTREAM_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags   = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found for proxy-upstream flow");

	assert(ct_entry->packets == 2);

	test_finish();
}

/* IPv6 variant of the proxy-upstream forward test. */
PKTGEN("tc", "host_proxy_v6_3_upstream_fwd")
int host_proxy_v6_3_upstream_fwd_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *tcp;

	pktgen__init(&builder, ctx);

	tcp = pktgen__push_ipv6_tcp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)backend_mac,
					   (__u8 *)NODE_IP6, (__u8 *)BACKEND_IP6,
					   PROXY_UPSTREAM_PORT, BACKEND_PORT);
	if (!tcp)
		return TEST_ERROR;

	tcp->syn = 1;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "host_proxy_v6_3_upstream_fwd")
int host_proxy_v6_3_upstream_fwd_setup(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)NODE_IP6, 0, 0, ENDPOINT_F_HOST,
			      HOST_ID, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry((union v6addr *)NODE_IP6, 0, HOST_ID, 0, 0);

	set_identity_mark(ctx, POD_SEC_IDENTITY, MARK_MAGIC_PROXY_INGRESS);

	return host_send_packet(ctx);
}

CHECK("tc", "host_proxy_v6_3_upstream_fwd")
int host_proxy_v6_3_upstream_fwd_check(const struct __ctx_buff *ctx)
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

	struct ipv6_ct_tuple tuple = {
		.dport   = BACKEND_PORT,
		.sport   = PROXY_UPSTREAM_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags   = TUPLE_F_OUT,
	};
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)NODE_IP6);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)BACKEND_IP6);

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry created for proxy-upstream forward SYN (v6)");

	assert(ct_entry->packets == 1);

	test_finish();
}

/* IPv6 reply SYN,ACK from the backend, mirroring the v4 reply test. */
PKTGEN("tc", "host_proxy_v6_4_upstream_reply")
int host_proxy_v6_4_upstream_reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *tcp;

	pktgen__init(&builder, ctx);

	tcp = pktgen__push_ipv6_tcp_packet(&builder,
					   (__u8 *)backend_mac, (__u8 *)node_mac,
					   (__u8 *)BACKEND_IP6, (__u8 *)NODE_IP6,
					   BACKEND_PORT, PROXY_UPSTREAM_PORT);
	if (!tcp)
		return TEST_ERROR;

	tcp->syn = 1;
	tcp->ack = 1;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "host_proxy_v6_4_upstream_reply")
int host_proxy_v6_4_upstream_reply_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK("tc", "host_proxy_v6_4_upstream_reply")
int host_proxy_v6_4_upstream_reply_check(const struct __ctx_buff *ctx)
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

	struct ipv6_ct_tuple tuple = {
		.dport   = BACKEND_PORT,
		.sport   = PROXY_UPSTREAM_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags   = TUPLE_F_OUT,
	};
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)NODE_IP6);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)BACKEND_IP6);

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found for proxy-upstream flow (v6)");

	assert(ct_entry->packets == 2);

	test_finish();
}
