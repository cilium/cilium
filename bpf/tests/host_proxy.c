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

#define POD_SECURITY_ID			40000
#define POD_IP				v4_pod_one
#define SERVER_IP			v4_ext_one
#define SERVER_PORT			bpf_htons(53)

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "lib/bpf_host.h"

ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"

static __always_inline int
pktgen(struct __ctx_buff *ctx, __be16 node_port, bool to_pod)
{
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   NODE_IP, to_pod ? POD_IP : SERVER_IP,
					   node_port, SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

/* Validate that a host-to-world packet matching a `proxy` policy entry
 * is actually redirected to the proxy.
 */
PKTGEN("tc", "proxy_v4_1_host_to_world")
int proxy_v4_1_host_to_world_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, NODE_PORT, false);
}

SETUP("tc", "proxy_v4_1_host_to_world")
int proxy_v4_1_host_to_world_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(NODE_IP, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      0, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(NODE_IP, 0, HOST_ID, 0, 0);
	ipcache_v4_add_world_entry();
	policy_add_entry(true, 0, IPPROTO_UDP, SERVER_PORT, 0, false, TPROXY_PORT);

	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

static __always_inline int
check_redirect(struct __ctx_buff *ctx, bool to_pod)
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
		.saddr   = to_pod ? POD_IP : SERVER_IP,
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

CHECK("tc", "proxy_v4_1_host_to_world")
int proxy_v4_1_host_to_world_check(struct __ctx_buff *ctx)
{
	return check_redirect(ctx, false);
}

/* Validate that a proxy-to-world packet is not redirected back to the proxy.
 */
PKTGEN("tc", "proxy_v4_2_proxy_to_world")
int proxy_v4_2_proxy_to_world_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, NODE_PROXY_PORT, false);
}

SETUP("tc", "proxy_v4_2_proxy_to_world")
int proxy_v4_2_proxy_to_world_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, HOST_ID, MARK_MAGIC_PROXY_EGRESS);

	return netdev_send_packet(ctx);
}

static __always_inline int
check_passthrough(const struct __ctx_buff *ctx, bool to_pod)
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
		.saddr   = to_pod ? POD_IP : SERVER_IP,
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

	test_finish();
}

CHECK("tc", "proxy_v4_2_proxy_to_world")
int proxy_v4_2_proxy_to_world_check(const struct __ctx_buff *ctx)
{
	return check_passthrough(ctx, false);
}

/* Validate that a host-to-pod packet matching a `proxy` policy entry
 * is actually redirected to the proxy.
 */
PKTGEN("tc", "proxy_v4_3_host_to_pod")
int proxy_v4_3_host_to_pod_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, NODE_PORT, true);
}

SETUP("tc", "proxy_v4_3_host_to_pod")
int proxy_v4_3_host_to_pod_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(POD_IP, 0, POD_SECURITY_ID, 0, 0);

	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return host_send_packet(ctx);
}

CHECK("tc", "proxy_v4_3_host_to_pod")
int proxy_v4_3_host_to_pod_check(struct __ctx_buff *ctx)
{
	return check_redirect(ctx, true);
}

/* Validate that a proxy-to-pod packet is not redirected back to the proxy.
 */
PKTGEN("tc", "proxy_v4_4_proxy_to_pod")
int proxy_v4_4_proxy_to_pod_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, NODE_PROXY_PORT, true);
}

SETUP("tc", "proxy_v4_4_proxy_to_pod")
int proxy_v4_4_proxy_to_pod_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, HOST_ID, MARK_MAGIC_PROXY_EGRESS);

	return host_send_packet(ctx);
}

CHECK("tc", "proxy_v4_4_proxy_to_pod")
int proxy_v4_4_proxy_to_pod_check(const struct __ctx_buff *ctx)
{
	return check_passthrough(ctx, true);
}
