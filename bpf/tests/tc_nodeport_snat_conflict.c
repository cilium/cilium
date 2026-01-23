// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/*
 * This test will ensure the node-port path detects local host traffic, creating
 * both a conntrack entry and a SNAT reservation to avoid NAT port allocation
 * conflicts
 */

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define ENABLE_NODEPORT 1
#define ENABLE_MASQUERADE_IPV4 1
#define ENABLE_MASQUERADE_IPV6 1

/* IPv4 test addresses */
#define POD_IP				v4_pod_one
#define NODE_IP				v4_node_one
#define NODE_PORT			bpf_htons(50001)

#define SERVER_IP			v4_ext_one
#define SERVER_PORT			bpf_htons(80)

/* IPv6 test addresses */
#define POD_IP6				v6_pod_one
#define POD_IP6_ADDR			{ .addr = v6_pod_one_addr }
#define NODE_IP6			v6_node_one
#define NODE_IP6_ADDR			{ .addr = v6_node_one_addr }

#define SERVER_IP6			v6_ext_node_one
#define SERVER_IP6_ADDR			{ .addr = v6_ext_node_one_addr }

#define POD_SEC_IDENTITY		112233

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "lib/bpf_host.h"

/*
 * helpers
 */
#include "lib/endpoint.h"
#include "lib/ipcache.h"

static __always_inline int
tc_nodeport_snat_conflict_assert_status(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		return 0;

	status_code = data;
	return *status_code == CTX_ACT_OK;
}

static __always_inline int tc_nodeport_snat_conflict_assert_ipv4(void)
{
	/*
	 * Confirm egress conntrack entry was created.
	 * CT tuple format:
	 * saddr=remote, daddr=local, sport=local_port, dport=remote_port
	 */
	struct ipv4_ct_tuple tuple = {
		.saddr   = SERVER_IP,
		.daddr   = NODE_IP,
		.sport   = NODE_PORT,
		.dport   = SERVER_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags   = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(&cilium_ct_any4_global, &tuple);

	return ct_entry ? 1 : 0;
}

static __always_inline int tc_nodeport_snat_conflict_assert_ipv6(void)
{
	/*
	 * Confirm egress conntrack entry was created.
	 * CT tuple format:
	 * saddr=remote, daddr=local, sport=local_port, dport=remote_port
	 */
	struct ipv6_ct_tuple tuple = {
		.saddr   = SERVER_IP6_ADDR,
		.daddr   = NODE_IP6_ADDR,
		.sport   = NODE_PORT,
		.dport   = SERVER_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags   = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(&cilium_ct_any6_global, &tuple);

	return ct_entry ? 1 : 0;
}

/*
 * Create a request from a host process or host-networked pod from a host IP
 * within the endpoint map to an external host, subjecting it to the nat fwd
 * path.
 */
PKTGEN("tc", "tc_nodeport_snat_conflict_host_ipv4")
int tc_nodeport_snat_conflict_host_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   NODE_IP, SERVER_IP,
					   NODE_PORT, SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_snat_conflict_host_ipv4")
int tc_nodeport_snat_conflict_host_ipv4_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(NODE_IP, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      0, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(NODE_IP, 0, HOST_ID, 0, 0);
	ipcache_v4_add_world_entry();

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_nodeport_snat_conflict_host_ipv4")
int tc_nodeport_snat_conflict_host_ipv4_check(struct __ctx_buff *ctx)
{
	test_init();
	assert(tc_nodeport_snat_conflict_assert_status(ctx));
	assert(tc_nodeport_snat_conflict_assert_ipv4());
	test_finish();
}

/*
 * IPv6: Create a request from a host process or host-networked pod from a host IP
 * within the endpoint map to an external host, subjecting it to the nat fwd path.
 */
PKTGEN("tc", "tc_nodeport_snat_conflict_host_ipv6")
int tc_nodeport_snat_conflict_host_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv6_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   (__u8 *)NODE_IP6, (__u8 *)SERVER_IP6,
					   NODE_PORT, SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_snat_conflict_host_ipv6")
int tc_nodeport_snat_conflict_host_ipv6_setup(struct __ctx_buff *ctx)
{
	union v6addr node_ip6 = NODE_IP6_ADDR;

	endpoint_v6_add_entry(&node_ip6, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry(&node_ip6, 0, HOST_ID, 0, 0);
	ipcache_v6_add_world_entry();

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_nodeport_snat_conflict_host_ipv6")
int tc_nodeport_snat_conflict_host_ipv6_check(struct __ctx_buff *ctx)
{
	test_init();
	assert(tc_nodeport_snat_conflict_assert_status(ctx));
	assert(tc_nodeport_snat_conflict_assert_ipv6());
	test_finish();
}

/*
 * Create a non-transparent request from the egress proxy sourced from a node
 * IP, subjecting it to the nat fwd path.
 */
PKTGEN("tc", "tc_nodeport_snat_conflict_egressproxy_ipv4")
int tc_nodeport_snat_conflict_egressproxy_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   NODE_IP, SERVER_IP,
					   NODE_PORT, SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	set_identity_mark(ctx, POD_SEC_IDENTITY, MARK_MAGIC_PROXY_EGRESS);

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_snat_conflict_egressproxy_ipv4")
int tc_nodeport_snat_conflict_egressproxy_ipv4_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(NODE_IP, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      0, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(NODE_IP, 0, HOST_ID, 0, 0);
	ipcache_v4_add_world_entry();

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_nodeport_snat_conflict_egressproxy_ipv4")
int tc_nodeport_snat_conflict_egressproxy_ipv4_check(struct __ctx_buff *ctx)
{
	test_init();
	assert(tc_nodeport_snat_conflict_assert_status(ctx));
	assert(tc_nodeport_snat_conflict_assert_ipv4());
	test_finish();
}

/*
 * IPv6: Create a non-transparent request from the egress proxy sourced from a
 * node IP, subjecting it to the nat fwd path.
 */
PKTGEN("tc", "tc_nodeport_snat_conflict_egressproxy_ipv6")
int tc_nodeport_snat_conflict_egressproxy_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv6_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   (__u8 *)NODE_IP6, (__u8 *)SERVER_IP6,
					   NODE_PORT, SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	set_identity_mark(ctx, POD_SEC_IDENTITY, MARK_MAGIC_PROXY_EGRESS);

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_snat_conflict_egressproxy_ipv6")
int tc_nodeport_snat_conflict_egressproxy_ipv6_setup(struct __ctx_buff *ctx)
{
	union v6addr node_ip6 = NODE_IP6_ADDR;

	endpoint_v6_add_entry(&node_ip6, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry(&node_ip6, 0, HOST_ID, 0, 0);
	ipcache_v6_add_world_entry();

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_nodeport_snat_conflict_egressproxy_ipv6")
int tc_nodeport_snat_conflict_egressproxy_ipv6_check(struct __ctx_buff *ctx)
{
	test_init();
	assert(tc_nodeport_snat_conflict_assert_status(ctx));
	assert(tc_nodeport_snat_conflict_assert_ipv6());
	test_finish();
}

/*
 * Create a request from a pod toward an external server, subjecting it to the
 * nat fwd path.
 *
 * We expect no conntrack to be created in this scenario.
 */
PKTGEN("tc", "tc_nodeport_snat_conflict_pod_ipv4")
int tc_nodeport_snat_conflict_pod_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   POD_IP, SERVER_IP,
					   NODE_PORT, SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	set_identity_mark(ctx, POD_SEC_IDENTITY, MARK_MAGIC_IDENTITY);

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_snat_conflict_pod_ipv4")
int tc_nodeport_snat_conflict_pod_ipv4_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(POD_IP, 0, 0, 0, POD_SEC_IDENTITY,
			      0, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(POD_IP, 0, POD_SEC_IDENTITY, 0, 0);
	ipcache_v4_add_world_entry();

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_nodeport_snat_conflict_pod_ipv4")
int tc_nodeport_snat_conflict_pod_ipv4_check(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {
		.saddr   = SERVER_IP,
		.daddr   = POD_IP,
		.sport   = NODE_PORT,
		.dport   = SERVER_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags   = TUPLE_F_OUT,
	};

	test_init();
	assert(tc_nodeport_snat_conflict_assert_status(ctx));

	/* Pod traffic should NOT create a conntrack entry */
	struct ct_entry *ct_entry = map_lookup_elem(&cilium_ct_any4_global, &tuple);

	assert(!ct_entry);

	test_finish();
}

/*
 * IPv6: Create a request from a pod toward an external server, subjecting it
 * to the nat fwd path.
 *
 * We expect no conntrack to be created in this scenario.
 */
PKTGEN("tc", "tc_nodeport_snat_conflict_pod_ipv6")
int tc_nodeport_snat_conflict_pod_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv6_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   (__u8 *)POD_IP6, (__u8 *)SERVER_IP6,
					   NODE_PORT, SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	set_identity_mark(ctx, POD_SEC_IDENTITY, MARK_MAGIC_IDENTITY);

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_snat_conflict_pod_ipv6")
int tc_nodeport_snat_conflict_pod_ipv6_setup(struct __ctx_buff *ctx)
{
	union v6addr pod_ip6 = POD_IP6_ADDR;

	endpoint_v6_add_entry(&pod_ip6, 0, 0, 0, POD_SEC_IDENTITY,
			      (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry(&pod_ip6, 0, POD_SEC_IDENTITY, 0, 0);
	ipcache_v6_add_world_entry();

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_nodeport_snat_conflict_pod_ipv6")
int tc_nodeport_snat_conflict_pod_ipv6_check(struct __ctx_buff *ctx)
{
	struct ipv6_ct_tuple tuple = {
		.saddr   = SERVER_IP6_ADDR,
		.daddr   = POD_IP6_ADDR,
		.sport   = NODE_PORT,
		.dport   = SERVER_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags   = TUPLE_F_OUT,
	};

	test_init();
	assert(tc_nodeport_snat_conflict_assert_status(ctx));

	/* Pod traffic should NOT create a conntrack entry */
	struct ct_entry *ct_entry = map_lookup_elem(&cilium_ct_any6_global, &tuple);

	assert(!ct_entry);

	test_finish();
}
