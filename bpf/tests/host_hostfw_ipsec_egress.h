/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Tests that MARK_MAGIC_ENCRYPT skips hostFW egress for the post-XFRM ESP
 * pass, while ordinary host-originated traffic is still evaluated.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4			1
#define ENABLE_IPV6			1
#define ENABLE_HOST_FIREWALL		1

#define LOCAL_NODE_IP			v4_node_one
#define REMOTE_NODE_IP			v4_node_two
#define LOCAL_NODE_IP6			((const union v6addr *)v6_node_one)
#define REMOTE_NODE_IP6			((const union v6addr *)v6_node_two)

#define POD_SRC_IP			v4_pod_one
#define POD_DST_IP			v4_pod_one_on_node_two
#define POD_SRC_IDENTITY		(CIDR_IDENTITY_RANGE_START - 1)
#define POD_DST_IDENTITY		(CIDR_IDENTITY_RANGE_START - 2)

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *peer_mac = mac_two;

#include "lib/bpf_host.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"

ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

/*
 * Test 1: hostfw_ipsec_egress_no_bogus_verdict (IPv4)
 *
 * ESP packet shaped like the post-XFRM pass. A host egress deny policy is
 * installed; MARK_MAGIC_ENCRYPT must bypass hostFW egress and leave no CT
 * entry for the outer ESP tuple.
 */
PKTGEN("tc", "hostfw_ipsec_egress_v4_no_bogus_verdict")
int hostfw_ipsec_egress_v4_no_bogus_verdict_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)node_mac, (__u8 *)peer_mac,
				      LOCAL_NODE_IP, REMOTE_NODE_IP);
	if (!l3)
		return TEST_ERROR;
	l3->protocol = IPPROTO_ESP;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "hostfw_ipsec_egress_v4_no_bogus_verdict")
int hostfw_ipsec_egress_v4_no_bogus_verdict_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(LOCAL_NODE_IP, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      0, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(LOCAL_NODE_IP, 0, HOST_ID, 0, 0);
	ipcache_v4_add_entry(REMOTE_NODE_IP, 0, REMOTE_NODE_ID, 0, 0);
	ipcache_v4_add_world_entry();

	/* This would drop the ESP tuple if hostFW egress ran. */
	policy_add_egress_deny_all_entry();

	/* Mark the skb as the post-XFRM pass. */
	ctx->mark = MARK_MAGIC_ENCRYPT;

	return netdev_send_packet(ctx);
}

CHECK("tc", "hostfw_ipsec_egress_v4_no_bogus_verdict")
int hostfw_ipsec_egress_v4_no_bogus_verdict_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v4_del_entry(LOCAL_NODE_IP);
	policy_delete_egress_all_entry();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	/* The outer ESP tuple must not be tracked by hostFW egress. */
	struct ipv4_ct_tuple tuple = {
		.daddr   = REMOTE_NODE_IP,
		.saddr   = LOCAL_NODE_IP,
		.dport   = 0,
		.sport   = 0,
		.nexthdr = IPPROTO_ESP,
		.flags   = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (ct_entry)
		test_fatal("hostFW egress unexpectedly created CT on encrypted recirculation");

	test_finish();
}

/*
 * Test 2: hostfw_ipsec_egress_v4_host_originated_still_evaluated
 *
 * Scope guard: MARK_MAGIC_HOST must not match the encrypted-recirculation
 * skip, so host-originated ICMP still hits egress policy.
 */
PKTGEN("tc", "hostfw_ipsec_egress_v4_host_originated_drop")
int hostfw_ipsec_egress_v4_host_originated_drop_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)node_mac, (__u8 *)peer_mac,
				      LOCAL_NODE_IP, REMOTE_NODE_IP);
	if (!l3)
		return TEST_ERROR;
	l3->protocol = IPPROTO_ICMP;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "hostfw_ipsec_egress_v4_host_originated_drop")
int hostfw_ipsec_egress_v4_host_originated_drop_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(LOCAL_NODE_IP, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      0, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(LOCAL_NODE_IP, 0, HOST_ID, 0, 0);
	ipcache_v4_add_entry(REMOTE_NODE_IP, 0, REMOTE_NODE_ID, 0, 0);
	ipcache_v4_add_world_entry();

	policy_add_egress_deny_all_entry();

	/* Host-originated traffic must still hit hostFW egress. */
	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK("tc", "hostfw_ipsec_egress_v4_host_originated_drop")
int hostfw_ipsec_egress_v4_host_originated_drop_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v4_del_entry(LOCAL_NODE_IP);
	policy_delete_egress_all_entry();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	test_finish();
}

/*
 * Test 3: hostfw_ipsec_egress_v4_clear_pass_short_circuits
 *
 * Clear pod-to-pod traffic should not trigger hostFW egress because neither
 * the source identity nor the ipcache source identity is HOST_ID.
 */
PKTGEN("tc", "hostfw_ipsec_egress_v4_clear_pass")
int hostfw_ipsec_egress_v4_clear_pass_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)node_mac, (__u8 *)peer_mac,
				      POD_SRC_IP, POD_DST_IP);
	if (!l3)
		return TEST_ERROR;
	l3->protocol = IPPROTO_TCP;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "hostfw_ipsec_egress_v4_clear_pass")
int hostfw_ipsec_egress_v4_clear_pass_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(POD_SRC_IP, 0, POD_SRC_IDENTITY, 0, 0);
	ipcache_v4_add_entry(POD_DST_IP, 0, POD_DST_IDENTITY, REMOTE_NODE_IP, 0);

	/* The clear pod-to-pod pass should bypass this host policy. */
	policy_add_egress_deny_all_entry();

	set_identity_mark(ctx, POD_SRC_IDENTITY, MARK_MAGIC_IDENTITY);

	return netdev_send_packet(ctx);
}

CHECK("tc", "hostfw_ipsec_egress_v4_clear_pass")
int hostfw_ipsec_egress_v4_clear_pass_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	policy_delete_egress_all_entry();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* HostFW egress skipped the pod-sourced packet. */
	assert(*status_code == CTX_ACT_OK);

	test_finish();
}

/*
 * Test 4: hostfw_ipsec_egress_v6_no_bogus_verdict
 *
 * IPv6 sibling of Test 1.
 */
PKTGEN("tc", "hostfw_ipsec_egress_v6_no_bogus_verdict")
int hostfw_ipsec_egress_v6_no_bogus_verdict_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6hdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv6_packet(&builder, (__u8 *)node_mac, (__u8 *)peer_mac,
				      (__u8 *)LOCAL_NODE_IP6, (__u8 *)REMOTE_NODE_IP6);
	if (!l3)
		return TEST_ERROR;
	l3->nexthdr = IPPROTO_ESP;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "hostfw_ipsec_egress_v6_no_bogus_verdict")
int hostfw_ipsec_egress_v6_no_bogus_verdict_setup(struct __ctx_buff *ctx)
{
	ipcache_v6_add_entry(LOCAL_NODE_IP6, 0, HOST_ID, 0, 0);
	ipcache_v6_add_entry(REMOTE_NODE_IP6, 0, REMOTE_NODE_ID, 0, 0);

	policy_add_egress_deny_all_entry();

	ctx->mark = MARK_MAGIC_ENCRYPT;

	return netdev_send_packet(ctx);
}

CHECK("tc", "hostfw_ipsec_egress_v6_no_bogus_verdict")
int hostfw_ipsec_egress_v6_no_bogus_verdict_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	policy_delete_egress_all_entry();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	test_finish();
}
