// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(bool, policy_deny_response_enabled, true)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"

#define CLIENT_IP v4_pod_one
#define TARGET_IP v4_ext_one

static __always_inline int build_packet(struct __ctx_buff *ctx,
					__be32 saddr, __be32 daddr)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  saddr, daddr,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

static __always_inline void init_policy_reject_response_setup(__be32 saddr,
							      __be32 daddr,
							      __u32 saddr_sec_identity,
							      __u32 daddr_sec_identity
)
{
	/* Add ipcache entries */
	ipcache_v4_add_entry(saddr, 0, saddr_sec_identity, 0, 0);
	ipcache_v4_add_entry(daddr, 0, daddr_sec_identity, 0, 0);

	/* Add policy that denies egress to target */
	policy_add_egress_deny_all_entry();
}

static __always_inline int check_policy_reject_response(const struct __ctx_buff *ctx,
							__be32 saddr, __be32 daddr)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct icmphdr *icmp;

	test_init();
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Should redirect ICMP response back to interface */
	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	/* Verify this is an ICMP response packet */
	if (l3->protocol != IPPROTO_ICMP)
		test_fatal("expected ICMP protocol, got %d", l3->protocol);

	/* Source should be swapped to target, destination should be source */
	if (l3->saddr != daddr)
		test_fatal("ICMP src should be destination IP");

	if (l3->daddr != saddr)
		test_fatal("ICMP dst should be source IP");

	icmp = (void *)l3 + sizeof(struct iphdr);

	if ((void *)icmp + sizeof(struct icmphdr) > data_end)
		test_fatal("ICMP header out of bounds");

	/* Verify ICMP error type and code for policy rejection */
	if (icmp->type != ICMP_DEST_UNREACH)
		test_fatal("expected ICMP_DEST_UNREACH, got type %d", icmp->type);

	if (icmp->code != ICMP_PKT_FILTERED)
		test_fatal("expected ICMP_PKT_FILTERED, got code %d", icmp->code);

	test_finish();
}

PKTGEN("tc", "policy_reject_response_egress_v4")
int policy_reject_response_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, CLIENT_IP, TARGET_IP);
}

SETUP("tc", "policy_reject_response_egress_v4")
int policy_reject_response_setup(struct __ctx_buff *ctx)
{
	init_policy_reject_response_setup(CLIENT_IP, TARGET_IP, 112233, 445566);

	/* Add endpoint for source */
	endpoint_v4_add_entry(CLIENT_IP, 0, 0, 0, 0, 0, NULL, NULL);

	return pod_send_packet(ctx);
}

CHECK("tc", "policy_reject_response_egress_v4")
int policy_reject_response_check(const struct __ctx_buff *ctx)
{
	return check_policy_reject_response(ctx, CLIENT_IP, TARGET_IP);
}

#define INGRESS_WORLD_SRC v4_ext_one
#define INGRESS_REMOTE_NODE_SRC v4_node_two
#define INGRESS_LOCAL_NODE_SRC v4_node_one
#define INGRESS_POD_SRC v4_pod_two
#define INGRESS_DST_IP v4_pod_one

/* Test policy deny response on ingress WORLD -> POD
 * The return should be an ICMP packet filtered from POD -> WORLD
 */
PKTGEN("tc", "policy_reject_response_ingress_from_world_v4")
int policy_reject_response_ingress_from_world_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, INGRESS_WORLD_SRC, INGRESS_DST_IP);
}

SETUP("tc", "policy_reject_response_ingress_from_world_v4")
int policy_reject_response_ingress_from_world_setup(struct __ctx_buff *ctx)
{
	init_policy_reject_response_setup(INGRESS_WORLD_SRC, INGRESS_DST_IP, WORLD_ID, 112233);

	/* Add endpoint for destination */
	endpoint_v4_add_entry(INGRESS_DST_IP, 0, 0, 0, 0, 0, NULL, NULL);

	return pod_receive_packet(ctx);
}

CHECK("tc", "policy_reject_response_ingress_from_world_v4")
int policy_reject_response_ingress_from_world_check(const struct __ctx_buff *ctx)
{
	return check_policy_reject_response(ctx, INGRESS_WORLD_SRC, INGRESS_DST_IP);
}

/* Test policy deny response on ingress REMOTE_NODE -> POD
 * The return should be an ICMP packet filtered from POD -> REMOTE_NODE
 */
PKTGEN("tc", "policy_reject_response_ingress_from_remote_node_v4")
int policy_reject_response_ingress_from_remote_node_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, INGRESS_REMOTE_NODE_SRC, INGRESS_DST_IP);
}

SETUP("tc", "policy_reject_response_ingress_from_remote_node_v4")
int policy_reject_response_ingress_from_remote_node_setup(struct __ctx_buff *ctx)
{
	init_policy_reject_response_setup(INGRESS_REMOTE_NODE_SRC, INGRESS_DST_IP,
					  REMOTE_NODE_ID, 112233);

	/* Add endpoint for destination */
	endpoint_v4_add_entry(INGRESS_DST_IP, 0, 0, 0, 0, 0, NULL, NULL);

	return pod_receive_packet(ctx);
}

CHECK("tc", "policy_reject_response_ingress_from_remote_node_v4")
int policy_reject_response_ingress_from_remote_node_check(const struct __ctx_buff *ctx)
{
	return check_policy_reject_response(ctx, INGRESS_REMOTE_NODE_SRC, INGRESS_DST_IP);
}

/* Test policy deny response on ingress LOCAL_NODE -> POD
 * The return should be an ICMP packet filtered from POD -> LOCAL_NODE
 */
PKTGEN("tc", "policy_reject_response_ingress_from_local_node_v4")
int policy_reject_response_ingress_from_local_node_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, INGRESS_LOCAL_NODE_SRC, INGRESS_DST_IP);
}

SETUP("tc", "policy_reject_response_ingress_from_local_node_v4")
int policy_reject_response_ingress_from_local_node_setup(struct __ctx_buff *ctx)
{
	init_policy_reject_response_setup(INGRESS_LOCAL_NODE_SRC, INGRESS_DST_IP, HOST_ID, 112233);

	/* Add endpoint for destination */
	endpoint_v4_add_entry(INGRESS_DST_IP, 0, 0, 0, 0, 0, NULL, NULL);

	return pod_receive_packet(ctx);
}

CHECK("tc", "policy_reject_response_ingress_from_local_node_v4")
int policy_reject_response_ingress_from_local_node_check(const struct __ctx_buff *ctx)
{
	return check_policy_reject_response(ctx, INGRESS_LOCAL_NODE_SRC, INGRESS_DST_IP);
}

/* Test policy deny response on ingress POD_OTHER -> POD
 * The return should be an ICMP packet filtered from POD -> POD_OTHER
 */
PKTGEN("tc", "policy_reject_response_ingress_from_pod_v4")
int policy_reject_response_ingress_from_pod_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, INGRESS_POD_SRC, INGRESS_DST_IP);
}

SETUP("tc", "policy_reject_response_ingress_from_pod_v4")
int policy_reject_response_ingress_from_pod_setup(struct __ctx_buff *ctx)
{
	init_policy_reject_response_setup(INGRESS_POD_SRC, INGRESS_DST_IP, 112233, 445566);

	/* Add endpoint for destination */
	endpoint_v4_add_entry(INGRESS_DST_IP, 0, 0, 0, 0, 0, NULL, NULL);
	endpoint_v4_add_entry(INGRESS_POD_SRC, 0, 0, 0, 0, 0, NULL, NULL);

	return pod_receive_packet(ctx);
}

CHECK("tc", "policy_reject_response_ingress_from_pod_v4")
int policy_reject_response_ingress_from_pod_check(const struct __ctx_buff *ctx)
{
	return check_policy_reject_response(ctx, INGRESS_POD_SRC, INGRESS_DST_IP);
}
