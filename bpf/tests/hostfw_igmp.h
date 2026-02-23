// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4			1
#define ENABLE_HOST_FIREWALL		1

#define NODE_IP				v4_node_one
#define NODE_IP2			v4_node_two

#define DST_IP			v4_ext_one
#define DST_IP2			v4_ext_two

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *dst_mac = mac_two;
static volatile const __u8 *node_mac2 = mac_three;
static volatile const __u8 *dst_mac2 = mac_four;

#include "lib/bpf_host.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"

#ifdef TEST_EXTENDED_PROTOCOLS
ASSIGN_CONFIG(bool, enable_extended_ip_protocols, true);
#endif
ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

/* Send an IGMP packet from host to IGMP destination (allow all egress policy).
 *
 */
PKTGEN("tc", "hostfw_igmp_1_egress")
int hostfw_igmp_egress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct igmphdr *igmp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	igmp = pktgen__push_ipv4_igmp_packet(&builder,
					     (__u8 *)node_mac, (__u8 *)dst_mac,
					     NODE_IP, DST_IP,
					     IGMP_HOST_MEMBERSHIP_REPORT);
	if (!igmp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hostfw_igmp_1_egress")
int hostfw_igmp_egress_setup(struct __ctx_buff *ctx)
{
	policy_add_egress_allow_all_entry();
	endpoint_v4_add_entry(NODE_IP, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      0, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(NODE_IP, 0, HOST_ID, 0, 0);
	ipcache_v4_add_world_entry();

	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK("tc", "hostfw_igmp_1_egress")
int hostfw_igmp_egress_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

#ifdef TEST_EXTENDED_PROTOCOLS
	assert(*status_code == CTX_ACT_OK);

	/* Check for egress CT entry */
	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = DST_IP,
		.dport   = 0,
		.sport   = 0,
		.nexthdr = IPPROTO_IGMP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	assert(ct_entry->packets == 1);
#else
	assert(*status_code == CTX_ACT_DROP);
#endif

	policy_delete_egress_all_entry();

	test_finish();
}

/* Send an IGMP packet from the IGMP destination to host. Packet is allowed based on
 * conntrack entry (no ingress policy).
 *
 */
PKTGEN("tc", "hostfw_igmp_2_ingress")
int hostfw_igmp_ingress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct igmphdr *igmp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	igmp = pktgen__push_ipv4_igmp_packet(&builder,
					     (__u8 *)dst_mac, (__u8 *)node_mac,
					     DST_IP, NODE_IP,
					     IGMP_HOST_MEMBERSHIP_REPORT);
	if (!igmp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hostfw_igmp_2_ingress")
int hostfw_igmp_ingress_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK("tc", "hostfw_igmp_2_ingress")
int hostfw_igmp_ingress_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

#ifdef TEST_EXTENDED_PROTOCOLS
	assert(*status_code == CTX_ACT_OK);

	/* Check whether this packet hits the existing egress entry */
	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = DST_IP,
		.dport   = 0,
		.sport   = 0,
		.nexthdr = IPPROTO_IGMP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	assert(ct_entry->packets == 2);
#else
	assert(*status_code == CTX_ACT_DROP);
#endif

	test_finish();
}

/* Send a packet from host to IGMP destination.
 *
 * The packet is allowed by the egress policy.
 */
PKTGEN("tc", "hostfw_igmp_3_egress_policy")
int hostfw_igmp_egress_policy_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct igmphdr *igmp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	igmp = pktgen__push_ipv4_igmp_packet(&builder,
					     (__u8 *)node_mac2, (__u8 *)dst_mac2,
					     NODE_IP2, DST_IP2,
					     IGMP_HOST_MEMBERSHIP_REPORT);
	if (!igmp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hostfw_igmp_3_egress_policy")
int hostfw_igmp_egress_policy_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(NODE_IP2, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      0, (__u8 *)node_mac2, (__u8 *)node_mac2);
	ipcache_v4_add_entry(NODE_IP2, 0, HOST_ID, 0, 0);
	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	policy_add_egress_allow_l4_entry(IPPROTO_IGMP, 0, 0);

	return netdev_send_packet(ctx);
}

CHECK("tc", "hostfw_igmp_3_egress_policy")
int hostfw_igmp_egress_policy_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

#ifdef TEST_EXTENDED_PROTOCOLS
	assert(*status_code == CTX_ACT_OK);

	/* Check for egress CT entry */
	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP2,
		.saddr   = DST_IP2,
		.dport   = 0,
		.sport   = 0,
		.nexthdr = IPPROTO_IGMP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");
#else
	assert(*status_code == CTX_ACT_DROP);
#endif

	policy_delete_egress_all_entry();
	test_finish();
}

/* Send a packet from IGMP destination to host. The packet doesn't match any
 * egress conntrack entry.
 *
 * The packet is dropped by the ingress policy.
 */
PKTGEN("tc", "hostfw_igmp_4_ingress_policy")
int hostfw_igmp_ingress_policy_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct igmphdr *igmp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	igmp = pktgen__push_ipv4_igmp_packet(&builder,
					     (__u8 *)dst_mac, (__u8 *)node_mac2,
					     DST_IP, NODE_IP2,
					     IGMP_HOST_MEMBERSHIP_REPORT);
	if (!igmp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hostfw_igmp_4_ingress_policy")
int hostfw_igmp_ingress_policy_setup(struct __ctx_buff *ctx)
{
	policy_add_ingress_deny_l4_entry(IPPROTO_IGMP, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "hostfw_igmp_4_ingress_policy")
int hostfw_igmp_ingress_policy_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_DROP);

	test_finish();
}
