// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4			1

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)

#define SERVER_IP		v4_ext_one
#define SERVER_PORT		__bpf_htons(222)

#define NODE_IP			v4_node_one

#define DST_IP			v4_ext_one
#define DST_IP2			v4_ext_two

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "bpf_lxc.c"

ASSIGN_CONFIG(__u16, endpoint_id, 233)
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one})
ASSIGN_CONFIG(bool, enable_extended_ip_protocols, true);
ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"

#define FROM_CONTAINER 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_CONTAINER] = &cil_from_container,
	},
};

/* Helper function to send packet from container, similar to pod_send_packet in lib/bpf_lxc.h */
static __always_inline int
pod_send_packet(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

/* Send an IGMP packet from pod to IGMP destination (allow all egress policy).
 *
 */
PKTGEN("tc", "lxc_igmp_egress")
int lxc_igmp_egress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct igmphdr *igmp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	igmp = pktgen__push_ipv4_igmp_packet(&builder,
					     (__u8 *)client_mac, (__u8 *)server_mac,
					     CLIENT_IP, DST_IP,
					     IGMP_HOST_MEMBERSHIP_REPORT);
	if (!igmp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "lxc_igmp_egress")
int lxc_igmp_egress_setup(struct __ctx_buff *ctx)
{
	policy_add_egress_allow_all_entry();
	endpoint_v4_add_entry(CLIENT_IP, 0, 0, ENDPOINT_F_HOST, LXC_ID,
			      0, (__u8 *)client_mac, (__u8 *)client_mac);
	ipcache_v4_add_entry(CLIENT_IP, 0, LXC_ID, 0, 0);
	ipcache_v4_add_world_entry();

	/* Set identity mark for the source pod */
	set_identity_mark(ctx, LXC_ID, MARK_MAGIC_IDENTITY);

	/* Send packet through container datapath */
	return pod_send_packet(ctx);
}

CHECK("tc", "lxc_igmp_egress")
int lxc_igmp_egress_check(const struct __ctx_buff *ctx)
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

	/* Check for egress CT entry */
	struct ipv4_ct_tuple tuple = {
		.daddr   = CLIENT_IP,
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

	policy_delete_egress_all_entry();

	test_finish();
}

/* Send an IGMP packet from pod to IGMP destination.
 *
 * The packet is allowed by the egress policy.
 */
PKTGEN("tc", "lxc_igmp_egress_policy")
int lxc_igmp_egress_policy_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct igmphdr *igmp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	igmp = pktgen__push_ipv4_igmp_packet(&builder,
					     (__u8 *)client_mac, (__u8 *)server_mac,
					     CLIENT_IP, DST_IP2,
					     IGMP_HOST_MEMBERSHIP_REPORT);
	if (!igmp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "lxc_igmp_egress_policy")
int lxc_igmp_egress_policy_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(CLIENT_IP, 0, 0, ENDPOINT_F_HOST, LXC_ID,
			      0, (__u8 *)client_mac, (__u8 *)client_mac);
	ipcache_v4_add_entry(CLIENT_IP, 0, LXC_ID, 0, 0);
	ipcache_v4_add_world_entry();
	policy_add_egress_allow_l4_entry(IPPROTO_IGMP, 0, 0);

	/* Set identity mark for the source pod */
	set_identity_mark(ctx, LXC_ID, MARK_MAGIC_IDENTITY);

	/* Send packet through container datapath */
	return pod_send_packet(ctx);
}

CHECK("tc", "lxc_igmp_egress_policy")
int lxc_igmp_egress_policy_check(const struct __ctx_buff *ctx)
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

	/* Check for egress CT entry */
	struct ipv4_ct_tuple tuple = {
		.daddr   = CLIENT_IP,
		.saddr   = DST_IP2,
		.dport   = 0,
		.sport   = 0,
		.nexthdr = IPPROTO_IGMP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	policy_delete_egress_all_entry();

	test_finish();
}

/* Send an IGMP packet from pod to IGMP destination.
 *
 * The packet is denied by the egress policy.
 */
PKTGEN("tc", "lxc_igmp_egress_policy_deny")
int lxc_igmp_egress_policy_deny_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct igmphdr *igmp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	igmp = pktgen__push_ipv4_igmp_packet(&builder,
					     (__u8 *)client_mac, (__u8 *)server_mac,
					     CLIENT_IP, DST_IP2,
					     IGMP_HOST_MEMBERSHIP_REPORT);
	if (!igmp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "lxc_igmp_egress_policy_deny")
int lxc_igmp_egress_policy_deny_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(CLIENT_IP, 0, 0, ENDPOINT_F_HOST, LXC_ID,
			      0, (__u8 *)client_mac, (__u8 *)client_mac);
	ipcache_v4_add_entry(CLIENT_IP, 0, LXC_ID, 0, 0);
	ipcache_v4_add_world_entry();
	policy_add_entry(true, 0, IPPROTO_IGMP, 0, 0, true);

	/* Set identity mark for the source pod */
	set_identity_mark(ctx, LXC_ID, MARK_MAGIC_IDENTITY);

	/* Send packet through container datapath */
	return pod_send_packet(ctx);
}

CHECK("tc", "lxc_igmp_egress_policy_deny")
int lxc_igmp_egress_policy_deny_check(const struct __ctx_buff *ctx)
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

	policy_delete_egress_all_entry();

	test_finish();
}
