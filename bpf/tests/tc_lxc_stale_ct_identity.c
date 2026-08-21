// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Test that stale src_sec_id in CT entries gets refreshed when an
 * endpoint's security identity changes. Covers both the egress path
 * (handle_ipv4_from_lxc -> ct_recreate4) and the ingress path
 * (ipv4_policy -> in-place update).
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4

#define OLD_IDENTITY	12345
#define NEW_IDENTITY	54321
#define REMOTE_ID	1000

#define LOCAL_IP	v4_pod_one
#define REMOTE_IP	v4_pod_two

#define EGRESS_LPORT	__bpf_htons(12345)
#define EGRESS_RPORT	__bpf_htons(54321)
#define INGRESS_LPORT	__bpf_htons(12121)
#define INGRESS_RPORT	__bpf_htons(21212)

static volatile const __u8 *local_mac = mac_one;
static volatile const __u8 *remote_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(__u32, security_label, NEW_IDENTITY)
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })

#include "lib/ipcache.h"
#include "lib/policy.h"

static __always_inline int
create_egress_ct_entry(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.saddr = REMOTE_IP,
		.daddr = LOCAL_IP,
		.dport = EGRESS_RPORT,
		.sport = EGRESS_LPORT,
		.flags = TUPLE_F_OUT,
	};
	struct ct_state ct_state = {
		.src_sec_id = OLD_IDENTITY,
	};

	return ct_create4(get_ct_map4(&tuple), &cilium_ct_any4_global,
			  &tuple, ctx, CT_EGRESS, &ct_state, NULL);
}

static __always_inline int
create_ingress_ct_entry(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.saddr = LOCAL_IP,
		.daddr = REMOTE_IP,
		.dport = INGRESS_LPORT,
		.sport = INGRESS_RPORT,
		.flags = TUPLE_F_IN,
	};
	struct ct_state ct_state = {
		.src_sec_id = OLD_IDENTITY,
	};

	return ct_create4(get_ct_map4(&tuple), &cilium_ct_any4_global,
			  &tuple, ctx, CT_INGRESS, &ct_state, NULL);
}

static __always_inline struct tcphdr *
build_non_syn_packet(struct __ctx_buff *ctx, __be32 sip, __be32 dip,
		     __be16 sport, __be16 dport)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)local_mac, (__u8 *)remote_mac,
					  sip, dip, sport, dport);
	if (!l4)
		return NULL;

	l4->syn = 0;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return NULL;

	pktgen__finish(&builder);
	return l4;
}

/*
 * egress: handle_ipv4_from_lxc should recreate CT when src_sec_id
 * doesn't match SECLABEL.
 */
PKTGEN("tc", "egress_stale_ct_identity")
int egress_pktgen(struct __ctx_buff *ctx)
{
	if (!build_non_syn_packet(ctx, LOCAL_IP, REMOTE_IP,
				  EGRESS_LPORT, EGRESS_RPORT))
		return TEST_ERROR;
	return 0;
}

SETUP("tc", "egress_stale_ct_identity")
int egress_setup(struct __ctx_buff *ctx)
{
	if (create_egress_ct_entry(ctx) < 0)
		return TEST_ERROR;

	ipcache_v4_add_entry(REMOTE_IP, 0, REMOTE_ID, 0, 0);
	policy_add_egress_allow_l3_entry(REMOTE_ID);

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

CHECK("tc", "egress_stale_ct_identity")
int egress_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ct_entry *entry;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	test_log("egress status_code: %d", *status_code);

	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.saddr = REMOTE_IP,
		.daddr = LOCAL_IP,
		.dport = EGRESS_RPORT,
		.sport = EGRESS_LPORT,
		.flags = TUPLE_F_OUT,
	};

	entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!entry)
		test_fatal("egress CT entry not found");

	test_log("egress src_sec_id: %u (want %u)", entry->src_sec_id, NEW_IDENTITY);
	assert(entry->src_sec_id == NEW_IDENTITY);

	test_finish();
}

/*
 * ingress: ipv4_policy should update CT src_sec_id in-place when
 * the source identity doesn't match the CT entry.
 */
PKTGEN("tc", "ingress_stale_ct_identity")
int ingress_pktgen(struct __ctx_buff *ctx)
{
	if (!build_non_syn_packet(ctx, REMOTE_IP, LOCAL_IP,
				  INGRESS_RPORT, INGRESS_LPORT))
		return TEST_ERROR;
	return 0;
}

SETUP("tc", "ingress_stale_ct_identity")
int ingress_setup(struct __ctx_buff *ctx)
{
	if (create_ingress_ct_entry(ctx) < 0)
		return TEST_ERROR;

	ipcache_v4_add_entry(REMOTE_IP, 0, NEW_IDENTITY, 0, 0);
	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0);

	local_delivery_fill_meta(ctx, NEW_IDENTITY, true, false, false, 0);

	tail_call_static(ctx, entry_call_map, TO_CONTAINER_TAILCALL);
	return TEST_ERROR;
}

CHECK("tc", "ingress_stale_ct_identity")
int ingress_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ct_entry *entry;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	test_log("ingress status_code: %d", *status_code);

	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.saddr = LOCAL_IP,
		.daddr = REMOTE_IP,
		.dport = INGRESS_LPORT,
		.sport = INGRESS_RPORT,
		.flags = TUPLE_F_IN,
	};

	entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!entry)
		test_fatal("ingress CT entry not found");

	test_log("ingress src_sec_id: %u (want %u)", entry->src_sec_id, NEW_IDENTITY);
	assert(entry->src_sec_id == NEW_IDENTITY);

	test_finish();
}
