// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_IPV4_FRAGMENTS
#define ENABLE_NODEPORT

#include "lib/bpf_host.h"

ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

#include "lib/endpoint.h"
#include "lib/lb.h"
#include "scapy.h"

#define CLIENT_IP	v4_ext_one
#define CLIENT_PORT	tcp_src_one

#define FRONTEND_IP	v4_svc_one
#define FRONTEND_PORT	tcp_svc_one

#define BACKEND_IP	v4_pod_one
#define BACKEND_PORT	tcp_dst_one

#define NAT_REV_INDEX	1
#define BACKEND_COUNT	1
#define BACKEND_ID	124
#define BACKEND_IFINDEX	11

/* Expected CT tuple to check for conntrack */
#define EXPECTED_CT_TUPLE {\
	.saddr = CLIENT_IP, \
	.sport = FRONTEND_PORT, \
	.daddr = FRONTEND_IP, \
	.dport = CLIENT_PORT, \
	.nexthdr = IPPROTO_TCP, \
	.flags = TUPLE_F_SERVICE }

/* Expected fragment ID to check for conntrack */
#define EXPECTED_FRAG_ID { \
	.saddr = CLIENT_IP, \
	.daddr = FRONTEND_IP, \
	.id = bpf_htons(256), \
	.proto = IPPROTO_TCP }

/* Expected metrics key to check for fragment-related metrics */
#define EXPECTED_METRIC_KEY { \
	.reason = REASON_FRAG_PACKET, \
	.dir = METRIC_SERVICE }

/* Test that the 1st fragment of an external-to-nodeport request is handled correctly */
PKTGEN("tc", "tc_nodeport_lb4_fragments_1")
int nodeport_lb4_fragments_1_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(LB4_NODEPORT_FRAGMENT1, lb4_nodeport_fragment1);
	BUILDER_PUSH_BUF(builder, LB4_NODEPORT_FRAGMENT1);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb4_fragments_1")
int nodeport_lb4_fragments_1_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(BACKEND_IP, BACKEND_IFINDEX, 0, 0, 0, 0,
			      (__u8 *)mac_one, (__u8 *)mac_two);
	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, BACKEND_COUNT,
				     NAT_REV_INDEX, SVC_FLAG_ROUTABLE | SVC_FLAG_NODEPORT, 0);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, BACKEND_COUNT, BACKEND_ID,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb4_fragments_1")
int nodeport_lb4_fragments_1_check(struct __ctx_buff *ctx)
{
	__u32 *status_code;
	void *data_end;
	void *data;
	struct ct_entry *ct_entry;
	struct ipv4_frag_l4ports *l4ports;
	struct ipv4_ct_tuple expected_ct_tuple = EXPECTED_CT_TUPLE;
	struct ipv4_frag_id expected_frag_id = EXPECTED_FRAG_ID;
	struct metrics_key metric_key = EXPECTED_METRIC_KEY;
	__u64 count = 1;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	status_code = data;

	/* Ensure packet offset and status code. */
	assert(data + sizeof(__u32) <= data_end);
	assert(*status_code == CTX_ACT_OK);

	/* Ensure fragment L4 ports are being tracked. */
	l4ports = map_lookup_elem(&cilium_ipv4_frag_datagrams, &expected_frag_id);
	assert(l4ports);
	assert(l4ports->dport == FRONTEND_PORT);
	assert(l4ports->sport == CLIENT_PORT);

	/* Ensure fragment-related metrics are updated accordingly. */
	assert_metrics_count(metric_key, count);

	/* Ensure packet has been DNAT correctly. */
	BUF_DECL(LB4_NODEPORT_FRAGMENT1_POST_DNAT, lb4_nodeport_fragment1_post_dnat);
	ASSERT_CTX_BUF_OFF("tcp4_first_fragment_ok", "Ether", ctx, sizeof(__u32),
			   LB4_NODEPORT_FRAGMENT1_POST_DNAT,
			   sizeof(BUF(LB4_NODEPORT_FRAGMENT1_POST_DNAT)));

	/* Ensure CT entry is updated accordingly (SVC). */
	ct_entry = map_lookup_elem(get_ct_map4(&expected_ct_tuple), &expected_ct_tuple);
	assert(ct_entry);
	assert(ct_entry->packets == count);
	assert(ct_entry->bytes == sizeof(BUF(LB4_NODEPORT_FRAGMENT1_POST_DNAT)));

	test_finish();
}

/* Test that the 2nd fragment of an external-to-nodeport request is handled correctly */
PKTGEN("tc", "tc_nodeport_lb4_fragments_2")
int nodeport_lb4_fragments_2_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(LB4_NODEPORT_FRAGMENT2, lb4_nodeport_fragment2);
	BUILDER_PUSH_BUF(builder, LB4_NODEPORT_FRAGMENT2);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb4_fragments_2")
int nodeport_lb4_fragments_2_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb4_fragments_2")
int nodeport_lb4_fragments_2_check(struct __ctx_buff *ctx)
{
	__u32 *status_code;
	void *data_end;
	void *data;
	struct ct_entry *ct_entry;
	struct ipv4_ct_tuple expected_ct_tuple = EXPECTED_CT_TUPLE;
	struct metrics_key metric_key = EXPECTED_METRIC_KEY;
	__u64 count = 2;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	status_code = data;

	/* Ensure packet offset and status code. */
	assert(data + sizeof(__u32) <= data_end);
	assert(*status_code == CTX_ACT_OK);

	/* Ensure fragment-related metrics are updated accordingly. */
	assert_metrics_count(metric_key, count);

	/* Ensure packet has been DNAT correctly. */
	BUF_DECL(LB4_NODEPORT_FRAGMENT1_POST_DNAT, lb4_nodeport_fragment1_post_dnat);
	BUF_DECL(LB4_NODEPORT_FRAGMENT2_POST_DNAT, lb4_nodeport_fragment2_post_dnat);
	ASSERT_CTX_BUF_OFF("tcp4_second_fragment_ok", "Ether", ctx, sizeof(__u32),
			   LB4_NODEPORT_FRAGMENT2_POST_DNAT,
			   sizeof(BUF(LB4_NODEPORT_FRAGMENT2_POST_DNAT)));

	/* Ensure CT entry is updated accordingly (SVC). */
	ct_entry = map_lookup_elem(get_ct_map4(&expected_ct_tuple), &expected_ct_tuple);
	assert(ct_entry);
	assert(ct_entry->packets == count);
	assert(ct_entry->bytes == sizeof(BUF(LB4_NODEPORT_FRAGMENT1_POST_DNAT)) +
				  sizeof(BUF(LB4_NODEPORT_FRAGMENT2_POST_DNAT)));

	test_finish();
}
