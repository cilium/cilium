// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV6
#define ENABLE_IPV6_FRAGMENTS
#define ENABLE_NODEPORT

#include "lib/bpf_host.h"

ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

#include "lib/endpoint.h"
#include "lib/lb.h"
#include "scapy.h"

#define CLIENT_IP	v6_ext_node_one
#define CLIENT_IP_RAW	v6_ext_node_one_addr
#define CLIENT_PORT	tcp_src_one

#define FRONTEND_IP	v6_svc_one
#define FRONTEND_IP_RAW v6_svc_one_addr
#define FRONTEND_PORT	tcp_svc_one

#define BACKEND_IP	v6_pod_one
#define BACKEND_PORT	tcp_dst_one

#define NAT_REV_INDEX	1
#define BACKEND_COUNT	1
#define BACKEND_ID	124
#define BACKEND_IFINDEX	11

/* Expected number of bytes received (incremental) */
__u64 expected_bytes;

/* Expected fragment ID to check for L4 ports tracking */
struct ipv6_frag_id expected_frag_id = {
	.saddr = { .addr = CLIENT_IP_RAW },
	.daddr = { .addr = FRONTEND_IP_RAW },
	.id = bpf_htonl(256),
	.proto = IPPROTO_TCP,
};

/* Expected CT tuple to check for conntrack */
struct ipv6_ct_tuple expected_ct_tuple = {
	.saddr   = { .addr = CLIENT_IP_RAW },
	.sport   = FRONTEND_PORT,
	.daddr   = { .addr = FRONTEND_IP_RAW },
	.dport   = CLIENT_PORT,
	.nexthdr = IPPROTO_TCP,
	.flags   = TUPLE_F_SERVICE,
};

/* Test that the 1st fragment of an external-to-nodeport request is handled correctly */
PKTGEN("tc", "tc_nodeport_lb6_fragment1")
int nodeport_lb6_fragment1_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(LB6_NODEPORT_FRAGMENT1, lb6_nodeport_fragment1);
	BUILDER_PUSH_BUF(builder, LB6_NODEPORT_FRAGMENT1);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb6_fragment1")
int nodeport_lb6_fragment1_setup(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)BACKEND_IP, BACKEND_IFINDEX, 0, 0, 0,
			      (__u8 *)mac_one, (__u8 *)mac_two);
	lb_v6_add_service_with_flags((union v6addr *)FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, BACKEND_COUNT,
				     NAT_REV_INDEX, SVC_FLAG_ROUTABLE | SVC_FLAG_NODEPORT, 0);
	lb_v6_add_backend((union v6addr *)FRONTEND_IP, FRONTEND_PORT, BACKEND_COUNT, BACKEND_ID,
			  (union v6addr *)BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	expected_bytes = ctx_full_len(ctx);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb6_fragment1")
int nodeport_lb6_fragment1_check(struct __ctx_buff *ctx)
{
	__u32 *status_code;
	void *data_end;
	void *data;
	struct ipv6_frag_l4ports *l4ports;
	struct ct_entry *ct_entry;
	struct metrics_key metric_key = {
		.reason = REASON_FRAG_PACKET,
		.dir = METRIC_SERVICE,
	};
	__u64 count = 1;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	status_code = data;

	assert(data + sizeof(__u32) <= data_end);

	assert(*status_code == CTX_ACT_OK);

	/* Ensure fragment L4 ports are being tracked. */
	l4ports = map_lookup_elem(&cilium_ipv6_frag_datagrams, &expected_frag_id);
	assert(l4ports);
	assert(l4ports->dport == FRONTEND_PORT);
	assert(l4ports->sport == CLIENT_PORT);

	/* Ensure fragment-related metrics are updated accordingly. */
	assert_metrics_count(metric_key, count);

	/* Ensure CT entry is updated accordingly (SVC). */
	ct_entry = map_lookup_elem(get_ct_map6(&expected_ct_tuple), &expected_ct_tuple);
	assert(ct_entry);
	assert(ct_entry->packets == 1);
	assert(ct_entry->bytes == expected_bytes);

	BUF_DECL(LB6_NODEPORT_FRAGMENT1_POST_DNAT, lb6_nodeport_fragment1_post_dnat);
	ASSERT_CTX_BUF_OFF("tcp6_first_fragment_ok", "Ether", ctx, sizeof(__u32),
			   LB6_NODEPORT_FRAGMENT1_POST_DNAT,
			   sizeof(BUF(LB6_NODEPORT_FRAGMENT1_POST_DNAT)));

	test_finish();
}

/* Test that the 2nd fragment of an external-to-nodeport request is handled correctly */
PKTGEN("tc", "tc_nodeport_lb6_fragment2")
int nodeport_lb6_fragment2_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(LB6_NODEPORT_FRAGMENT2, lb6_nodeport_fragment2);
	BUILDER_PUSH_BUF(builder, LB6_NODEPORT_FRAGMENT2);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb6_fragment2")
int nodeport_lb6_fragment2_setup(struct __ctx_buff *ctx)
{
	expected_bytes = expected_bytes + ctx_full_len(ctx);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb6_fragment2")
int nodeport_lb6_fragment2_check(struct __ctx_buff *ctx)
{
	__u32 *status_code;
	void *data_end;
	void *data;
	struct ipv6_frag_l4ports *l4ports;
	struct ct_entry *ct_entry;
	struct metrics_key metric_key = {
		.reason = REASON_FRAG_PACKET,
		.dir = METRIC_SERVICE,
	};
	__u64 count = 2;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	status_code = data;

	assert(data + sizeof(__u32) <= data_end);

	assert(*status_code == CTX_ACT_OK);

	/* Ensure fragment L4 ports were being correctly retrieved. */
	l4ports = map_lookup_elem(&cilium_ipv6_frag_datagrams, &expected_frag_id);
	assert(l4ports);
	assert(l4ports->dport == FRONTEND_PORT);
	assert(l4ports->sport == CLIENT_PORT);

	/* Ensure fragment-related metrics are updated accordingly. */
	assert_metrics_count(metric_key, count);

	/* Ensure CT entry is updated accordingly (SVC). */
	ct_entry = map_lookup_elem(get_ct_map6(&expected_ct_tuple), &expected_ct_tuple);
	assert(ct_entry);
	assert(ct_entry->packets == 2);
	assert(ct_entry->bytes == expected_bytes);

	BUF_DECL(LB6_NODEPORT_FRAGMENT2_POST_DNAT, lb6_nodeport_fragment2_post_dnat);
	ASSERT_CTX_BUF_OFF("tcp6_second_fragment_ok", "Ether", ctx, sizeof(__u32),
			   LB6_NODEPORT_FRAGMENT2_POST_DNAT,
			   sizeof(BUF(LB6_NODEPORT_FRAGMENT2_POST_DNAT)));

	test_finish();
}
