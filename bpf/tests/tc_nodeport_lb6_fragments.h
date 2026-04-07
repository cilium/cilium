/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright Authors of Cilium
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV6 1
#define ENABLE_NODEPORT 1

#ifdef NORTH_SOUTH_TEST
# define CLIENT_IP	v6_ext_node_one
# define HOOK		netdev_receive_packet

# include "lib/bpf_host.h"
#elif defined(EAST_WEST_TEST)
# define ENABLE_SOCKET_LB_HOST_ONLY 1
# define CLIENT_IP	v6_pod_two
# define HOOK		pod_send_packet

# include "lib/bpf_lxc.h"
#else
# error "Needs to be included with either NORTH_SOUTH_TEST or EAST_WEST_TEST defined"
#endif

ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)
ASSIGN_CONFIG(bool, enable_ipv6_fragments, true)

#include "lib/endpoint.h"
#include "lib/policy.h"
#include "lib/lb.h"
#include "scapy.h"

#define CLIENT_PORT	tcp_src_one

#define FRONTEND_IP	v6_svc_one
#define FRONTEND_PORT	tcp_svc_one

#define BACKEND_IP	v6_pod_one
#define BACKEND_PORT	tcp_dst_one

#define NAT_REV_INDEX	1
#define BACKEND_COUNT	1
#define BACKEND_ID	124
#define BACKEND_IFINDEX	11

/* Expected CT tuple to check for conntrack */
#define EXPECTED_CT_TUPLE {\
	.saddr = *(union v6addr *)CLIENT_IP, \
	.sport = FRONTEND_PORT, \
	.daddr = *(union v6addr *)FRONTEND_IP, \
	.dport = CLIENT_PORT, \
	.nexthdr = IPPROTO_TCP, \
	.flags = TUPLE_F_SERVICE }

/* Expected fragment ID to check for conntrack */
#define EXPECTED_FRAG_ID { \
	.saddr = *(union v6addr *)CLIENT_IP, \
	.daddr = *(union v6addr *)FRONTEND_IP, \
	.id = bpf_htonl(256), \
	.proto = IPPROTO_TCP }

/* Expected metrics key to check for fragment-related metrics */
#define EXPECTED_METRIC_KEY { \
	.reason = REASON_FRAG_PACKET, \
	.dir = METRIC_SERVICE }

/* Test that the 1st fragment is handled correctly */
PKTGEN("tc", "tc_nodeport_lb6_fragment1")
int nodeport_lb6_fragment1_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

#ifdef NORTH_SOUTH_TEST
	BUF_DECL(LB6_NS_NODEPORT_FRAGMENT1, lb6_ns_nodeport_fragment1);
	BUILDER_PUSH_BUF(builder, LB6_NS_NODEPORT_FRAGMENT1);
#else
	BUF_DECL(LB6_EW_NODEPORT_FRAGMENT1, lb6_ew_nodeport_fragment1);
	BUILDER_PUSH_BUF(builder, LB6_EW_NODEPORT_FRAGMENT1);
#endif

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb6_fragment1")
int nodeport_lb6_fragment1_setup(struct __ctx_buff *ctx)
{
	policy_add_egress_allow_all_entry();

	endpoint_v6_add_entry((union v6addr *)BACKEND_IP, BACKEND_IFINDEX, 0, 0, 0,
			      (__u8 *)mac_one, (__u8 *)mac_two);
	lb_v6_add_service_with_flags((union v6addr *)FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP,
				     BACKEND_COUNT, NAT_REV_INDEX,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_NODEPORT, 0);
	lb_v6_add_backend((union v6addr *)FRONTEND_IP, FRONTEND_PORT, BACKEND_COUNT, BACKEND_ID,
			  (union v6addr *)BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	return HOOK(ctx);
}

CHECK("tc", "tc_nodeport_lb6_fragment1")
int nodeport_lb6_fragment1_check(struct __ctx_buff *ctx)
{
	__u32 *status_code;
	void *data_end;
	void *data;
	struct ipv6_frag_l4ports *l4ports;
	struct ct_entry *ct_entry;
	struct ipv6_frag_id expected_frag_id = EXPECTED_FRAG_ID;
	struct ipv6_ct_tuple expected_ct_tuple = EXPECTED_CT_TUPLE;
	struct metrics_key metric_key = EXPECTED_METRIC_KEY;
	__u64 count = 1;
	__u64 bytes = 0;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	status_code = data;

	/* Ensure packet offset and status code. */
	assert(data + sizeof(__u32) <= data_end);
	assert(*status_code == CTX_ACT_OK);

	/* Ensure fragment L4 ports are being tracked. */
	l4ports = map_lookup_elem(&cilium_ipv6_frag_datagrams, &expected_frag_id);
	assert(l4ports);
	assert(l4ports->dport == FRONTEND_PORT);
	assert(l4ports->sport == CLIENT_PORT);

	/* Ensure fragment-related metrics are updated accordingly. */
	assert_metrics_count(metric_key, count);

	/* Ensure packet has been DNAT correctly. */
#ifdef NORTH_SOUTH_TEST
	BUF_DECL(LB6_NS_NODEPORT_FRAGMENT1_POST_DNAT, lb6_ns_nodeport_fragment1_post_dnat);
	ASSERT_CTX_BUF_OFF("tcp6_first_fragment_ok", "Ether", ctx, sizeof(__u32),
			   LB6_NS_NODEPORT_FRAGMENT1_POST_DNAT,
			   sizeof(BUF(LB6_NS_NODEPORT_FRAGMENT1_POST_DNAT)));
	bytes = sizeof(BUF(LB6_NS_NODEPORT_FRAGMENT1_POST_DNAT));
#else
	BUF_DECL(LB6_EW_NODEPORT_FRAGMENT1_POST_DNAT, lb6_ew_nodeport_fragment1_post_dnat);
	ASSERT_CTX_BUF_OFF("tcp6_first_fragment_ok", "Ether", ctx, sizeof(__u32),
			   LB6_EW_NODEPORT_FRAGMENT1_POST_DNAT,
			   sizeof(BUF(LB6_EW_NODEPORT_FRAGMENT1_POST_DNAT)));
	bytes = sizeof(BUF(LB6_EW_NODEPORT_FRAGMENT1_POST_DNAT));
#endif

	/* Ensure CT entry is updated accordingly (SVC). */
	ct_entry = map_lookup_elem(get_ct_map6(&expected_ct_tuple), &expected_ct_tuple);
	assert(ct_entry);
	assert(ct_entry->packets == count);
	assert(ct_entry->bytes == bytes);

	test_finish();
}

/* Test that the 2nd fragment is handled correctly */
PKTGEN("tc", "tc_nodeport_lb6_fragment2")
int nodeport_lb6_fragment2_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

#ifdef NORTH_SOUTH_TEST
	BUF_DECL(LB6_NS_NODEPORT_FRAGMENT2, lb6_ns_nodeport_fragment2);
	BUILDER_PUSH_BUF(builder, LB6_NS_NODEPORT_FRAGMENT2);
#else
	BUF_DECL(LB6_EW_NODEPORT_FRAGMENT2, lb6_ew_nodeport_fragment2);
	BUILDER_PUSH_BUF(builder, LB6_EW_NODEPORT_FRAGMENT2);
#endif

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb6_fragment2")
int nodeport_lb6_fragment2_setup(struct __ctx_buff *ctx)
{
	return HOOK(ctx);
}

CHECK("tc", "tc_nodeport_lb6_fragment2")
int nodeport_lb6_fragment2_check(struct __ctx_buff *ctx)
{
	__u32 *status_code;
	void *data_end;
	void *data;
	struct ct_entry *ct_entry;
	struct ipv6_ct_tuple expected_ct_tuple = EXPECTED_CT_TUPLE;
	struct metrics_key metric_key = EXPECTED_METRIC_KEY;
	__u64 count = 2;
	__u64 bytes = 0;

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
#ifdef NORTH_SOUTH_TEST
	BUF_DECL(LB6_NS_NODEPORT_FRAGMENT1_POST_DNAT, lb6_ns_nodeport_fragment1_post_dnat);
	BUF_DECL(LB6_NS_NODEPORT_FRAGMENT2_POST_DNAT, lb6_ns_nodeport_fragment2_post_dnat);
	ASSERT_CTX_BUF_OFF("tcp6_second_fragment_ok", "Ether", ctx, sizeof(__u32),
			   LB6_NS_NODEPORT_FRAGMENT2_POST_DNAT,
			   sizeof(BUF(LB6_NS_NODEPORT_FRAGMENT2_POST_DNAT)));
	bytes = sizeof(BUF(LB6_NS_NODEPORT_FRAGMENT1_POST_DNAT)) +
		sizeof(BUF(LB6_NS_NODEPORT_FRAGMENT2_POST_DNAT));
#else
	BUF_DECL(LB6_EW_NODEPORT_FRAGMENT1_POST_DNAT, lb6_ew_nodeport_fragment1_post_dnat);
	BUF_DECL(LB6_EW_NODEPORT_FRAGMENT2_POST_DNAT, lb6_ew_nodeport_fragment2_post_dnat);
	ASSERT_CTX_BUF_OFF("tcp6_second_fragment_ok", "Ether", ctx, sizeof(__u32),
			   LB6_EW_NODEPORT_FRAGMENT2_POST_DNAT,
			   sizeof(BUF(LB6_EW_NODEPORT_FRAGMENT2_POST_DNAT)));
	bytes = sizeof(BUF(LB6_EW_NODEPORT_FRAGMENT1_POST_DNAT)) +
		sizeof(BUF(LB6_EW_NODEPORT_FRAGMENT2_POST_DNAT));
#endif

	/* Ensure CT entry is updated accordingly (SVC). */
	ct_entry = map_lookup_elem(get_ct_map6(&expected_ct_tuple), &expected_ct_tuple);
	assert(ct_entry);
	assert(ct_entry->packets == count);
	assert(ct_entry->bytes == bytes);

	test_finish();
}
