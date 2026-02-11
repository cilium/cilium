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

#define SADDR		v4_ext_one
#define SPORT		tcp_src_one

#define FRONTEND_IP	v4_svc_one
#define FRONTEND_PORT	tcp_svc_one

#define BACKEND_IP	v4_pod_one
#define BACKEND_PORT	tcp_dst_one

#define NAT_REV_INDEX	1
#define BACKEND_COUNT	1
#define BACKEND_ID	124
#define BACKEND_IFINDEX	11

/* Global variables to store data between setup and check functions. */
__u64 bytes;
struct ipv4_frag_id frag_id;
struct ipv4_ct_tuple ct_tuple;
struct ipv4_ct_tuple ct_tuple_dnated;

/* fetch_global_params retrieves fragment and connection tracking information
 * before the ingress program is executed, which will be used for checks in the test cases.
 * This function must be called from within a SETUP, given it does not expect the status (__u32)
 * to be at the beginning of the packet data, which is the case in CHECKs.
 * The CT tuple post XLATION (DNAT) is also computed here to simulate the expected tuple that would
 * be looked up in the nodeport_svc_lb4 program with backend_local=true after DNAT is applied.
 */
static __always_inline int
fetch_global_params(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct iphdr *ip4 = data + sizeof(struct ethhdr);
	int l4_off = sizeof(struct ethhdr) + sizeof(struct iphdr);

	if ((void *)ip4 + sizeof(struct iphdr) > data_end)
		return TEST_ERROR;

	fraginfo_t fraginfo = ipfrag_encode_ipv4(ip4);

	frag_id = (struct ipv4_frag_id){
		.daddr = ip4->daddr,
		.saddr = ip4->saddr,
		.id = (__be16)ipfrag_get_id(fraginfo),
		.proto = ipfrag_get_protocol(fraginfo),
	};

	/* Extract CT tuple for SVC (pre DNAT). */
	lb4_extract_tuple(ctx, ip4, fraginfo, l4_off, &ct_tuple);
	ct_tuple.flags = TUPLE_F_SERVICE;

	/* Extract CT tuple for post DNAT. This simulates a call to `lb4_dnat_request` + reverse
	 * tuple for CT lookup in nodeport_svc_lb4 with backend_local
	 */
	ct_tuple_dnated = (struct ipv4_ct_tuple) {
		.saddr   = BACKEND_IP,
		.dport   = BACKEND_PORT,
		.daddr   = ct_tuple.saddr,
		.sport   = ct_tuple.dport,
		.nexthdr = ct_tuple.nexthdr,
		.flags   = 0,
	};

	bytes = bytes + ctx_full_len(ctx);

	return 0;
}

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

	fetch_global_params(ctx);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb4_fragments_1")
int nodeport_lb4_fragments_1_check(struct __ctx_buff *ctx)
{
	__u32 *status_code;
	void *data_end;
	void *data;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Ensure status code match. */
	if (*status_code != CTX_ACT_OK)
		test_fatal("status code is %lu, expected %lu", *status_code, CTX_ACT_OK);

	/* Ensure fragment L4 ports are being tracked. */
	struct ipv4_frag_l4ports *l4ports = map_lookup_elem(&cilium_ipv4_frag_datagrams, &frag_id);

	if (!l4ports)
		test_fatal("frag l4ports entry not found");
	assert(l4ports->dport == FRONTEND_PORT);
	assert(l4ports->sport == SPORT);

	/* Ensure expected DNAT happened. */
	BUF_DECL(LB4_NODEPORT_FRAGMENT1_POST_DNAT, lb4_nodeport_fragment1_post_dnat);
	ASSERT_CTX_BUF_OFF("tcp4_first_fragment_ok", "Ether", ctx, sizeof(__u32),
			   LB4_NODEPORT_FRAGMENT1_POST_DNAT,
			   sizeof(BUF(LB4_NODEPORT_FRAGMENT1_POST_DNAT)));

	/* Ensure fragment-related metrics are updated accordingly. */
	struct metrics_key metric_key = {
		.reason = REASON_FRAG_PACKET,
		.dir = METRIC_SERVICE,
	};
	__u64 count = 1;

	assert_metrics_count(metric_key, count);

	/* Ensure CT entry is updated accordingly (SVC). */
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&ct_tuple), &ct_tuple);

	if (!ct_entry)
		test_fatal("CT entry not found");
	assert(ct_entry->packets == 1);
	assert(ct_entry->bytes == bytes);

	/* Ensure CT entry is updated accordingly (post DNAT). */
	ct_entry = map_lookup_elem(get_ct_map4(&ct_tuple_dnated), &ct_tuple_dnated);
	if (!ct_entry)
		test_fatal("CT entry not found");
	assert(ct_entry->packets == 1);
	assert(ct_entry->bytes == bytes);
	assert(ct_entry->node_port == 1);

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
	fetch_global_params(ctx);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb4_fragments_2")
int nodeport_lb4_fragments_2_check(struct __ctx_buff *ctx)
{
	__u32 *status_code;
	void *data_end;
	void *data;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_fatal("status code is %lu, expected %lu", *status_code, CTX_ACT_OK);

	/* Ensure fragment L4 ports were being correctly retrieved. */
	struct ipv4_frag_l4ports *l4ports = map_lookup_elem(&cilium_ipv4_frag_datagrams, &frag_id);

	if (!l4ports)
		test_fatal("frag l4ports entry not found");
	assert(l4ports->dport == FRONTEND_PORT);
	assert(l4ports->sport == SPORT);

	/* Ensure expected DNAT happened. */
	BUF_DECL(LB4_NODEPORT_FRAGMENT2_POST_DNAT, lb4_nodeport_fragment2_post_dnat);
	ASSERT_CTX_BUF_OFF("tcp4_second_fragment_ok", "Ether", ctx, sizeof(__u32),
			   LB4_NODEPORT_FRAGMENT2_POST_DNAT,
			   sizeof(BUF(LB4_NODEPORT_FRAGMENT2_POST_DNAT)));

	/* Ensure fragment-related metrics are updated accordingly. */
	struct metrics_key metric_key = {
		.reason = REASON_FRAG_PACKET,
		.dir = METRIC_SERVICE,
	};
	__u64 count = 2;

	assert_metrics_count(metric_key, count);

	/* Ensure CT entry is updated accordingly (SVC). */
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&ct_tuple), &ct_tuple);

	if (!ct_entry)
		test_fatal("CT entry not found");
	assert(ct_entry->packets == 2);
	assert(ct_entry->bytes == bytes);

	/* Ensure CT entry is updated accordingly (post DNAT). */
	ct_entry = map_lookup_elem(get_ct_map4(&ct_tuple_dnated), &ct_tuple_dnated);
	if (!ct_entry)
		test_fatal("CT entry not found");
	assert(ct_entry->packets == 2);
	assert(ct_entry->bytes == bytes);
	assert(ct_entry->node_port == 1);

	test_finish();
}
