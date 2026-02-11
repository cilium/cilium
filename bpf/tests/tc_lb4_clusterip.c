// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		tcp_src_one

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v4_pod_one
#define BACKEND_PORT		tcp_dst_one

#define NAT_REV_INDEX		1
#define BACKEND_COUNT		1
#define BACKEND_IFINDEX		11
#define BACKEND_ID		124

#include "lib/bpf_host.h"
#include "lib/endpoint.h"
#include "lib/lb.h"
#include "scapy.h"

/* For checking statistics in conntrack map. */
ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

/* Global variables to store data between setup and check functions. */
struct ipv4_ct_tuple ct_tuple;
struct ipv4_ct_tuple ct_tuple_dnated;

/* Test that a request from an external client to a ClusterIP service w/o the
 * `bpf-lb-external-clusterip` flag set is denied. The reason is due to the SVC
 * being created w/o the SVC_FLAG_ROUTABLE flag being set in the bpf map,
 * leading to the datapath dropping the packet with the reason code
 * DROP_IS_CLUSTER_IP, and the respective BPF metric updated accordingly.
 */
PKTGEN("tc", "tc_lb4_nonroutable_clusterip")
int lb4_nonroutable_clusterip_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(LB4_CLUSTERIP, lb4_clusterip);
	BUILDER_PUSH_BUF(builder, LB4_CLUSTERIP);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lb4_nonroutable_clusterip")
int lb4_nonroutable_clusterip_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(BACKEND_IP, BACKEND_IFINDEX, 0, 0, 0, 0,
			      (__u8 *)mac_one, (__u8 *)mac_two);
	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT,
				     IPPROTO_TCP, BACKEND_COUNT, NAT_REV_INDEX,
				     0, 0);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, BACKEND_COUNT, BACKEND_ID,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_lb4_nonroutable_clusterip")
int lb4_nonroutable_clusterip_check(__maybe_unused const struct __ctx_buff *ctx)
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

	BUF_DECL(LB4_CLUSTERIP, lb4_clusterip);
	ASSERT_CTX_BUF_OFF("lb4_nonroutable_clusterip", "Ether", ctx, sizeof(__u32),
			   LB4_CLUSTERIP, sizeof(BUF(LB4_CLUSTERIP)));

	/* Retrieve drop reason from metadata (bpf/lib/drop.h) */
	__u32 reason = ctx_load_meta(ctx, 2);

	assert(reason == -DROP_IS_CLUSTER_IP);

	struct metrics_key key = {
		.reason = -DROP_IS_CLUSTER_IP,
		.dir = METRIC_INGRESS,
	};
	__u64 count = 1;

	assert_metrics_count(key, count);

	test_finish();
}

/* Test that a request from an external client to a ClusterIP service with the
 * `bpf-lb-external-clusterip` flag set is allowed. The reason is due to the SVC
 * being created w/ the SVC_FLAG_ROUTABLE flag being set in the bpf map,
 * leading to the datapath correctly accepting and DNAT the packet, and the
 * respective BPF metric updated accordingly.
 */
PKTGEN("tc", "tc_lb4_routable_clusterip")
int lb4_routable_clusterip_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(LB4_CLUSTERIP, lb4_clusterip);
	BUILDER_PUSH_BUF(builder, LB4_CLUSTERIP);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lb4_routable_clusterip")
int lb4_routable_clusterip_setup(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct iphdr *ip4 = data + sizeof(struct ethhdr);
	int l4_off = sizeof(struct ethhdr) + sizeof(struct iphdr);

	if ((void *)ip4 + sizeof(struct iphdr) > data_end)
		return TEST_ERROR;

	fraginfo_t fraginfo = ipfrag_encode_ipv4(ip4);

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

	/* Endpoint and backend added in previous setup, simply change SVC flags. */
	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT,
				     IPPROTO_TCP, BACKEND_COUNT, NAT_REV_INDEX,
				     SVC_FLAG_ROUTABLE, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_lb4_routable_clusterip")
int lb4_routable_clusterip_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	__u32 pkt_size = ctx_full_len(ctx) - sizeof(__u32);

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	BUF_DECL(LB4_CLUSTERIP_POST_DNAT, lb4_clusterip_post_dnat);
	ASSERT_CTX_BUF_OFF("lb4_routable_clusterip", "Ether", ctx, sizeof(__u32),
			   LB4_CLUSTERIP_POST_DNAT, sizeof(BUF(LB4_CLUSTERIP_POST_DNAT)));

	/* Ensure CT entry is updated accordingly (SVC). */
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&ct_tuple), &ct_tuple);

	if (!ct_entry)
		test_fatal("CT entry not found");
	assert(ct_entry->packets == 1);
	assert(ct_entry->bytes == pkt_size);

	/* Ensure CT entry is updated accordingly (post DNAT). */
	ct_entry = map_lookup_elem(get_ct_map4(&ct_tuple_dnated), &ct_tuple_dnated);
	if (!ct_entry)
		test_fatal("CT entry not found");
	assert(ct_entry->packets == 1);
	assert(ct_entry->bytes == pkt_size);
	assert(ct_entry->node_port == 1);

	test_finish();
}
