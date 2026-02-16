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
	__u32 *status_code, drop_reason;
	__u64 count = 1;
	struct metrics_key key = {
		.reason = -DROP_IS_CLUSTER_IP,
		.dir = METRIC_INGRESS,
	};

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	status_code = data;
	/* Retrieve drop reason from metadata (bpf/lib/drop.h) */
	drop_reason = ctx_load_meta(ctx, 2);

	assert(data + sizeof(__u32) <= data_end)

	assert(*status_code == CTX_ACT_DROP);

	assert(drop_reason == -DROP_IS_CLUSTER_IP);

	assert_metrics_count(key, count);

	BUF_DECL(LB4_CLUSTERIP, lb4_clusterip);
	ASSERT_CTX_BUF_OFF("lb4_nonroutable_clusterip", "Ether", ctx, sizeof(__u32),
			   LB4_CLUSTERIP, sizeof(BUF(LB4_CLUSTERIP)));

	test_finish();
}
