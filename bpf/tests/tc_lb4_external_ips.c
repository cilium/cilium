// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		tcp_src_one

#define FRONTEND_IP		v4_ext_two
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

/* Test that a request for an ExternalIP service is handled correctly */
PKTGEN("tc", "tc_lb4_external_ips")
int lb4_external_ips_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(LB4_EXTERNAL_IP, lb4_external_ip);
	BUILDER_PUSH_BUF(builder, LB4_EXTERNAL_IP);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lb4_external_ips")
int lb4_external_ips_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(BACKEND_IP, BACKEND_IFINDEX, 0, 0, 0, 0,
			      (__u8 *)mac_one, (__u8 *)mac_two);
	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT,
				     IPPROTO_TCP, BACKEND_COUNT, NAT_REV_INDEX,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_EXTERNAL_IP, 0);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, BACKEND_COUNT, BACKEND_ID,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_lb4_external_ips")
int lb4_external_ips_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code, pkt_size;
	struct ct_entry *ct_entry;
	struct ipv4_ct_tuple tuple = {
		.saddr   = CLIENT_IP,
		.sport   = FRONTEND_PORT,
		.daddr   = FRONTEND_IP,
		.dport   = CLIENT_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags   = TUPLE_F_SERVICE,
	};

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	pkt_size = ctx_full_len(ctx) - sizeof(__u32);
	status_code = data;

	assert(data + sizeof(__u32) <= data_end)

	assert(*status_code == CTX_ACT_OK);

	/* Ensure CT entry is updated accordingly (SVC). */
	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	assert(ct_entry);
	assert(ct_entry->packets == 1);
	assert(ct_entry->bytes == pkt_size);

	BUF_DECL(LB4_CLUSTERIP_POST_DNAT, lb4_external_ip_post_dnat);
	ASSERT_CTX_BUF_OFF("lb4_routable_clusterip", "Ether", ctx, sizeof(__u32),
			   LB4_CLUSTERIP_POST_DNAT, sizeof(BUF(LB4_CLUSTERIP_POST_DNAT)));

	test_finish();
}
