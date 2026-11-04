// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "tc_nodeport_lb6_ipip_termination.h"

ASSIGN_CONFIG(bool, ipip_use_outer_dst, false)

PKTGEN(PROG_TYPE, "tc_nodeport_ipip_term_v6_local_node")
int ipip_term_v6_local_node_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_ipip_v6(ctx, (void *)v6_node_one, (void *)v6_pod_three);
}

SETUP(PROG_TYPE, "tc_nodeport_ipip_term_v6_local_node")
int ipip_term_v6_local_node_setup(struct __ctx_buff *ctx)
{
	lb_v6_add_service((const union v6addr *)v6_pod_three, FRONTEND_PORT,
			  IPPROTO_TCP, 1, 1);
	lb_v6_add_backend((const union v6addr *)v6_pod_three, FRONTEND_PORT,
			  1, 124,
			  (const union v6addr *)v6_pod_two, FRONTEND_PORT,
			  IPPROTO_TCP, 0);

	endpoint_v6_add_entry((const union v6addr *)v6_pod_two,
			      BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);
	endpoint_v6_add_entry((const union v6addr *)v6_node_one, 0, 0,
			      ENDPOINT_F_HOST, HOST_ID, NULL, NULL);

	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	num_calls[RECORD_TAILCALL] = 0;
	xdp_xfer_flags = 0;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_ipip_term_v6_local_node")
int ipip_term_v6_local_node_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	if (num_calls[RECORD_TAILCALL] != 1)
		test_fatal("expected exactly one policy tail-call, got %u",
			   num_calls[RECORD_TAILCALL]);
	if (num_calls[RECORD_REDIRECT_PEER] != 1)
		test_fatal("expected exactly one ctx_redirect_peer call, got %u",
			   num_calls[RECORD_REDIRECT_PEER]);
	if (num_calls[RECORD_REDIRECT] != 0)
		test_fatal("did not expect plain ctx_redirect, got %u",
			   num_calls[RECORD_REDIRECT]);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->nexthdr != IPPROTO_TCP)
		test_fatal("post-decap nexthdr is %u, expected TCP",
			   l3->nexthdr);
	if (memcmp(&l3->saddr, (void *)v6_pod_one, 16) != 0)
		test_fatal("post-decap src IP is not the client IP");
	if (memcmp(&l3->daddr, (void *)v6_pod_two, 16) != 0)
		test_fatal("post-decap dst IP is not the backend Pod IP");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != CLIENT_PORT)
		test_fatal("post-decap src port has changed");
	if (l4->dest != FRONTEND_PORT)
		test_fatal("post-decap dst port has changed");
	if (!l4->syn)
		test_fatal("post-decap TCP flags lost the SYN");

	endpoint_v6_del_entry((const union v6addr *)v6_pod_two);
	endpoint_v6_del_entry((const union v6addr *)v6_node_one);

	test_finish();
}
