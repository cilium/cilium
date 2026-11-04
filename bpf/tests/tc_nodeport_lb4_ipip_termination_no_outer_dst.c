// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "tc_nodeport_lb4_ipip_termination.h"

ASSIGN_CONFIG(bool, ipip_use_outer_dst, false)

/*
 * Test 4: outer dst is a node IP (--bpf-lb-ipip-use-outer-dst=false).
 * The forced-backend path should be skipped, dst should
 * stay the LB VIP so that nodeport_lb4() can select the appropriate backend.
 */

PKTGEN(PROG_TYPE, "tc_nodeport_ipip_term_v4_local_node")
int ipip_term_v4_local_node_pktgen(struct __ctx_buff *ctx)
{
	/* the outer destination is a local node IP */
	return pktgen_ipip_v4(ctx, L7_HOST_BACKEND_IP, FRONTEND_IP);
}

SETUP(PROG_TYPE, "tc_nodeport_ipip_term_v4_local_node")
int ipip_term_v4_local_node_setup(struct __ctx_buff *ctx)
{
	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, 1);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 124,
			  BACKEND_IP, FRONTEND_PORT, IPPROTO_TCP, 0);

	endpoint_v4_add_entry(BACKEND_IP, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);

	/* Host endpoint at the outer dst so lookup_ip4_endpoint() in the
	 * strip block resolves and gets ANDed with the ipip_use_outer_dst flag.
	 */
	endpoint_v4_add_entry(L7_HOST_BACKEND_IP, 0, 0, ENDPOINT_F_HOST,
			      HOST_ID, 0, NULL, NULL);

	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	num_calls[RECORD_TAILCALL] = 0;
	xdp_xfer_flags = 0;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_ipip_term_v4_local_node")
int ipip_term_v4_local_node_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	/* policy tail-call */
	if (num_calls[RECORD_TAILCALL] != 1)
		test_fatal("expected exactly one tail-call, got %u",
			   num_calls[RECORD_TAILCALL]);

	/* expect redirect to endpoint */
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
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->protocol != IPPROTO_TCP)
		test_fatal("post-decap L3 protocol is %u, expected TCP",
			   l3->protocol);

	/* Post-decap, inner souce should be the CLIENT_IP and inner dst should
	 * be the BACKEND_IP as the backend has been selected by lb4_local().
	 */
	if (l3->saddr != CLIENT_IP)
		test_fatal("post-decap src IP is %x, expected the client IP",
			   l3->saddr);
	if (l3->daddr != BACKEND_IP)
		test_fatal("post-decap dst IP is %x, expected BACKEND_IP",
			   l3->daddr);

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != CLIENT_PORT)
		test_fatal("post-decap src port has changed");
	if (l4->dest != FRONTEND_PORT)
		test_fatal("post-decap dst port has changed");
	if (!l4->syn)
		test_fatal("post-decap TCP flags lost the SYN");

	test_finish();
}
