// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "tc_nodeport_lb6_ipip_termination.h"

/* -------------------------------------------------------------------------- */
/* Test 1: outer dst is a local Pod IP. Strip + DNAT + redirect_peer.         */
/* -------------------------------------------------------------------------- */

PKTGEN(PROG_TYPE, "tc_nodeport_ipip_term_v6_local_pod")
int ipip_term_v6_local_pod_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_ipip_v6(ctx, (void *)v6_pod_two, (void *)v6_pod_three);
}

SETUP(PROG_TYPE, "tc_nodeport_ipip_term_v6_local_pod")
int ipip_term_v6_local_pod_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Service at FRONTEND (v6_pod_three) with v6_pod_two as the backend.
	 * The outer dst of the IPIP packet IS the backend IP, which the
	 * strip path stashes into CB_FORCED_BACKEND_V6_* and lb6_local()
	 * uses to DNAT.
	 */
	lb_v6_add_service((const union v6addr *)v6_pod_three, FRONTEND_PORT,
			  IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend((const union v6addr *)v6_pod_three, FRONTEND_PORT,
			  1, 124,
			  (const union v6addr *)v6_pod_two, FRONTEND_PORT,
			  IPPROTO_TCP, 0);

	endpoint_v6_add_entry((const union v6addr *)v6_pod_two,
			      BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);

	ipcache_v6_add_entry((const union v6addr *)v6_pod_two, 0, 112233, 0, 0);

	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	num_calls[RECORD_TAILCALL] = 0;
	xdp_xfer_flags = 0;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_ipip_term_v6_local_pod")
int ipip_term_v6_local_pod_check(struct __ctx_buff *ctx)
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

	/* phys-netdev ingress to a local Pod with BPF host routing: one policy
	 * tail-call into the Pod's program (mocked here) then delivery via
	 * ctx_redirect_peer(). See the IPv4 sibling test for the rationale.
	 */
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
		test_fatal("post-decap nexthdr is %u, expected TCP", l3->nexthdr);
	if (memcmp(&l3->saddr, (void *)v6_pod_one, 16) != 0)
		test_fatal("post-decap src IP is not the client IP");
	if (memcmp(&l3->daddr, (void *)v6_pod_two, 16) != 0)
		test_fatal("post-decap dst IP is not the backend Pod IP (DNAT failed)");

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

	test_finish();
}

/* -------------------------------------------------------------------------- */
/* Test 2: --enable-ipip-termination Envoy target (v6 mirror). The inner      */
/* targets an L7-punt-proxy service whose backend is local (the host itself). */
/* The strip block must still decap, but nodeport_svc_lb6 must take the       */
/* lb6_svc_is_l7_punt_proxy && backend_local gate and punt to host stack      */
/* without running the forced-backend DNAT so Envoy sees the inner unchanged. */
/* -------------------------------------------------------------------------- */

PKTGEN(PROG_TYPE, "tc_nodeport_ipip_term_v6_l7_punt_proxy")
int ipip_term_v6_l7_punt_proxy_pktgen(struct __ctx_buff *ctx)
{
	/* outer dst = local host IP (v6_node_one), inner dst = L7 svc VIP. */
	return pktgen_ipip_v6(ctx, (void *)v6_node_one, (void *)v6_pod_three);
}

SETUP(PROG_TYPE, "tc_nodeport_ipip_term_v6_l7_punt_proxy")
int ipip_term_v6_l7_punt_proxy_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	lb_v6_add_service_with_flags((const union v6addr *)v6_pod_three,
				     FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_LOADBALANCER,
				     SVC_FLAG_L7_DELEGATE);
	lb_v6_add_backend((const union v6addr *)v6_pod_three, FRONTEND_PORT,
			  1, 200,
			  (const union v6addr *)v6_node_one, FRONTEND_PORT,
			  IPPROTO_TCP, 0);

	endpoint_v6_add_entry((const union v6addr *)v6_node_one, 0, 0,
			      ENDPOINT_F_HOST, HOST_ID,
			      NULL, NULL);

	ipcache_v6_add_entry((const union v6addr *)v6_node_one, 0, HOST_ID, 0, 0);

	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	num_calls[RECORD_TAILCALL] = 0;
	xdp_xfer_flags = 0;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_ipip_term_v6_l7_punt_proxy")
int ipip_term_v6_l7_punt_proxy_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;

	test_init();

	endpoint_v6_del_entry((const union v6addr *)v6_node_one);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_fatal("expected CTX_ACT_OK (punt to stack), got %u",
			   *status_code);
	if (num_calls[RECORD_REDIRECT_PEER] != 0)
		test_fatal("did not expect ctx_redirect_peer on L7-punt path, got %u",
			   num_calls[RECORD_REDIRECT_PEER]);
	if (num_calls[RECORD_REDIRECT] != 0)
		test_fatal("did not expect ctx_redirect on L7-punt path, got %u",
			   num_calls[RECORD_REDIRECT]);

	/* Strip must have happened: the on-wire L3 after BPF is now what was
	 * the inner IPv6 (nexthdr=TCP).
	 */
	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->nexthdr != IPPROTO_TCP)
		test_fatal("expected inner-as-L3 with nexthdr=TCP, got %u (strip didn't run?)",
			   l3->nexthdr);

	/* DNAT MUST NOT have happened: inner dst stays the L7 svc VIP. */
	if (memcmp(&l3->saddr, (void *)v6_pod_one, 16) != 0)
		test_fatal("inner src IP changed");
	if (memcmp(&l3->daddr, (void *)v6_pod_three, 16) != 0)
		test_fatal("inner dst IP was rewritten - forced-backend DNAT must not run on L7-punt-proxy path");

	test_finish();
}

/* -------------------------------------------------------------------------- */
/* Test 3: same input as test 1 (IPIP6 -> local Pod) but XDP NodePort accel   */
/* ran upstream and set XFER_PKT_NO_SVC. See the IPv4 sibling test for the    */
/* rationale and the full contract being pinned.                              */
/* -------------------------------------------------------------------------- */

PKTGEN(PROG_TYPE, "tc_nodeport_ipip_term_v6_xdp_handoff")
int ipip_term_v6_xdp_handoff_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_ipip_v6(ctx, (void *)v6_pod_two, (void *)v6_pod_three);
}

SETUP(PROG_TYPE, "tc_nodeport_ipip_term_v6_xdp_handoff")
int ipip_term_v6_xdp_handoff_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v6_add_service((const union v6addr *)v6_pod_three, FRONTEND_PORT,
			  IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend((const union v6addr *)v6_pod_three, FRONTEND_PORT,
			  1, 124,
			  (const union v6addr *)v6_pod_two, FRONTEND_PORT,
			  IPPROTO_TCP, 0);

	endpoint_v6_add_entry((const union v6addr *)v6_pod_two,
			      BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry((const union v6addr *)v6_pod_two, 0, 112233, 0, 0);

	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	num_calls[RECORD_TAILCALL] = 0;
	xdp_xfer_flags = XFER_PKT_NO_SVC;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_ipip_term_v6_xdp_handoff")
int ipip_term_v6_xdp_handoff_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;

	test_init();

	endpoint_v6_del_entry((const union v6addr *)v6_pod_two);

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
		test_fatal("post-decap nexthdr is %u, expected TCP", l3->nexthdr);
	if (memcmp(&l3->daddr, (void *)v6_pod_two, 16) != 0)
		test_fatal("post-decap dst IP is not BACKEND - forced-backend DNAT skipped (stale skip-nodeport hint from XDP)");

	test_finish();
}
