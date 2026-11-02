// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "tc_nodeport_lb4_ipip_termination.h"

/* -------------------------------------------------------------------------- */
/* Test 1: outer dst is a local Pod IP. Expect strip + DNAT + redirect_peer.  */
/* -------------------------------------------------------------------------- */

PKTGEN(PROG_TYPE, "tc_nodeport_ipip_term_v4_local_pod")
int ipip_term_v4_local_pod_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_ipip_v4(ctx, BACKEND_IP, FRONTEND_IP);
}

SETUP(PROG_TYPE, "tc_nodeport_ipip_term_v4_local_pod")
int ipip_term_v4_local_pod_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* The LB service must exist so nodeport_svc_lb4 finds it for the
	 * decapped inner. The forced-backend path in lb4_local then short-
	 * circuits selection and DNATs to the stashed outer dst.
	 */
	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	/* Local Pod endpoint at outer dst -- required for the
	 * lookup_ip4_endpoint() gate in the strip block to fire.
	 */
	endpoint_v4_add_entry(BACKEND_IP, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);

	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);

	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	num_calls[RECORD_TAILCALL] = 0;
	xdp_xfer_flags = 0;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_ipip_term_v4_local_pod")
int ipip_term_v4_local_pod_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();

	endpoint_v4_del_entry(BACKEND_IP);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	/* phys-netdev ingress to a local Pod with BPF host routing:
	 * local_delivery() makes one policy tail-call into the Pod's program
	 * (mocked here), which then delivers via ctx_redirect_peer() -
	 * should_redirect_peer() is true for a from_host=false packet on both
	 * veth and netkit phys ingress. No plain ctx_redirect().
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

	/* After strip + DNAT the on-wire packet should be:
	 *   [ETH][inner IPv4: src=CLIENT, dst=BACKEND, proto=TCP][TCP SYN]
	 * Outer IPv4 must be gone, length must reflect the strip.
	 */
	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->protocol != IPPROTO_TCP)
		test_fatal("post-decap L3 protocol is %u, expected TCP",
			   l3->protocol);
	if (l3->saddr != CLIENT_IP)
		test_fatal("post-decap src IP is not the client IP");
	if (l3->daddr != BACKEND_IP)
		test_fatal("post-decap dst IP is %x, expected BACKEND_IP (DNAT failed)",
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

/* -------------------------------------------------------------------------- */
/* Test 2: --enable-ipip-termination Envoy target. The inner targets an       */
/* L7-punt-proxy service whose backend is local (the host itself). The strip  */
/* block must still decap (the HOST-DELIVERY exclusion was lifted), but the   */
/* forced-backend DNAT must NOT run. Instead nodeport_svc_lb4 sets            */
/* punt_to_stack on the lb4_svc_is_l7_punt_proxy && backend_local gate so the */
/* decapped inner reaches the host stack unchanged for Envoy to intercept.    */
/* -------------------------------------------------------------------------- */

PKTGEN(PROG_TYPE, "tc_nodeport_ipip_term_v4_l7_punt_proxy")
int ipip_term_v4_l7_punt_proxy_pktgen(struct __ctx_buff *ctx)
{
	/* Outer dst = local host IP; inner dst = the L7-delegate svc VIP. */
	return pktgen_ipip_v4(ctx, L7_HOST_BACKEND_IP, L7_FRONTEND_IP);
}

SETUP(PROG_TYPE, "tc_nodeport_ipip_term_v4_l7_punt_proxy")
int ipip_term_v4_l7_punt_proxy_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	/* L7-delegate service: SVC_FLAG_L7_DELEGATE puts this into the
	 * lb4_svc_is_l7_punt_proxy bucket. The single "backend" is the
	 * local host endpoint (Envoy listening on this node).
	 */
	lb_v4_add_service_with_flags(L7_FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP,
				     1, revnat_id,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_LOADBALANCER,
				     SVC_FLAG_L7_DELEGATE);
	lb_v4_add_backend(L7_FRONTEND_IP, FRONTEND_PORT, 1, 200,
			  L7_HOST_BACKEND_IP, FRONTEND_PORT, IPPROTO_TCP, 0);

	/* Host endpoint at the outer dst so lookup_ip4_endpoint() in the
	 * strip block resolves (HOST_DELIVERY exclusion was lifted) and
	 * backend_local in nodeport_svc_lb4 is true for the punt gate.
	 */
	endpoint_v4_add_entry(L7_HOST_BACKEND_IP, 0, 0, ENDPOINT_F_HOST,
			      HOST_ID, 0, NULL, NULL);

	ipcache_v4_add_entry(L7_HOST_BACKEND_IP, 0, HOST_ID, 0, 0);

	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	num_calls[RECORD_TAILCALL] = 0;
	xdp_xfer_flags = 0;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_ipip_term_v4_l7_punt_proxy")
int ipip_term_v4_l7_punt_proxy_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	endpoint_v4_del_entry(L7_HOST_BACKEND_IP);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	/* Punt to host stack: BPF returns CTX_ACT_OK without redirecting. */
	if (*status_code != CTX_ACT_OK)
		test_fatal("expected CTX_ACT_OK (punt to stack), got %u",
			   *status_code);
	if (num_calls[RECORD_REDIRECT_PEER] != 0)
		test_fatal("did not expect ctx_redirect_peer on L7-punt path, got %u",
			   num_calls[RECORD_REDIRECT_PEER]);
	if (num_calls[RECORD_REDIRECT] != 0)
		test_fatal("did not expect ctx_redirect on L7-punt path, got %u",
			   num_calls[RECORD_REDIRECT]);

	/* The strip MUST still have happened - decap on netdev ingress is
	 * how Envoy now sees the inner. Verify the outer IPIP header is gone.
	 */
	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->protocol != IPPROTO_TCP)
		test_fatal("expected inner-as-L3 with proto=TCP, got %u (strip didn't run?)",
			   l3->protocol);

	/* DNAT MUST NOT have happened: inner dst stays the L7 svc VIP so the
	 * host stack / Envoy sees the same 5-tuple the client sent.
	 */
	if (l3->saddr != CLIENT_IP)
		test_fatal("inner src IP changed");
	if (l3->daddr != L7_FRONTEND_IP)
		test_fatal("inner dst IP was rewritten - forced-backend DNAT must not run on L7-punt-proxy path (got %x, want %x)",
			   l3->daddr, L7_FRONTEND_IP);

	test_finish();
}

/* -------------------------------------------------------------------------- */
/* Test 3: same input as test 1 (IPIP -> local Pod) but XDP NodePort accel    */
/* ran upstream and set XFER_PKT_NO_SVC. cil_from_netdev mirrors that into a  */
/* tc_index skip-nodeport hint. The IPIP strip must clear that hint so that  */
/* handle_ipv4() still calls into nodeport_lb4() and the forced-backend DNAT */
/* runs - otherwise the inner falls through with daddr == LB VIP.            */
/* -------------------------------------------------------------------------- */

PKTGEN(PROG_TYPE, "tc_nodeport_ipip_term_v4_xdp_handoff")
int ipip_term_v4_xdp_handoff_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_ipip_v4(ctx, BACKEND_IP, FRONTEND_IP);
}

SETUP(PROG_TYPE, "tc_nodeport_ipip_term_v4_xdp_handoff")
int ipip_term_v4_xdp_handoff_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	endpoint_v4_add_entry(BACKEND_IP, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);

	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);

	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	num_calls[RECORD_TAILCALL] = 0;

	/* Simulate XDP NodePort acceleration: the IPIP outer can't be
	 * classified (proto=4 has no L4 service tuple), so XDP returned
	 * CTX_ACT_OK with XFER_PKT_NO_SVC set. cil_from_netdev will read
	 * this and call ctx_skip_nodeport_set() on the skb.
	 */
	xdp_xfer_flags = XFER_PKT_NO_SVC;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_ipip_term_v4_xdp_handoff")
int ipip_term_v4_xdp_handoff_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	endpoint_v4_del_entry(BACKEND_IP);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	/* End result must be identical to the non-XDP local_pod case: one policy
	 * tail-call then ctx_redirect_peer(). If the IPIP strip didn't clear the
	 * skip-nodeport hint, handle_ipv4 would skip nodeport_lb4(), no DNAT would
	 * run, and dst would stay the LB VIP.
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
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->protocol != IPPROTO_TCP)
		test_fatal("post-decap L3 protocol is %u, expected TCP",
			   l3->protocol);
	if (l3->daddr != BACKEND_IP)
		test_fatal("post-decap dst IP is %x, expected BACKEND_IP - forced-backend DNAT was skipped (stale skip-nodeport hint from XDP)",
			   l3->daddr);

	test_finish();
}
