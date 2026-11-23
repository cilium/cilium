// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/*
 * Tests for the inbound DSR-IPIP termination path on the backend node, as
 * introduced in
 *   "bpf: Terminate inbound DSR IPIP in BPF on netdev ingress"
 *   "bpf, datapath: BPF-terminate all inbound IPIP, drop bpf_host on cilium_ipip{4,6}"
 *   "bpf: lb: skip service CT touch for L7-punt-proxy on forced-backend path"
 *   "bpf: deliver inbound IPIP-decapped pkts to local netkit Pod via redirect_peer"
 *
 * cil_from_netdev on the physical netdev's TC ingress is expected to:
 *  - decap (strip) the outer IPv4 header when its destination matches a local
 *    endpoint and the protocol is IPPROTO_IPIP,
 *  - for a regular LB service, DNAT the inner LB IP to the specific backend
 *    the LB picked (i.e. the outer dst, stashed via CB_FORCED_BACKEND_V4),
 *    and on netkit deliver straight into the Pod netns via ctx_redirect_peer,
 *  - for an L7-punt-proxy service whose backend is local, decap *without*
 *    running the forced-backend DNAT and punt the inner up to the host stack
 *    so Envoy can intercept it (this is the --enable-ipip-termination Envoy
 *    target path).
 */

#define __CONFIG_IPIP_USE_OUTER_DST

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

	/* SVC_BACKEND_IP is used here to distinguish from outer dst IP of the packet */
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 124,
			  SVC_BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

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
