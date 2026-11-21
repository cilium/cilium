// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/*
 * IPv6 mirror of tc_nodeport_lb4_ipip_termination.c. Covers the inbound
 * DSR IPIP6 (v6-in-v6) termination path introduced in
 *   "bpf: terminate inbound DSR IPIP6 in BPF on netdev ingress"
 * and the rest of the inbound-IPIP6 + redirect_peer stack.
 *
 * The v6 strip block in do_netdev() only fires when the outer's nexthdr
 * is NEXTHDR_IPV6 directly (no extension headers, which the DSR-IPIP6
 * encap path never inserts), the outer dst resolves to a local endpoint,
 * and we're on the physical netdev (!from_host).
 */

#define __CONFIG_IPIP_USE_OUTER_DST

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
