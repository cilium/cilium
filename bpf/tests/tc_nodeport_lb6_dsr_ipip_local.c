// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/*
 * IPv6 mirror of tc_nodeport_lb4_dsr_ipip_local.c. Covers the LB-node side
 * of DSR-IPIP6 when the LB-picked backend is local to this node.
 *
 *  * Local Pod backend on a DSR-IPIP6 service: nodeport_skip_xlate6() must
 *    DNAT instead of skipping it (per "bpf: DNAT local backends under DSR
 *    IPIP dispatch"), and ctx_redirect_peer() delivers the now-DNAT'ed
 *    packet into the Pod's netkit peer.
 *
 *  * Local L7-punt-proxy backend on a DSR-IPIP6 service: lb6_svc_is_l7_
 *    punt_proxy && backend_local must punt to host stack before DNAT runs.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_DSR		1
#define DSR_ENCAP_IPIP		2
#define DSR_ENCAP_MODE		DSR_ENCAP_IPIP

#define ENCAP6_IFINDEX		42

#define CLIENT_PORT		__bpf_htons(111)
#define FRONTEND_PORT		tcp_svc_one

#define DEFAULT_IFACE		24
#define BACKEND_IFACE		25
#define BACKEND_EP_ID		127

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *backend_mac = mac_four;

enum {
	RECORD_REDIRECT_PEER = 0,
	RECORD_REDIRECT,
	RECORD_ENCAP_REDIRECT,
	RECORD_TAILCALL,
	RECORD_MAX,
};

static volatile __u32 num_calls[RECORD_MAX];

#define ctx_redirect_peer mock_ctx_redirect_peer
static __always_inline __maybe_unused int
mock_ctx_redirect_peer(const struct __ctx_buff *ctx __maybe_unused,
		       int ifindex __maybe_unused,
		       __u32 flags __maybe_unused)
{
	num_calls[RECORD_REDIRECT_PEER]++;
	return CTX_ACT_REDIRECT;
}

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __ctx_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused,
		  __u32 flags __maybe_unused)
{
	if (ifindex == ENCAP6_IFINDEX)
		num_calls[RECORD_ENCAP_REDIRECT]++;
	else
		num_calls[RECORD_REDIRECT]++;
	return CTX_ACT_REDIRECT;
}

/* The DNAT'ed packet is delivered to the local backend Pod via
 * ipv6_local_delivery() -> local_delivery(). With BPF host routing on a
 * from_netdev (from_host=false) packet, should_redirect_peer() is true, so
 * local_delivery() jumps to the destination Pod's policy program through
 * tail_call_policy() and that program performs the redirect_ep(). The unit-test
 * harness loads no per-endpoint policy program, so - mirroring
 * tc_redirect_netdev.h - we route the policy tail-call into a stub that runs
 * the redirect_ep() the real bpf_lxc policy program would.
 */
int mock_tail_policy(struct __ctx_buff *ctx); /* defined below bpf_host.h */

__section_entry
int mock_handle_policy(struct __ctx_buff *ctx)
{
	num_calls[RECORD_TAILCALL]++;
	if (num_calls[RECORD_TAILCALL] == 1)
		return mock_tail_policy(ctx);
	return CTX_ACT_DROP;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[BACKEND_EP_ID] = &mock_handle_policy,
	},
};

static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused,
		       __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

#define tail_call_dynamic mock_tail_call_dynamic

/* should_redirect_peer() keys off skb->ingress_ifindex, which BPF_PROG_TEST_RUN
 * leaves at 0. On netkit that runtime arm is what selects redirect_peer(), so
 * mock it to the physical netdev index to mirror a real phys-netdev TC ingress.
 */
static volatile __u32 mock_ingress_ifindex = DEFAULT_IFACE;
#define ctx_get_ingress_ifindex mock_ctx_get_ingress_ifindex
static __always_inline __maybe_unused __u32
mock_ctx_get_ingress_ifindex(const struct __sk_buff *ctx __maybe_unused)
{
	return mock_ingress_ifindex;
}

#include "lib/bpf_host.h"

/* Stands in for bpf_lxc's tail_ipv6_policy program: reads the calling-convention
 * meta that local_delivery_fill_meta() set and performs the redirect_ep() with
 * should_redirect_peer()'s verdict, exactly as the real policy program would.
 * We entered via cil_from_netdev, so from_host is false.
 */
int mock_tail_policy(struct __ctx_buff *ctx)
{
	bool do_redirect = ctx_load_meta(ctx, CB_DELIVERY_FLAGS) & CB_DELIVERY_FLAGS_REDIRECT;
	bool from_host = ctx_load_and_clear_meta(ctx, CB_FROM_HOST);

	if (do_redirect)
		return redirect_ep(ctx, CONFIG(interface_ifindex),
				   should_redirect_peer(ctx, from_host),
				   false);
	return CTX_ACT_DROP;
}

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)
ASSIGN_CONFIG(bool, enable_bpf_host_routing, true)
ASSIGN_CONFIG(bool, enable_netkit, true)

/* Plain client -> svc TCP SYN, no IPIP wrapping. */
static __always_inline int
pktgen_client_to_svc_v6(struct __ctx_buff *ctx, const void *svc_addr,
			__be16 svc_port)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  (__u8 *)v6_pod_one, (__u8 *)svc_addr,
					  CLIENT_PORT, svc_port);
	if (!l4)
		return TEST_ERROR;
	l4->syn = 1;

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* -------------------------------------------------------------------------- */
/* Test 1: client -> DSR-IPIP6 svc, backend picked is a LOCAL Pod. DNAT must  */
/* run (post-fd483bd2cd contract), delivery via ctx_redirect_peer, no encap.  */
/* -------------------------------------------------------------------------- */

PKTGEN("tc", "tc_nodeport_dsr_ipip_lb_local_pod_v6")
int nodeport_dsr_ipip_lb_local_pod_v6_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_client_to_svc_v6(ctx, (void *)v6_pod_three, FRONTEND_PORT);
}

SETUP("tc", "tc_nodeport_dsr_ipip_lb_local_pod_v6")
int nodeport_dsr_ipip_lb_local_pod_v6_setup(struct __ctx_buff *ctx)
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
	num_calls[RECORD_ENCAP_REDIRECT] = 0;
	num_calls[RECORD_TAILCALL] = 0;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_dsr_ipip_lb_local_pod_v6")
int nodeport_dsr_ipip_lb_local_pod_v6_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();

	endpoint_v6_del_entry((const union v6addr *)v6_pod_two);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	/* Deliver into the Pod netns directly, NOT IPIP-encap back out:
	 * local_delivery() makes one policy tail-call into the Pod's program
	 * (mocked here), which then delivers via ctx_redirect_peer().
	 */
	assert(*status_code == CTX_ACT_REDIRECT);
	if (num_calls[RECORD_TAILCALL] != 1)
		test_fatal("expected exactly one policy tail-call, got %u",
			   num_calls[RECORD_TAILCALL]);
	if (num_calls[RECORD_REDIRECT_PEER] != 1)
		test_fatal("expected one ctx_redirect_peer, got %u",
			   num_calls[RECORD_REDIRECT_PEER]);
	if (num_calls[RECORD_ENCAP_REDIRECT] != 0)
		test_fatal("packet was IPIP-encapped for a local backend (got %u redirects to ENCAP6_IFINDEX)",
			   num_calls[RECORD_ENCAP_REDIRECT]);
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
		test_fatal("outermost nexthdr is %u, expected TCP (got IPIP-encapped?)",
			   l3->nexthdr);
	if (memcmp(&l3->saddr, (void *)v6_pod_one, 16) != 0)
		test_fatal("src IP changed unexpectedly");
	if (memcmp(&l3->daddr, (void *)v6_pod_two, 16) != 0)
		test_fatal("dst IP not DNAT'ed to backend - DNAT was skipped on local backend (pre-fd483bd2cd bug)");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port changed");
	if (l4->dest != FRONTEND_PORT)
		test_fatal("dst port changed");
	if (!l4->syn)
		test_fatal("TCP flags lost the SYN");

	test_finish();
}

/* -------------------------------------------------------------------------- */
/* Test 2: client -> DSR-IPIP6 svc, backend is the LOCAL host (Envoy in       */
/* host-ns). Punt to stack; no DNAT, no encap, no redirect.                   */
/* -------------------------------------------------------------------------- */

PKTGEN("tc", "tc_nodeport_dsr_ipip_lb_local_l7punt_v6")
int nodeport_dsr_ipip_lb_local_l7punt_v6_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_client_to_svc_v6(ctx, (void *)v6_pod_three, FRONTEND_PORT);
}

SETUP("tc", "tc_nodeport_dsr_ipip_lb_local_l7punt_v6")
int nodeport_dsr_ipip_lb_local_l7punt_v6_setup(struct __ctx_buff *ctx)
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
			      ENDPOINT_F_HOST, HOST_ID, NULL, NULL);
	ipcache_v6_add_entry((const union v6addr *)v6_node_one, 0, HOST_ID, 0, 0);

	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	num_calls[RECORD_ENCAP_REDIRECT] = 0;
	num_calls[RECORD_TAILCALL] = 0;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_dsr_ipip_lb_local_l7punt_v6")
int nodeport_dsr_ipip_lb_local_l7punt_v6_check(struct __ctx_buff *ctx)
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
	if (num_calls[RECORD_ENCAP_REDIRECT] != 0)
		test_fatal("did not expect IPIP encap on L7-punt path, got %u",
			   num_calls[RECORD_ENCAP_REDIRECT]);
	if (num_calls[RECORD_REDIRECT] != 0)
		test_fatal("did not expect ctx_redirect on L7-punt path, got %u",
			   num_calls[RECORD_REDIRECT]);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");
	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->nexthdr != IPPROTO_TCP)
		test_fatal("nexthdr changed");
	if (memcmp(&l3->saddr, (void *)v6_pod_one, 16) != 0)
		test_fatal("src IP changed");
	if (memcmp(&l3->daddr, (void *)v6_pod_three, 16) != 0)
		test_fatal("dst IP was rewritten - DNAT must not run on L7-punt-proxy path");

	test_finish();
}
