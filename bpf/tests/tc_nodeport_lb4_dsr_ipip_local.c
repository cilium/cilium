// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/*
 * Tests for the LB-node side of DSR-IPIP when the LB-picked backend is
 * co-located on the LB node itself. The remote-backend (IPIP encap) case
 * is covered by tc_nodeport_lb4_dsr_ipip.c. The backend-node side (decap
 * after IPIP termination) is covered by tc_nodeport_lb4_ipip_termination.c.
 *
 * Two cases here:
 *
 *  * Local Pod backend on a DSR-IPIP service. Per
 *      "bpf: DNAT local backends under DSR IPIP dispatch"
 *    nodeport_skip_xlate4() must NOT skip DNAT for a local backend even
 *    though DSR_ENCAP_MODE == DSR_ENCAP_IPIP. We expect plain DNAT to the
 *    Pod and ctx_redirect_peer() delivery (no IPIP encap to ourselves).
 *
 *  * Local L7-punt-proxy backend on a DSR-IPIP service. Same as above but
 *    the service has SVC_FLAG_L7_DELEGATE and the "backend" is the local
 *    host (Envoy on this node). nodeport_svc_lb4 must punt to the host
 *    stack via the lb4_svc_is_l7_punt_proxy && backend_local gate before
 *    any DNAT runs - same contract as the equivalent termination-side test.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_DSR		1
#define DSR_ENCAP_IPIP		2
#define DSR_ENCAP_MODE		DSR_ENCAP_IPIP
#define ENABLE_HOST_ROUTING	1

/* nodeport_lb4 references this for DSR_ENCAP_IPIP egress (TX side). The
 * remote-encap test exercises it; here we only ever pick local backends
 * so it shouldn't get used, but the symbol must resolve at compile time.
 */
#define ENCAP4_IFINDEX		42

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define LB_NODE_IP		v4_node_one	/* this node, the LB */
#define IPV4_DIRECT_ROUTING	LB_NODE_IP

#define FRONTEND_IP		v4_svc_one	/* regular DSR-IPIP svc VIP */
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v4_pod_one	/* local Pod backend */
#define BACKEND_PORT		FRONTEND_PORT

#define L7_FRONTEND_IP		v4_svc_two	/* L7-delegate svc VIP */
#define L7_HOST_BACKEND_IP	LB_NODE_IP	/* host-ns Envoy on this node */

#define DEFAULT_IFACE		24
#define BACKEND_IFACE		25
#define BACKEND_EP_ID		127

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *backend_mac = mac_four;

enum {
	RECORD_REDIRECT_PEER = 0,
	RECORD_REDIRECT,
	RECORD_ENCAP_REDIRECT,	/* redirect to ENCAP4_IFINDEX = IPIP encap egress */
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
	if (ifindex == ENCAP4_IFINDEX)
		num_calls[RECORD_ENCAP_REDIRECT]++;
	else
		num_calls[RECORD_REDIRECT]++;
	return CTX_ACT_REDIRECT;
}

#include "lib/bpf_host.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)
ASSIGN_CONFIG(bool, enable_netkit, true)

/* Build a plain client -> svc TCP SYN. No IPIP wrapping - this is the first
 * hop into the LB node from the external client.
 */
static __always_inline int
pktgen_client_to_svc(struct __ctx_buff *ctx, __be32 svc_addr, __be16 svc_port)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  CLIENT_IP, svc_addr,
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
/* Test 1: client -> DSR-IPIP svc, backend picked is a LOCAL Pod.             */
/*                                                                            */
/* Pre-"bpf: DNAT local backends under DSR IPIP dispatch", nodeport_skip_     */
/* xlate4() returned true unconditionally under DSR_ENCAP_IPIP, so the DNAT   */
/* to the Pod was skipped and the Pod saw the LB VIP as its dst. With the     */
/* fix, DNAT runs for local backends and ctx_redirect_peer delivers into the  */
/* Pod netns (netkit). No IPIP encap happens.                                 */
/* -------------------------------------------------------------------------- */

PKTGEN("tc", "tc_nodeport_dsr_ipip_lb_local_pod")
int nodeport_dsr_ipip_lb_local_pod_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_client_to_svc(ctx, FRONTEND_IP, FRONTEND_PORT);
}

SETUP("tc", "tc_nodeport_dsr_ipip_lb_local_pod")
int nodeport_dsr_ipip_lb_local_pod_setup(struct __ctx_buff *ctx)
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
	num_calls[RECORD_ENCAP_REDIRECT] = 0;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_dsr_ipip_lb_local_pod")
int nodeport_dsr_ipip_lb_local_pod_check(struct __ctx_buff *ctx)
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

	/* Must deliver into the Pod netns directly, NOT IPIP-encap back out. */
	assert(*status_code == CTX_ACT_REDIRECT);
	if (num_calls[RECORD_REDIRECT_PEER] != 1)
		test_fatal("expected one ctx_redirect_peer, got %u",
			   num_calls[RECORD_REDIRECT_PEER]);
	if (num_calls[RECORD_ENCAP_REDIRECT] != 0)
		test_fatal("packet was IPIP-encapped for a local backend (got %u redirects to ENCAP4_IFINDEX)",
			   num_calls[RECORD_ENCAP_REDIRECT]);
	if (num_calls[RECORD_REDIRECT] != 0)
		test_fatal("did not expect plain ctx_redirect, got %u",
			   num_calls[RECORD_REDIRECT]);

	/* The packet must be DNAT'ed to the local Pod (the fd483bd2cd contract).
	 * Layout: [ETH][IPv4 src=CLIENT, dst=BACKEND, proto=TCP][TCP SYN].
	 */
	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->protocol != IPPROTO_TCP)
		test_fatal("outermost L3 proto is %u, expected TCP (got IPIP-encapped?)",
			   l3->protocol);
	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP changed unexpectedly");
	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP is %x, expected BACKEND_IP - DNAT was skipped on local backend (pre-fd483bd2cd bug)",
			   l3->daddr);

	l4 = (void *)l3 + sizeof(struct iphdr);
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
/* Test 2: client -> DSR-IPIP svc, backend is the LOCAL host (Envoy in        */
/* host-ns, L7-punt-proxy). The service has SVC_FLAG_L7_DELEGATE; the         */
/* lb4_svc_is_l7_punt_proxy && backend_local gate in nodeport_svc_lb4 must    */
/* punt to host stack so Envoy can intercept on the same 5-tuple - no DNAT,   */
/* no encap, no redirect.                                                     */
/* -------------------------------------------------------------------------- */

PKTGEN("tc", "tc_nodeport_dsr_ipip_lb_local_l7punt")
int nodeport_dsr_ipip_lb_local_l7punt_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_client_to_svc(ctx, L7_FRONTEND_IP, FRONTEND_PORT);
}

SETUP("tc", "tc_nodeport_dsr_ipip_lb_local_l7punt")
int nodeport_dsr_ipip_lb_local_l7punt_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	lb_v4_add_service_with_flags(L7_FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP,
				     1, revnat_id,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_LOADBALANCER,
				     SVC_FLAG_L7_DELEGATE);
	lb_v4_add_backend(L7_FRONTEND_IP, FRONTEND_PORT, 1, 200,
			  L7_HOST_BACKEND_IP, FRONTEND_PORT, IPPROTO_TCP, 0);

	endpoint_v4_add_entry(L7_HOST_BACKEND_IP, 0, 0, ENDPOINT_F_HOST,
			      HOST_ID, 0, NULL, NULL);
	ipcache_v4_add_entry(L7_HOST_BACKEND_IP, 0, HOST_ID, 0, 0);

	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	num_calls[RECORD_ENCAP_REDIRECT] = 0;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_dsr_ipip_lb_local_l7punt")
int nodeport_dsr_ipip_lb_local_l7punt_check(struct __ctx_buff *ctx)
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

	/* No DNAT: the host stack / Envoy must see the same 5-tuple as on the
	 * wire - src=CLIENT_IP, dst=L7_FRONTEND_IP.
	 */
	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->protocol != IPPROTO_TCP)
		test_fatal("L3 proto changed");
	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP changed");
	if (l3->daddr != L7_FRONTEND_IP)
		test_fatal("dst IP was rewritten - forced/picked-backend DNAT must not run on L7-punt-proxy path (got %x)",
			   l3->daddr);

	test_finish();
}
