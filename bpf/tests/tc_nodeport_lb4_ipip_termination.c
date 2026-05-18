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

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_NODEPORT_ACCELERATION	/* exercise the XFER_PKT_NO_SVC handoff */
#define ENABLE_DSR		1
#define DSR_ENCAP_IPIP		2
#define DSR_ENCAP_MODE		DSR_ENCAP_IPIP
#define ENABLE_IPIP_TERMINATION	1
#define ENABLE_HOST_ROUTING	1

/* nodeport_lb4 references this for DSR_ENCAP_IPIP egress (TX side). We only
 * exercise the RX/decap side here, but the symbol needs to resolve.
 */
#define ENCAP4_IFINDEX		42

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define LB_NODE_IP		v4_node_one	/* announcer / IPIP outer src */
#define BACKEND_NODE_IP		v4_node_two	/* this node */

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v4_pod_one	/* local pod, IPIP outer dst */
#define BACKEND_PORT		FRONTEND_PORT	/* identity port mapping */

/* For the L7-punt-proxy test: the LB-picked "backend" is the host itself
 * (Envoy target). Outer dst is this node's IP, set up as a HOST endpoint.
 */
#define L7_FRONTEND_IP		v4_svc_two
#define L7_HOST_BACKEND_IP	BACKEND_NODE_IP

#define DEFAULT_IFACE		24
#define BACKEND_IFACE		25

#define BACKEND_EP_ID		127

static volatile const __u8 *lb_node_mac = mac_one;
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *backend_mac = mac_four;

/* Track redirect_peer / redirect to confirm the right delivery primitive. */
enum {
	RECORD_REDIRECT_PEER = 0,
	RECORD_REDIRECT,
	RECORD_MAX,
};

static volatile __u32 num_calls[RECORD_MAX];

/* Simulated XDP -> TC handoff state. cil_from_netdev calls ctx_get_xfer()
 * at entry; with ENABLE_NODEPORT_ACCELERATION set this is how XDP signals
 * "I couldn't classify, skip nodeport at TC" via XFER_PKT_NO_SVC. We mock
 * it so each test can choose whether to simulate XDP having run upstream.
 *
 * Pull in lib/overloadable.h first so that ctx_get_xfer's static inline
 * definition gets the original name. The #define below then only rewrites
 * subsequent call sites (cil_from_netdev pulled in via lib/bpf_host.h).
 *
 * overloadable_skb.h includes lib/common.h which defines EVENT_SOURCE=0
 * (only with #ifndef), but bpf_host.c expects to be the first to set it
 * (to CONFIG(host_ep_id)). Pre-define+undef so the include below doesn't
 * leave EVENT_SOURCE defined when bpf_host.c gets pulled in later.
 */
#define EVENT_SOURCE 0
#include <lib/overloadable.h>
#undef EVENT_SOURCE

static volatile __u32 xdp_xfer_flags;

#define ctx_get_xfer mock_ctx_get_xfer
static __always_inline __maybe_unused __u32
mock_ctx_get_xfer(struct __sk_buff *ctx __maybe_unused, __u32 off __maybe_unused)
{
	return xdp_xfer_flags;
}

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
	num_calls[RECORD_REDIRECT]++;
	return CTX_ACT_REDIRECT;
}

#include "lib/bpf_host.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)
ASSIGN_CONFIG(bool, enable_netkit, true)

/*
 * Build an IPIP-encapped TCP SYN with:
 *   outer ETH | outer IPv4 (proto=IPIP, src=$lb_node, dst=$outer_dst) |
 *   inner IPv4 (src=$client, dst=FRONTEND) | TCP SYN
 *
 * pktgen's IPv4 finish doesn't know how to set protocol=IPIP for a stacked
 * IPv4-in-IPv4 packet (the inner layer is just another IPv4 to it), so we
 * fix up the outer protocol and recompute its checksum manually after
 * pktgen__finish().
 */
static __always_inline int
pktgen_ipip_v4(struct __ctx_buff *ctx, __be32 outer_dst, __be32 inner_dst)
{
	struct pktgen builder;
	struct iphdr *outer_l3, *inner_l3;
	struct tcphdr *l4;
	struct ethhdr *l2;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)lb_node_mac, (__u8 *)node_mac);

	outer_l3 = pktgen__push_default_iphdr(&builder);
	if (!outer_l3)
		return TEST_ERROR;
	outer_l3->saddr = LB_NODE_IP;
	outer_l3->daddr = outer_dst;

	inner_l3 = pktgen__push_default_iphdr(&builder);
	if (!inner_l3)
		return TEST_ERROR;
	inner_l3->saddr = CLIENT_IP;
	inner_l3->daddr = inner_dst;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = CLIENT_PORT;
	l4->dest = FRONTEND_PORT;
	l4->syn = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	/* Fix up the outer IPv4: pktgen__finish sees the inner IPv4 as L4 and
	 * leaves outer->protocol untouched (== 0). Set it to IPPROTO_IPIP and
	 * recompute the outer header checksum.
	 */
	{
		void *pdata = (void *)(long)ctx_data(ctx);
		void *pdata_end = (void *)(long)ctx->data_end;
		struct iphdr *o;

		o = pdata + sizeof(struct ethhdr);
		if ((void *)o + sizeof(struct iphdr) > pdata_end)
			return TEST_ERROR;
		o->protocol = IPPROTO_IPIP;
		o->check = 0;
		o->check = csum_fold(csum_diff(NULL, 0, o, sizeof(*o), 0));
	}

	return 0;
}

/* -------------------------------------------------------------------------- */
/* Test 1: outer dst is a local Pod IP. Expect strip + DNAT + redirect_peer.  */
/* -------------------------------------------------------------------------- */

PKTGEN("tc", "tc_nodeport_ipip_term_v4_local_pod")
int ipip_term_v4_local_pod_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_ipip_v4(ctx, BACKEND_IP, FRONTEND_IP);
}

SETUP("tc", "tc_nodeport_ipip_term_v4_local_pod")
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
	xdp_xfer_flags = 0;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_ipip_term_v4_local_pod")
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

	/* Must redirect_peer (BPF host routing + netkit + from_netdev). */
	assert(*status_code == CTX_ACT_REDIRECT);
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

PKTGEN("tc", "tc_nodeport_ipip_term_v4_l7_punt_proxy")
int ipip_term_v4_l7_punt_proxy_pktgen(struct __ctx_buff *ctx)
{
	/* Outer dst = local host IP; inner dst = the L7-delegate svc VIP. */
	return pktgen_ipip_v4(ctx, L7_HOST_BACKEND_IP, L7_FRONTEND_IP);
}

SETUP("tc", "tc_nodeport_ipip_term_v4_l7_punt_proxy")
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
	xdp_xfer_flags = 0;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_ipip_term_v4_l7_punt_proxy")
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

PKTGEN("tc", "tc_nodeport_ipip_term_v4_xdp_handoff")
int ipip_term_v4_xdp_handoff_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_ipip_v4(ctx, BACKEND_IP, FRONTEND_IP);
}

SETUP("tc", "tc_nodeport_ipip_term_v4_xdp_handoff")
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

	/* Simulate XDP NodePort acceleration: the IPIP outer can't be
	 * classified (proto=4 has no L4 service tuple), so XDP returned
	 * CTX_ACT_OK with XFER_PKT_NO_SVC set. cil_from_netdev will read
	 * this and call ctx_skip_nodeport_set() on the skb.
	 */
	xdp_xfer_flags = XFER_PKT_NO_SVC;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_ipip_term_v4_xdp_handoff")
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

	/* End result must be identical to the non-XDP local_pod case. If the
	 * IPIP strip didn't clear the skip-nodeport hint, handle_ipv4 would
	 * skip nodeport_lb4(), no DNAT would run, and dst would stay LB VIP.
	 */
	assert(*status_code == CTX_ACT_REDIRECT);
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
