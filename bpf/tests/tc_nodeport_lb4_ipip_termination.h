/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4 1
#define ENABLE_NODEPORT 1
#define DSR_ENCAP_IPIP		2
#define DSR_ENCAP_MODE		DSR_ENCAP_IPIP

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

/* Track policy tail-call / redirect_peer / redirect to confirm the right
 * delivery primitive.
 */
enum {
	RECORD_REDIRECT_PEER = 0,
	RECORD_REDIRECT,
	RECORD_TAILCALL,
	RECORD_MAX,
};

static volatile __u32 num_calls[RECORD_MAX];

/* Simulated XDP -> TC handoff state. cil_from_netdev calls ctx_get_xfer()
 * at entry; with enable_nodeport_acceleration config set, this is how XDP signals
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

/* The decapped packet is delivered to the local backend Pod via
 * ipv4_local_delivery() -> local_delivery(). With BPF host routing on a
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
 * leaves at 0. Mock it to the physical netdev index so the runtime arm mirrors
 * a real phys-netdev TC ingress.
 */
static volatile __u32 mock_ingress_ifindex = DEFAULT_IFACE;
#define ctx_get_ingress_ifindex mock_ctx_get_ingress_ifindex
static __always_inline __maybe_unused __u32
mock_ctx_get_ingress_ifindex(const struct __sk_buff *ctx __maybe_unused)
{
	return mock_ingress_ifindex;
}

#include "lib/bpf_host.h"

/* Stands in for bpf_lxc's tail_ipv4_policy program: reads the calling-convention
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

/* nodeport_lb4 references this for DSR_ENCAP_IPIP egress (TX side). We only
 * exercise the RX/decap side here, but the dummy runtime-config value is required.
 */
ASSIGN_CONFIG(__u32, encap4_ifindex, 42)

ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)
ASSIGN_CONFIG(bool, enable_bpf_host_routing, true)
ASSIGN_CONFIG(bool, enable_endpoint_routes, true)
ASSIGN_CONFIG(bool, enable_netkit, false)
ASSIGN_CONFIG(bool, enable_ipip_termination, true)
ASSIGN_CONFIG(struct dsr_config, dsr_cfg, { .enable = true })
ASSIGN_CONFIG(bool, enable_nodeport_acceleration, true) /* exercise the XFER_PKT_NO_SVC handoff */

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
