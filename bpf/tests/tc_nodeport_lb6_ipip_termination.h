/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6 1
#define ENABLE_NODEPORT 1
#define DSR_ENCAP_IPIP		2
#define DSR_ENCAP_MODE		DSR_ENCAP_IPIP

#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_PORT		tcp_svc_one

#define DEFAULT_IFACE		24
#define BACKEND_IFACE		25

#define BACKEND_EP_ID		127

static volatile const __u8 *lb_node_mac = mac_one;
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *backend_mac = mac_four;

enum {
	RECORD_REDIRECT_PEER = 0,
	RECORD_REDIRECT,
	RECORD_TAILCALL,
	RECORD_MAX,
};

static volatile __u32 num_calls[RECORD_MAX];

/* See the IPv4 sibling file for why we wrap the overloadable.h include in
 * an EVENT_SOURCE define/undef and mock ctx_get_xfer via a macro.
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
ASSIGN_CONFIG(__u32, encap6_ifindex, 42)
ASSIGN_CONFIG(bool, enable_bpf_host_routing, true)
ASSIGN_CONFIG(bool, enable_endpoint_routes, true)
ASSIGN_CONFIG(bool, enable_netkit, false)
ASSIGN_CONFIG(bool, enable_ipip_termination, true)
ASSIGN_CONFIG(struct dsr_config, dsr_cfg, { .enable = true })
ASSIGN_CONFIG(bool, enable_nodeport_acceleration, true) /* exercise the XFER_PKT_NO_SVC handoff */

/* Build a v6-in-v6 DSR-IPIP TCP SYN. pktgen's IPv6 finisher only sets nexthdr
 * based on the next layer it knows about (TCP/UDP/...). For stacked IPv6 we
 * fix up the OUTER nexthdr to NEXTHDR_IPV6 manually.
 */
static __always_inline int
pktgen_ipip_v6(struct __ctx_buff *ctx, const void *outer_dst,
	       const void *inner_dst)
{
	struct pktgen builder;
	struct ipv6hdr *outer_l3, *inner_l3;
	struct tcphdr *l4;
	struct ethhdr *l2;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)lb_node_mac, (__u8 *)node_mac);

	outer_l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!outer_l3)
		return TEST_ERROR;
	memcpy(&outer_l3->saddr, (void *)v6_node_one, 16);
	memcpy(&outer_l3->daddr, outer_dst, 16);

	inner_l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!inner_l3)
		return TEST_ERROR;
	memcpy(&inner_l3->saddr, (void *)v6_pod_one, 16);	/* client */
	memcpy(&inner_l3->daddr, inner_dst, 16);

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

	/* Outer nexthdr was left at the value pktgen picked (the inner's
	 * "L4"-equivalent). Force it to NEXTHDR_IPV6 to make the packet a
	 * proper v6-in-v6 IPIP packet for the strip gate to match.
	 */
	{
		void *pdata = (void *)(long)ctx_data(ctx);
		void *pdata_end = (void *)(long)ctx->data_end;
		struct ipv6hdr *o;

		o = pdata + sizeof(struct ethhdr);
		if ((void *)o + sizeof(struct ipv6hdr) > pdata_end)
			return TEST_ERROR;
		o->nexthdr = NEXTHDR_IPV6;
	}

	return 0;
}
