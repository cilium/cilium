// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include "bpf/compiler.h"
#include <bpf/ctx/skb.h>
#include "mock_skb_metadata.h"
#include "pktgen.h"

/*
 * Datapath configurations
 */

/* Set dummy ifindex for tunnel device */
#define ENCAP_IFINDEX 1

/* Overlapping PodCIDR is only supported for IPv4 for now */
#define ENABLE_IPV4

/* Overlapping PodCIDR depends on tunnel */
#define TUNNEL_MODE

/* Fully enable KPR since kubeproxy doesn't understand cluster aware addressing */
#define ENABLE_NODEPORT

/* Cluster-aware addressing is mandatory for overlapping PodCIDR support */
#define ENABLE_CLUSTER_AWARE_ADDRESSING

/* Inter-cluster SNAT is mandatory for overlapping PodCIDR support for now */
#define ENABLE_INTER_CLUSTER_SNAT

/* Import map definitions and some default values */
#include "node_config.h"

/* Overwrite the default port range defined in node_config.h
 * to have deterministic source port selection.
 */
#undef NODEPORT_PORT_MAX
#undef NODEPORT_PORT_MIN_NAT
#undef NODEPORT_PORT_MAX_NAT
#define NODEPORT_PORT_MAX 32767
#define NODEPORT_PORT_MIN_NAT (NODEPORT_PORT_MAX + 1)
#define NODEPORT_PORT_MAX_NAT (NODEPORT_PORT_MIN_NAT + 1)

/* Overwrite (local) CLUSTER_ID defined in node_config.h */
#undef CLUSTER_ID
#define CLUSTER_ID 1

/*
 * Test configurations
 */
#define CLIENT_IFINDEX		12345
#define CLIENT_MAC		mac_one
#define CLIENT_ROUTER_MAC	mac_two
#define BACKEND_ROUTER_MAC	mac_three
#define CLIENT_IP		v4_pod_one
#define BACKEND_IP		v4_pod_two
#define CLIENT_NODE_IP		v4_ext_one
#define BACKEND_NODE_IP		v4_ext_two
#define CLIENT_PORT		__bpf_htons(NODEPORT_PORT_MAX_NAT + 1)
#define BACKEND_PORT		tcp_svc_one
#define BACKEND_CLUSTER_ID	2
#define BACKEND_IDENTITY	(0x00000000 | (BACKEND_CLUSTER_ID << 16) | 0xff01)

#undef IPV4_INTER_CLUSTER_SNAT
#define IPV4_INTER_CLUSTER_SNAT CLIENT_NODE_IP

/* SNAT should always select NODEPORT_PORT_MIN_NAT as a source */
#define CLIENT_INTER_CLUSTER_SNAT_PORT __bpf_htons(NODEPORT_PORT_MIN_NAT)

/* Mock out get_tunnel_key to emulate input from tunnel device */
#define skb_get_tunnel_key mock_skb_get_tunnel_key

static __always_inline
int mock_skb_get_tunnel_key(struct __ctx_buff *ctx __maybe_unused, struct bpf_tunnel_key *to,
			    __u32 size __maybe_unused, __u32 flags __maybe_unused)
{
	to->remote_ipv4 = BACKEND_NODE_IP;
	to->tunnel_id = BACKEND_IDENTITY;
	return 0;
}

/*
 * Mock out send_drop_notify. This is because it uses ctx_store_meta internally
 * and breaks the skb->cb test.
 */

#define DEBUG
#include <lib/drop.h>

#define _send_drop_notify mock_send_drop_notify

static __always_inline
int mock_send_drop_notify(__u8 file __maybe_unused, __u16 line __maybe_unused,
			  struct __ctx_buff *ctx, __u32 src __maybe_unused,
			  __u32 dst __maybe_unused, __u32 dst_id __maybe_unused,
			  __u32 reason, __u32 exitcode, enum metric_dir direction)
{
	cilium_dbg3(ctx, DBG_GENERIC, reason, exitcode, direction);
	return exitcode;
}

/* Include an actual datapath code */
#include <bpf_overlay.c>

#include "lib/endpoint.h"

/*
 * Tests
 */

#define TO_OVERLAY 0
#define FROM_OVERLAY 1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_OVERLAY] = &cil_to_overlay,
		[FROM_OVERLAY] = &cil_from_overlay,
	},
};

static __always_inline int
pktgen_to_overlay(struct __ctx_buff *ctx, bool syn, bool ack)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)CLIENT_MAC, (__u8 *)CLIENT_ROUTER_MAC,
					  CLIENT_IP, BACKEND_IP,
					  CLIENT_PORT, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = syn ? 1 : 0;
	l4->ack = ack ? 1 : 0;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

static __always_inline int
pktgen_from_overlay(struct __ctx_buff *ctx, bool syn, bool ack)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)BACKEND_ROUTER_MAC,
					  (__u8 *)CLIENT_ROUTER_MAC,
					  BACKEND_IP, IPV4_INTER_CLUSTER_SNAT,
					  BACKEND_PORT, CLIENT_INTER_CLUSTER_SNAT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = syn ? 1 : 0;
	l4->ack = ack ? 1 : 0;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

PKTGEN("tc", "01_to_overlay_syn")
int to_overlay_syn_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to_overlay(ctx, true, false);
}

SETUP("tc", "01_to_overlay_syn")
int to_overlay_syn_setup(struct __ctx_buff *ctx)
{
	/* Emulate input from bpf_lxc */
	ctx_set_cluster_id_mark(ctx, 2);

	tail_call_static(ctx, &entry_call_map, TO_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "01_to_overlay_syn")
int to_overlay_syn_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__s32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct ipv4_ct_tuple tuple;
	struct ipv4_nat_entry *entry;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_fatal("unexpected status code %d, want %d", *status_code, CTX_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)CLIENT_MAC, ETH_ALEN) != 0)
		test_fatal("src MAC has changed")

	if (memcmp(l2->h_dest, (__u8 *)CLIENT_ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("dst MAC has changed")

	if (l3->saddr != IPV4_INTER_CLUSTER_SNAT)
		test_fatal("src IP hasn't been SNATed for inter-cluster communication");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP has changed");

	if (l4->source != CLIENT_INTER_CLUSTER_SNAT_PORT)
		test_fatal("src port hasn't been SNATed for inter-cluster communication");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port has changed");

	tuple.daddr = BACKEND_IP;
	tuple.saddr = CLIENT_IP;
	tuple.dport = BACKEND_PORT;
	tuple.sport = CLIENT_PORT;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.flags = TUPLE_F_OUT;

	entry = map_lookup_elem(&per_cluster_snat_mapping_ipv4_2, &tuple);
	if (!entry)
		test_fatal("couldn't find egress SNAT mapping");

	tuple.daddr = IPV4_INTER_CLUSTER_SNAT;
	tuple.saddr = BACKEND_IP;
	tuple.dport = CLIENT_INTER_CLUSTER_SNAT_PORT;
	tuple.sport = BACKEND_PORT;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.flags = TUPLE_F_IN;

	entry = map_lookup_elem(&per_cluster_snat_mapping_ipv4_2, &tuple);
	if (!entry)
		test_fatal("couldn't find ingress SNAT mapping");

	test_finish();
}

PKTGEN("tc", "02_from_overlay_synack")
int from_overlay_synack_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_overlay(ctx, true, true);
}

SETUP("tc", "02_from_overlay_synack")
int from_overlay_synack_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(CLIENT_IP, CLIENT_IFINDEX, 0, 0,
			      (__u8 *)CLIENT_MAC, (__u8 *)CLIENT_ROUTER_MAC);

	tail_call_static(ctx, &entry_call_map, FROM_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "02_from_overlay_synack")
int from_overlay_synack_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__s32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 meta;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* The packet should go to ipv4_local_delivery and dropped with
	 * missed tail call since the POLICY_CALL_MAP should be empty.
	 */
	if (*status_code != CTX_ACT_DROP)
		test_fatal("unexpected status code %d, want %d", *status_code, CTX_ACT_DROP);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)CLIENT_ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("src MAC is not client router MAC");

	if (memcmp(l2->h_dest, (__u8 *)CLIENT_MAC, ETH_ALEN) != 0)
		test_fatal("dst MAC is not client MAC");

	if (l3->saddr != BACKEND_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != CLIENT_IP)
		test_fatal("dst IP hasn't been RevSNATed to client IP");

	if (l4->source != BACKEND_PORT)
		test_fatal("src port has changed");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port hasn't been RevSNATed to client port");

	meta = ctx_load_meta(ctx, CB_IFINDEX);
	if (meta != CLIENT_IFINDEX)
		test_fatal("skb->cb[CB_IFINDEX] should be %d, got %d", CLIENT_IFINDEX, meta);

	meta = ctx_load_meta(ctx, CB_SRC_LABEL);
	if (meta != BACKEND_IDENTITY)
		test_fatal("skb->cb[CB_SRC_LABEL] should be %d, got %d", BACKEND_IDENTITY, meta);

	meta = ctx_load_meta(ctx, CB_FROM_TUNNEL);
	if (meta != 1)
		test_fatal("skb->cb[CB_FROM_TUNNEL] should be 1, got %d", meta);

	meta = ctx_load_meta(ctx, CB_FROM_HOST);
	if (meta != 0)
		test_fatal("skb->cb[CB_FROM_HOST] should be 0, got %d", meta);

	meta = ctx_load_meta(ctx, CB_CLUSTER_ID_INGRESS);
	if (meta != BACKEND_CLUSTER_ID)
		test_fatal("skb->cb[CB_CLUSTER_ID_INGRESS] should be %u, got %d",
			   BACKEND_CLUSTER_ID, meta);

	test_finish();
}

PKTGEN("tc", "03_to_overlay_ack")
int to_overlay_ack_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to_overlay(ctx, false, true);
}

SETUP("tc", "03_to_overlay_ack")
int to_overlay_ack_setup(struct __ctx_buff *ctx)
{
	/* Emulate input from bpf_lxc */
	ctx_set_cluster_id_mark(ctx, 2);

	tail_call_static(ctx, &entry_call_map, TO_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "03_to_overlay_ack")
int to_overlay_ack_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__s32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_fatal("unexpected status code %d, want %d", *status_code, CTX_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)CLIENT_MAC, ETH_ALEN) != 0)
		test_fatal("src MAC has changed");

	if (memcmp(l2->h_dest, (__u8 *)CLIENT_ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("dst MAC has changed");

	if (l3->saddr != IPV4_INTER_CLUSTER_SNAT)
		test_fatal("src IP hasn't been SNATed for inter-cluster communication");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP has changed");

	if (l4->source != CLIENT_INTER_CLUSTER_SNAT_PORT)
		test_fatal("src port hasn't been SNATed for inter-cluster communication");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port has changed");

	test_finish();
}
