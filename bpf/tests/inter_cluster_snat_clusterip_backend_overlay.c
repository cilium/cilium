// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "linux/if_ether.h"
#include "pktgen.h"
#include "mock_skb_metadata.h"

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
#define BACKEND_IFINDEX		12345
#define BACKEND_MAC		mac_one
#define BACKEND_ROUTER_MAC	mac_two
#define CLIENT_ROUTER_MAC	mac_three
#define BACKEND_IP		v4_pod_one
#define CLIENT_NODE_IP		v4_ext_one
#define BACKEND_NODE_IP		v4_ext_two
#define BACKEND_PORT		tcp_svc_one
#define CLIENT_CLUSTER_ID	1
#define CLIENT_IDENTITY		(0x00000000 | (CLIENT_CLUSTER_ID << 16) | 0xff01)

#undef IPV4_INTER_CLUSTER_SNAT
#define IPV4_INTER_CLUSTER_SNAT BACKEND_NODE_IP

/* SNAT should always select NODEPORT_PORT_MIN_NAT as a source */
#define CLIENT_INTER_CLUSTER_SNAT_PORT __bpf_htons(NODEPORT_PORT_MIN_NAT)

/* Mock out get_tunnel_key to emulate input from tunnel device */
#define skb_get_tunnel_key mock_skb_get_tunnel_key

int mock_skb_get_tunnel_key(struct __ctx_buff *ctx __maybe_unused, struct bpf_tunnel_key *to,
			    __u32 size __maybe_unused, __u32 flags __maybe_unused)
{
	to->remote_ipv4 = CLIENT_NODE_IP;
	to->tunnel_id = CLIENT_IDENTITY;
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
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)BACKEND_MAC, (__u8 *)BACKEND_ROUTER_MAC);

	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = BACKEND_IP;
	l3->daddr = CLIENT_NODE_IP;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = BACKEND_PORT;
	l4->dest = CLIENT_INTER_CLUSTER_SNAT_PORT;
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
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)CLIENT_ROUTER_MAC, (__u8 *)BACKEND_ROUTER_MAC);

	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_NODE_IP;
	l3->daddr = BACKEND_IP;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_INTER_CLUSTER_SNAT_PORT;
	l4->dest = BACKEND_PORT;
	l4->syn = syn ? 1 : 0;
	l4->ack = ack ? 1 : 0;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

PKTGEN("tc", "01_from_overlay_syn")
int from_overlay_syn_pktgen(struct __ctx_buff *ctx)
{
	/* Emulate input from bpf_lxc */
	ctx_set_cluster_id_mark(ctx, 0);

	return pktgen_from_overlay(ctx, true, false);
}

SETUP("tc", "01_from_overlay_syn")
int from_overlay_syn_setup(struct __ctx_buff *ctx)
{
	struct endpoint_key ep_key = {
		.ip4 = BACKEND_IP,
		.family = ENDPOINT_KEY_IPV4,
	};
	struct endpoint_info ep_value = {
		.ifindex = BACKEND_IFINDEX,
	};
	memcpy(&ep_value.mac, (__u8 *)BACKEND_MAC, ETH_ALEN);
	memcpy(&ep_value.node_mac, (__u8 *)BACKEND_ROUTER_MAC, ETH_ALEN);

	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	tail_call_static(ctx, &entry_call_map, FROM_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "01_from_overlay_syn")
int from_overlay_syn_check(struct __ctx_buff *ctx)
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

	if (memcmp(l2->h_source, (__u8 *)BACKEND_ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("src MAC is not the backend router MAC")

	if (memcmp(l2->h_dest, (__u8 *)BACKEND_MAC, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the backend MAC")

	if (l3->saddr != CLIENT_NODE_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP has changed");

	if (l4->source != CLIENT_INTER_CLUSTER_SNAT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port has changed");

	meta = ctx_load_meta(ctx, CB_IFINDEX);
	if (meta != BACKEND_IFINDEX)
		test_fatal("skb->cb[CB_IFINDEX] should be %d, got %d", BACKEND_IFINDEX, meta);

	meta = ctx_load_meta(ctx, CB_SRC_LABEL);
	if (meta != CLIENT_IDENTITY)
		test_fatal("skb->cb[CB_SRC_LABEL] should be %d, got %d", CLIENT_IDENTITY, meta);

	meta = ctx_load_meta(ctx, CB_FROM_TUNNEL);
	if (meta != 1)
		test_fatal("skb->cb[CB_FROM_TUNNEL] should be 1, got %d", meta);

	meta = ctx_load_meta(ctx, CB_FROM_HOST);
	if (meta != 0)
		test_fatal("skb->cb[CB_FROM_HOST] should be 0, got %d", meta);

	meta = ctx_load_meta(ctx, CB_CLUSTER_ID_INGRESS);
	if (meta != 0)
		test_fatal("skb->cb[CB_CLUSTER_ID_INGRESS] should be 0, got %d", meta);

	test_finish();
}

PKTGEN("tc", "02_to_overlay_synack")
int to_overlay_synack_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to_overlay(ctx, true, true);
}

SETUP("tc", "02_to_overlay_synack")
int to_overlay_synack_setup(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, &entry_call_map, TO_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "02_to_overlay_synack")
int to_overlay_synack_check(struct __ctx_buff *ctx)
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

	if (memcmp(l2->h_source, (__u8 *)BACKEND_MAC, ETH_ALEN) != 0)
		test_fatal("src MAC has changed")

	if (memcmp(l2->h_dest, (__u8 *)BACKEND_ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("dst MAC has changed")

	if (l3->saddr != BACKEND_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != CLIENT_NODE_IP)
		test_fatal("dst IP has changed");

	if (l4->source != BACKEND_PORT)
		test_fatal("src port has changed");

	if (l4->dest != CLIENT_INTER_CLUSTER_SNAT_PORT)
		test_fatal("dst port has changed");

	test_finish();
}

PKTGEN("tc", "03_from_overlay_ack")
int from_overlay_ack_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_overlay(ctx, false, true);
}

SETUP("tc", "03_from_overlay_ack")
int from_overlay_ack_setup(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, &entry_call_map, FROM_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "03_from_overlay_ack")
int from_overlay_ack_check(struct __ctx_buff *ctx)
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

	if (memcmp(l2->h_source, (__u8 *)BACKEND_ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("src MAC is not the backend router MAC")

	if (memcmp(l2->h_dest, (__u8 *)BACKEND_MAC, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the backend MAC")

	if (l3->saddr != CLIENT_NODE_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP has changed");

	if (l4->source != CLIENT_INTER_CLUSTER_SNAT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port has changed");

	meta = ctx_load_meta(ctx, CB_IFINDEX);
	if (meta != BACKEND_IFINDEX)
		test_fatal("skb->cb[CB_IFINDEX] should be %d, got %d", BACKEND_IFINDEX, meta);

	meta = ctx_load_meta(ctx, CB_SRC_LABEL);
	if (meta != CLIENT_IDENTITY)
		test_fatal("skb->cb[CB_SRC_LABEL] should be %d, got %d", CLIENT_IDENTITY, meta);

	meta = ctx_load_meta(ctx, CB_FROM_TUNNEL);
	if (meta != 1)
		test_fatal("skb->cb[CB_FROM_TUNNEL] should be 1, got %d", meta);

	meta = ctx_load_meta(ctx, CB_FROM_HOST);
	if (meta != 0)
		test_fatal("skb->cb[CB_FROM_HOST] should be 0, got %d", meta);

	meta = ctx_load_meta(ctx, CB_CLUSTER_ID_INGRESS);
	if (meta != 0)
		test_fatal("skb->cb[CB_CLUSTER_ID_INGRESS] should be 0, got %d", meta);

	test_finish();
}
