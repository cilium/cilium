// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/*
 * Test configurations
 */
#define BACKEND_MAC			mac_one
#define BACKEND_ROUTER_MAC		mac_two
#define CLIENT_IP			v4_pod_one
#define BACKEND_IP			v4_pod_two
#define CLIENT_NODE_IP			v4_ext_one
#define BACKEND_PORT			tcp_src_one
#define CLIENT_INTER_CLUSTER_SNAT_PORT	tcp_src_two
#define CLIENT_CLUSTER_ID		1
#define CLIENT_IDENTITY			(0x00000000 | (CLIENT_CLUSTER_ID << 16) | 0xff01)

/*
 * Datapath configurations
 */

/* Set dummy ifindex for tunnel device */
#define ENCAP_IFINDEX 1

/* Set the LXC source address to be the address of pod one */
#define LXC_IPV4 BACKEND_IP

/* We need this for ipcache */
#define HAVE_LPM_TRIE_MAP_TYPE

/* Overlapping PodCIDR is only supported for IPv4 for now */
#define ENABLE_IPV4

/* Overlapping PodCIDR depends on tunnel */
#define TUNNEL_MODE

/* Fully enable KPR since kubeproxy doesn't understand cluster aware addressing */
#define ENABLE_NODEPORT

/* Cluster-aware addressing is mandatory for overlapping PodCIDR support */
#define ENABLE_CLUSTER_AWARE_ADDRESSING

/* Import some default values */
#include "config_replacement.h"

/* Import map definitions and some default values */
#include "node_config.h"

/* Overwrite (local) CLUSTER_ID defined in node_config.h */
#undef CLUSTER_ID
#define CLUSTER_ID 1

/* Need to undef EVENT_SOURCE here since it is defined in
 * both of common.h and bpf_lxc.c.
 */
#undef EVENT_SOURCE

/* Include an actual datapath code */
#include <bpf_lxc.c>

/*
 * Tests
 */

#define FROM_CONTAINER 0
#define HANDLE_POLICY 1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_CONTAINER] = &cil_from_container,
		[HANDLE_POLICY] = &handle_policy,
	},
};

static __always_inline int
pktgen_to_lxc(struct __ctx_buff *ctx, bool syn, bool ack)
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

	ethhdr__set_macs(l2, (__u8 *)BACKEND_ROUTER_MAC, (__u8 *)BACKEND_MAC);

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

static __always_inline int
pktgen_from_lxc(struct __ctx_buff *ctx, bool syn, bool ack)
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

PKTGEN("tc", "01_overlay_to_lxc_syn")
int overlay_to_lxc_syn_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to_lxc(ctx, true, false);
}

SETUP("tc", "01_overlay_to_lxc_syn")
int overlay_to_lxc_syn_setup(struct __ctx_buff *ctx)
{
	/*
	 * Apply policy based on the remote "real"
	 * identity instead of remote-node identity.
	 */
	struct policy_key policy_key = {
		.sec_label = CLIENT_IDENTITY,
		.dport = BACKEND_PORT,
		.protocol = IPPROTO_TCP,
		.egress = 0,
	};

	struct policy_entry policy_value = {
		.deny = 0,
	};

	map_update_elem(&POLICY_MAP, &policy_key, &policy_value, BPF_ANY);

	/* Emulate metadata filled by ipv4_local_delivery on bpf_overlay */
	ctx_store_meta(ctx, CB_SRC_LABEL, CLIENT_IDENTITY);
	ctx_store_meta(ctx, CB_IFINDEX, 1);
	ctx_store_meta(ctx, CB_CLUSTER_ID_INGRESS, 0);
	ctx_store_meta(ctx, CB_FROM_HOST, 0);
	ctx_store_meta(ctx, CB_FROM_TUNNEL, 1);

	tail_call_static(ctx, &entry_call_map, HANDLE_POLICY);

	return TEST_ERROR;
}

CHECK("tc", "01_overlay_to_lxc_syn")
int overlay_to_lxc_syn_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct ipv4_ct_tuple tuple;
	struct ct_entry *entry;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("unexpected status code %d, want %d", *status_code, CTX_ACT_REDIRECT);

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
		test_fatal("src MAC has changed")

	if (memcmp(l2->h_dest, (__u8 *)BACKEND_MAC, ETH_ALEN) != 0)
		test_fatal("dst MAC has changed")

	if (l3->saddr != CLIENT_NODE_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP has changed");

	if (l4->source != CLIENT_INTER_CLUSTER_SNAT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port has changed");

	/* Check ingress conntrack state is in the default CT */
	tuple.daddr   = CLIENT_NODE_IP;
	tuple.saddr   = BACKEND_IP;
	tuple.dport   = BACKEND_PORT;
	tuple.sport   = CLIENT_INTER_CLUSTER_SNAT_PORT;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.flags   = TUPLE_F_IN;

	entry = map_lookup_elem(&CT_MAP_TCP4, &tuple);
	if (!entry)
		test_fatal("couldn't find ingress conntrack entry");

	if (!entry->from_tunnel)
		test_fatal("from_tunnel flag is not set on ingress conntrack entry");

	if (entry->src_sec_id != CLIENT_IDENTITY)
		test_fatal("src_security_identity is not client identity");

	test_finish();
}

PKTGEN("tc", "02_lxc_to_overlay_synack")
int lxc_to_overlay_synack_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_lxc(ctx, true, true);
}

SETUP("tc", "02_lxc_to_overlay_synack")
int lxc_to_overlay_synack_setup(struct __ctx_buff *ctx)
{
	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(V4_CACHE_KEY_LEN),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = CLIENT_NODE_IP,
	};

	struct remote_endpoint_info cache_value = {
		.sec_identity = REMOTE_NODE_ID,
	};

	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	tail_call_static(ctx, &entry_call_map, FROM_CONTAINER);

	return TEST_ERROR;
}

CHECK("tc", "02_lxc_to_overlay_synack")
int lxc_to_overlay_ack_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct ipv4_ct_tuple tuple;
	struct ct_entry *entry;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("unexpected status code %d, want %d", *status_code, CTX_ACT_REDIRECT);

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
		test_fatal("src MAC has changed");

	if (memcmp(l2->h_dest, (__u8 *)BACKEND_ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("dst MAC has changed");

	if (l3->saddr != BACKEND_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != CLIENT_NODE_IP)
		test_fatal("dst IP has changed");

	if (l4->source != BACKEND_PORT)
		test_fatal("src port has changed");

	if (l4->dest != CLIENT_INTER_CLUSTER_SNAT_PORT)
		test_fatal("dst port has changed");

	/* Make sure we hit the conntrack entry */
	tuple.saddr   = BACKEND_IP;
	tuple.daddr   = CLIENT_NODE_IP;
	tuple.dport   = BACKEND_PORT;
	tuple.sport   = CLIENT_INTER_CLUSTER_SNAT_PORT;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.flags   = TUPLE_F_IN;

	entry = map_lookup_elem(&CT_MAP_TCP4, &tuple);
	if (!entry)
		test_fatal("couldn't find egress conntrack entry");

	if (entry->tx_packets != 1)
		test_fatal("tx packet didn't hit conntrack entry");

	test_finish();
}

PKTGEN("tc", "03_overlay_to_lxc_ack")
int overlay_to_lxc_ack_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to_lxc(ctx, false, true);
}

SETUP("tc", "03_overlay_to_lxc_ack")
int overlay_to_lxc_ack_setup(struct __ctx_buff *ctx)
{
	/* Emulate metadata filled by ipv4_local_delivery on bpf_overlay */
	ctx_store_meta(ctx, CB_SRC_LABEL, CLIENT_IDENTITY);
	ctx_store_meta(ctx, CB_IFINDEX, 1);
	ctx_store_meta(ctx, CB_CLUSTER_ID_INGRESS, 0);
	ctx_store_meta(ctx, CB_FROM_HOST, 0);
	ctx_store_meta(ctx, CB_FROM_TUNNEL, 1);

	tail_call_static(ctx, &entry_call_map, HANDLE_POLICY);

	return TEST_ERROR;
}

CHECK("tc", "03_overlay_to_lxc_ack")
int overlay_to_lxc_ack_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct ipv4_ct_tuple tuple;
	struct ct_entry *entry;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("unexpected status code %d, want %d", *status_code, CTX_ACT_REDIRECT);

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
		test_fatal("src MAC has changed")

	if (memcmp(l2->h_dest, (__u8 *)BACKEND_MAC, ETH_ALEN) != 0)
		test_fatal("dst MAC has changed")

	if (l3->saddr != CLIENT_NODE_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP has changed");

	if (l4->source != CLIENT_INTER_CLUSTER_SNAT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port has changed");

	/* Make sure we hit the conntrack entry */
	tuple.daddr   = CLIENT_NODE_IP;
	tuple.saddr   = BACKEND_IP;
	tuple.dport   = BACKEND_PORT;
	tuple.sport   = CLIENT_INTER_CLUSTER_SNAT_PORT;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.flags   = TUPLE_F_IN;

	entry = map_lookup_elem(&CT_MAP_TCP4, &tuple);
	if (!entry)
		test_fatal("couldn't find ingress conntrack entry");

	if (entry->rx_packets != 2)
		test_fatal("rx packet didn't hit conntrack entry");

	test_finish();
}
