// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"
#include "config_replacement.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT

#define TUNNEL_MODE
#define ENCAP_IFINDEX		42
#define TUNNEL_PROTOCOL		TUNNEL_PROTOCOL_GENEVE

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)
#define ENCAP_SOURCE_PORT	__bpf_htons(NAT_MIN_EGRESS)
#define IPV4_DIRECT_ROUTING	v4_node_one
#define NATIVE_DEV_IFINDEX	DIRECT_ROUTING_DEV_IFINDEX

#define REMOTE_POD_IP		v4_pod_two
#define REMOTE_POD_PORT		__bpf_htons(222)
#define REMOTE_NODE_IP		v4_node_two

#define SECCTX_FROM_IPCACHE 1

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *remote_node_mac = mac_two;

#include "bpf_host.c"

#define TO_NETDEV 0
#define FROM_NETDEV 1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_NETDEV] = &cil_to_netdev,
		[FROM_NETDEV] = &cil_from_netdev,
	},
};

/* Test that a tunnel connection is exempt from CT / SNAT tracking */
PKTGEN("tc", "nodeport_geneve_snat_host1")
int nodeport_geneve_snat_host1_pktgen(struct __ctx_buff *ctx)
{
	struct ethhdr *l2, *l2_inner;
	struct iphdr *l3, *l3_inner;
	struct genevehdr *geneve;
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)node_mac, (__u8 *)remote_node_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = IPV4_DIRECT_ROUTING;
	l3->daddr = REMOTE_NODE_IP;

	udp = pktgen__push_default_udphdr(&builder);
	if (!udp)
		return TEST_ERROR;

	udp->source = ENCAP_SOURCE_PORT;
	udp->dest = bpf_htons(TUNNEL_PORT);

	geneve = pktgen__push_default_genevehdr(&builder);
	if (!geneve)
		return TEST_ERROR;

	/* Push ethernet header */
	l2_inner = pktgen__push_ethhdr(&builder);
	if (!l2_inner)
		return TEST_ERROR;

	/* Push IPv4 header */
	l3_inner = pktgen__push_default_iphdr(&builder);
	if (!l3_inner)
		return TEST_ERROR;

	l3_inner->saddr = CLIENT_IP;
	l3_inner->daddr = REMOTE_POD_IP;

	/* can't add more layers, pkt builder exceeds program size */

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "nodeport_geneve_snat_host1")
int nodeport_geneve_snat_host1_setup(struct __ctx_buff *ctx)
{
	struct policy_key policy_key = {
		.egress = 1,
	};
	struct policy_entry policy_value = {
		.deny = 0,
	};

	/* Avoid policy drop */
	map_update_elem(&POLICY_MAP, &policy_key, &policy_value, BPF_ANY);

	struct endpoint_info ep_value = {
		.flags = ENDPOINT_F_HOST,
	};

	memcpy(&ep_value.mac, (__u8 *)node_mac, ETH_ALEN);
	memcpy(&ep_value.node_mac, (__u8 *)node_mac, ETH_ALEN);

	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = IPV4_DIRECT_ROUTING,
	};
	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	/* Mark as host-originating: */
	ctx->mark = MARK_MAGIC_HOST;

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "nodeport_geneve_snat_host1")
int nodeport_geneve_snat_host1_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *udp;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	udp = (void *)l3 + sizeof(*l3);
	if ((void *)udp + sizeof(*udp) > data_end)
		test_fatal("udp out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")

	if (memcmp(l2->h_dest, (__u8 *)remote_node_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the remote node MAC")

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 ethertype is bad");

	if (l3->saddr != IPV4_DIRECT_ROUTING)
		test_fatal("src IP has changed");

	if (l3->daddr != REMOTE_NODE_IP)
		test_fatal("dst IP has changed");

	if (udp->source != ENCAP_SOURCE_PORT)
		test_fatal("src port has changed");

	if (udp->dest != bpf_htons(TUNNEL_PORT))
		test_fatal("dst port has changed");

	struct ipv4_ct_tuple tuple = {
		.daddr   = IPV4_DIRECT_ROUTING,
		.saddr   = REMOTE_NODE_IP,
		.dport   = bpf_htons(TUNNEL_PORT),
		.sport   = ENCAP_SOURCE_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (ct_entry)
		test_fatal("found CT entry");

	tuple.saddr = IPV4_DIRECT_ROUTING;
	tuple.daddr = REMOTE_NODE_IP;

	struct ipv4_nat_entry *nat_entry = __snat_lookup(&SNAT_MAPPING_IPV4, &tuple);

	if (nat_entry)
		test_fatal("found NAT entry");

	test_finish();
}
