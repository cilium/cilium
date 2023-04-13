// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define HAVE_LPM_TRIE_MAP_TYPE
#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"
#include "config_replacement.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_EGRESS_GATEWAY
#define ENABLE_MASQUERADE
#define ENCAP_IFINDEX 0

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)

#define EXTERNAL_SVC_IP		v4_ext_one
#define EXTERNAL_SVC_PORT	__bpf_htons(1234)

#define NODE_IP			v4_node_one

#define EGRESS_IP		IPV4(1, 2, 3, 4)

#define SECCTX_FROM_IPCACHE 1

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *ext_svc_mac = mac_two;

#include "bpf_host.c"

#define TO_NETDEV 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_NETDEV] = &cil_to_netdev,
	},
};

/* Test that a packet matching an egress gateway policy on the to-netdev program
 * gets correctly SNATed with the egress IP of the policy.
 */
PKTGEN("tc", "tc_egressgw_snat")
int egressgw_snat_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)ext_svc_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = EXTERNAL_SVC_IP;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = EXTERNAL_SVC_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_egressgw_snat")
int egressgw_snat_setup(struct __ctx_buff *ctx)
{
	struct egress_gw_policy_key in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN(24), {} },
		.saddr   = CLIENT_IP,
		.daddr   = EXTERNAL_SVC_IP & 0Xffffff,
	};

	struct egress_gw_policy_entry in_val = {
		.egress_ip  = EGRESS_IP,
		.gateway_ip = NODE_IP,
	};

	map_update_elem(&EGRESS_POLICY_MAP, &in_key, &in_val, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_snat")
int egressgw_snat_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
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
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the client MAC")

	if (memcmp(l2->h_dest, (__u8 *)ext_svc_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the external svc MAC")

	if (l3->saddr != EGRESS_IP)
		test_fatal("src IP hasn't been NATed to egress gateway IP");

	if (l3->daddr != EXTERNAL_SVC_IP)
		test_fatal("dst IP has changed");

	/* Lookup the SNAT mapping for the original packet to determine the new source port */
	struct ipv4_ct_tuple tuple = {
		.daddr   = EXTERNAL_SVC_IP,
		.saddr   = CLIENT_IP,
		.dport   = EXTERNAL_SVC_PORT,
		.sport   = CLIENT_PORT,
		.nexthdr = IPPROTO_TCP,
	};

	struct ipv4_nat_entry *nat_entry = __snat_lookup(&SNAT_MAPPING_IPV4, &tuple);

	if (!nat_entry)
		test_fatal("could not find a NAT entry for the packet");

	if (l4->source != nat_entry->to_sport)
		test_fatal("src TCP port hasn't been NATed to egress gateway port");

	if (l4->dest != EXTERNAL_SVC_PORT)
		test_fatal("dst port has changed");

	test_finish();
}
