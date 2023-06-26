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
#define ENCAP_IFINDEX		42

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)
#define CLIENT_NODE_IP		v4_node_two

#define EXTERNAL_SVC_IP		v4_ext_one
#define EXTERNAL_SVC_PORT	__bpf_htons(1234)

#define NODE_IP			v4_node_one

#define EGRESS_IP		IPV4(1, 2, 3, 4)

#define SECCTX_FROM_IPCACHE 1

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *ext_svc_mac = mac_two;

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused);

#include "bpf_host.c"

#include "lib/egressgw.h"

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if (ifindex == ENCAP_IFINDEX)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_DROP;
}

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

static __always_inline int egressgw_snat_pktgen(struct __ctx_buff *ctx,
						struct egressgw_test_ctx test_ctx)
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

	if (test_ctx.reply)
		ethhdr__set_macs(l2, (__u8 *)ext_svc_mac, (__u8 *)client_mac);
	else
		ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)ext_svc_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	if (test_ctx.reply) {
		l3->saddr = EXTERNAL_SVC_IP;
		l3->daddr = EGRESS_IP;
	} else {
		l3->saddr = CLIENT_IP;
		l3->daddr = EXTERNAL_SVC_IP;
	}

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	if (test_ctx.reply) {
		/* Get the destination port from the NAT entry. */
		struct ipv4_ct_tuple tuple = {
			.saddr   = CLIENT_IP,
			.daddr   = EXTERNAL_SVC_IP,
			.dport   = EXTERNAL_SVC_PORT,
			.sport   = client_port(test_ctx.test),
			.nexthdr = IPPROTO_TCP,
		};
		struct ipv4_nat_entry *nat_entry = __snat_lookup(&SNAT_MAPPING_IPV4, &tuple);

		if (!nat_entry)
			return TEST_ERROR;
		l4->source = EXTERNAL_SVC_PORT;
		l4->dest = nat_entry->to_sport;
	} else {
		l4->source = client_port(test_ctx.test);
		l4->dest = EXTERNAL_SVC_PORT;
	}

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

static __always_inline int egressgw_snat_check(const struct __ctx_buff *ctx,
					       struct egressgw_test_ctx test_ctx)
{
	void *data, *data_end;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	assert(*(__u32 *)data == test_ctx.status_code);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (test_ctx.reply) {
		if (memcmp(l2->h_source, (__u8 *)ext_svc_mac, ETH_ALEN) != 0)
			test_fatal("src MAC is not the external svc MAC")

		if (memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) != 0)
			test_fatal("dst MAC is not the client MAC")

		if (l3->saddr != EXTERNAL_SVC_IP)
			test_fatal("src IP has changed");

		if (l3->daddr != CLIENT_IP)
			test_fatal("dst IP hasn't been revSNATed to client IP");
	} else {
		if (memcmp(l2->h_source, (__u8 *)client_mac, ETH_ALEN) != 0)
			test_fatal("src MAC is not the client MAC")

		if (memcmp(l2->h_dest, (__u8 *)ext_svc_mac, ETH_ALEN) != 0)
			test_fatal("dst MAC is not the external svc MAC")

		if (l3->saddr != EGRESS_IP)
			test_fatal("src IP hasn't been NATed to egress gateway IP");

		if (l3->daddr != EXTERNAL_SVC_IP)
			test_fatal("dst IP has changed");
	}

	/* Lookup the SNAT mapping for the original packet to determine the new source port */
	struct ipv4_ct_tuple tuple = {
		.daddr   = CLIENT_IP,
		.saddr   = EXTERNAL_SVC_IP,
		.dport   = EXTERNAL_SVC_PORT,
		.sport   = client_port(test_ctx.test),
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	if (ct_entry->tx_packets != test_ctx.tx_packets)
		test_fatal("bad TX packet count (expected %u, actual %u)",
			   test_ctx.tx_packets, ct_entry->tx_packets)
	if (ct_entry->rx_packets != test_ctx.rx_packets)
		test_fatal("bad RX packet count (expected %u, actual %u)",
			   test_ctx.rx_packets, ct_entry->rx_packets)

	tuple.saddr = CLIENT_IP;
	tuple.daddr = EXTERNAL_SVC_IP;

	struct ipv4_nat_entry *nat_entry = __snat_lookup(&SNAT_MAPPING_IPV4, &tuple);

	if (!nat_entry)
		test_fatal("could not find a NAT entry for the packet");

	if (test_ctx.reply) {
		if (l4->source != EXTERNAL_SVC_PORT)
			test_fatal("src port has changed");

		if (l4->dest != client_port(test_ctx.test))
			test_fatal("dst TCP port hasn't been revSNATed to client port");
	} else {
		if (l4->source != nat_entry->to_sport)
			test_fatal("src TCP port hasn't been NATed to egress gateway port");

		if (l4->dest != EXTERNAL_SVC_PORT)
			test_fatal("dst port has changed");
	}

	test_finish();
}

/* Test that a packet matching an egress gateway policy on the to-netdev program
 * gets correctly SNATed with the egress IP of the policy.
 */
PKTGEN("tc", "tc_egressgw_snat1")
int egressgw_snat1_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_snat_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT1,
		});
}

SETUP("tc", "tc_egressgw_snat1")
int egressgw_snat1_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, NODE_IP, EGRESS_IP);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_snat1")
int egressgw_snat1_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT1,
			.tx_packets = 1,
			.rx_packets = 0,
			.status_code = CTX_ACT_OK
		});
}

/* Test that a packet matching an egress gateway policy on the from-netdev program
 * gets correctly revSNATed and connection tracked.
 */
PKTGEN("tc", "tc_egressgw_snat1_2_reply")
int egressgw_snat1_2_reply_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_snat_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT1,
			.reply = true,
		});
}

SETUP("tc", "tc_egressgw_snat1_2_reply")
int egressgw_snat1_2_reply_setup(struct __ctx_buff *ctx)
{
	/* install ipcache entry for the CLIENT_IP: */
	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = CLIENT_IP,
	};
	struct remote_endpoint_info cache_value = {
		.tunnel_endpoint = CLIENT_NODE_IP,
	};
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_snat1_2_reply")
int egressgw_snat1_2_reply_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT1,
			.reply = true,
			.tx_packets = 1,
			.rx_packets = 1,
			.status_code = CTX_ACT_REDIRECT,
		});
}

PKTGEN("tc", "tc_egressgw_snat2")
int egressgw_snat2_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_snat_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT2,
		});
}

SETUP("tc", "tc_egressgw_snat2")
int egressgw_snat2_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_snat2")
int egressgw_snat2_check(struct __ctx_buff *ctx)
{
	int ret = egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT2,
			.tx_packets = 1,
			.rx_packets = 0,
			.status_code = CTX_ACT_OK
		});

	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0Xffffff, 24);

	return ret;
}
