/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_MASQUERADE_IPV4		1

#include "lib/bpf_host.h"

#include <bpf/config/node.h>

#define DEBUG

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

#include "bpf_nat_tuples.h"

#include "lib/endpoint.h"

#define NODE_ONE v4_node_one
#define EXT_IP v4_ext_one
#define EXT_HOP_IP v4_ext_two
#define POD_IP v4_pod_one


__always_inline int gen_pmtu_pkt(struct pktgen *builder, __u8 l4_type)
{
	struct ethhdr *l2 = NULL;
	struct iphdr *outer_l3 = NULL;
	struct iphdr *inner_l3 = NULL;
	struct icmphdr *l4 = NULL;
	struct tcphdr *inner_l4 = NULL;
	struct udphdr *inner_l4_udp = NULL;
	void *data;

	l2 = pktgen__push_ethhdr(builder);
	if (!l2)
		return TEST_FAIL;

	outer_l3 = pktgen__push_default_iphdr(builder);
	if (!outer_l3)
		return TEST_FAIL;

	outer_l3->saddr = EXT_IP;
	outer_l3->daddr = NODE_ONE;
	outer_l3->protocol = IPPROTO_ICMP;

	l4 = pktgen__push_icmphdr(builder);
	if (!l4)
		return TEST_FAIL;

	l4->type = ICMP_DEST_UNREACH;
	l4->code = ICMP_FRAG_NEEDED;

	inner_l3 = pktgen__push_default_iphdr(builder);
	if (!inner_l3)
		return TEST_FAIL;

	/* Original packet addr tuple */
	inner_l3->saddr = NODE_ONE;
	inner_l3->daddr = EXT_IP;
	inner_l3->protocol = l4_type;

	switch (l4_type) {
	case IPPROTO_TCP:
		inner_l4 = pktgen__push_default_tcphdr(builder);
		if (!inner_l4)
			return TEST_FAIL;
		inner_l4->dest = 1234;
		inner_l4->source = 30001;
		break;
	case IPPROTO_UDP:
		inner_l4_udp = pktgen__push_default_udphdr(builder);
		if (!inner_l4_udp)
			return TEST_FAIL;
		inner_l4_udp->dest = 1234;
		inner_l4_udp->source = 30001;
		break;
	default:
		return TEST_FAIL;
	}
	data = pktgen__push_data(builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_FAIL;

	return TEST_PASS;
}

int snat_v4_insert_ct_nat(__u8 proto)
{
	struct ipv4_nat_entry entry = {
		.to_daddr = POD_IP,
	};
	entry.to_sport = 0;
	entry.to_dport = 20;
	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_ONE,
		.saddr   = EXT_IP,
		.dport   = 30001,
		.sport   = 1234,
		.nexthdr = proto,
		.flags = TUPLE_F_IN,
	};
	return map_update_elem(&cilium_snat_v4_external, &tuple, &entry, BPF_ANY);
}

__always_inline int check_pmtu_snat(const struct __ctx_buff *ctx)
{
	struct iphdr *l3;
	__u16 *sport = NULL;
	__u16 *dport = NULL;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr) +
		sizeof(struct icmphdr) + sizeof(struct iphdr) +
		sizeof(__u16) + sizeof(__u16) > data_end)
		return TEST_FAIL;

	l3 = (struct iphdr *)(data + sizeof(__u32) + sizeof(struct ethhdr));

	/* dest addr should now be pod IP following rev-snat */
	if (l3->daddr != POD_IP)
		return TEST_FAIL;

	/* source addr should just be the external endpoint IP */
	if (l3->saddr != EXT_IP)
		return TEST_FAIL;

	if (l3->protocol != IPPROTO_ICMP)
		return TEST_FAIL;

	sport = (__u16 *)(data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr) +
		sizeof(struct icmphdr) + sizeof(struct iphdr));
	dport = (__u16 *)(data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr) +
		sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(__u16));
	if (*sport != 20)
		return TEST_FAIL;
	if (*dport != 1234)
		return TEST_FAIL;

	return 0;
}

PKTGEN("tc", "nodeport_revsnat_icmp4_pmtu")
int nodeport_revsnat_icmp4_pmtu_pktgen(struct __ctx_buff *ctx)
{
	int ret;
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	ret = gen_pmtu_pkt(&builder, IPPROTO_TCP);
	pktgen__finish(&builder);
	return ret;
}

SETUP("tc", "nodeport_revsnat_icmp4_pmtu")
int nodeport_revsnat_icmp4_pmtu_setup(struct __ctx_buff *ctx)
{
	snat_v4_insert_ct_nat(IPPROTO_TCP);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "nodeport_revsnat_icmp4_pmtu")
int nodeport_revsnat_icmp4_pmtu_check(__maybe_unused const struct __ctx_buff *ctx)
{
	test_init();
	if (check_pmtu_snat(ctx) != 0)
		test_fatal("snat check failed");
	test_finish();
}

PKTGEN("tc", "nodeport_revsnat_icmp4_pmtu_udp")
int nodeport_revsnat_icmp4_pmtu_udp_pktgen(struct __ctx_buff *ctx)
{
	int ret;
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	ret = gen_pmtu_pkt(&builder, IPPROTO_UDP);
	pktgen__finish(&builder);
	return ret;
}

SETUP("tc", "nodeport_revsnat_icmp4_pmtu_udp")
int nodeport_revsnat_icmp4_pmtu_udp_setup(struct __ctx_buff *ctx)
{
	snat_v4_insert_ct_nat(IPPROTO_UDP);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "nodeport_revsnat_icmp4_pmtu_udp")
int nodeport_revsnat_icmp4_pmtu_udp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	test_init();
	if (check_pmtu_snat(ctx) != 0)
		test_fatal("snat check failed");
	test_finish();
}
