// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_SCTP
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_MASQUERADE_IPV6

#include "bpf_host.c"

#define DEBUG

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

#include "node_config.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"

// Need to mirror v6_{pod,node}_{one,two} value addresses.
#define v6_pod_one_addr {0xfd, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
#define v6_pod_two_addr {0xfd, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
#define v6_node_one_addr {0xfd, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

#define NODE_ONE { .addr = v6_node_one_addr }
#define EXT_IP { .addr = v6_ext_node_one_addr }
#define POD_IP { .addr = v6_pod_one_addr }

#define FROM_NETDEV	0
#define TO_NETDEV	1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
		[TO_NETDEV] = &cil_to_netdev,
	},
};

/*
 * Input packet represents a device sending a PKT_TOO_BIG response ICMPv6
 * message due to a MTU pathing issue following a TCP being sent to a l4
 * address tuple.
 *
 * ┌────────────────────────────────┐
 * │  L2 Header                     │
 * ├────────────────────────────────┤
 * │  IPV6 Header:                  │
 * │    saddr: Remote Endpoint IP   │
 * │    daddr: Cilium Node IP       │
 * ├────────────────────────────────┤
 * │  ICMPv6 Header:                │
 * │    type: PKT_TOO_BIG (2)       │
 * ├────────────────────────────────┤
 * │  IPV6 Header (Inner):          │
 * │    saddr: Cilium Node IP       │
 * │    daddr: Remote Endpoint IP   │
 * ├────────────────────────────────┤
 * │  TCP Header:                   │
 * │  ...                           │
 * └────────────────────────────────┘
 *
 * Following SNAT6, it should be remapped as follows:
 *
 * ┌────────────────────────────────┐
 * │  L2 Header                     │
 * ├────────────────────────────────┤
 * │  IPV6 Header:                  │
 * │    saddr: Cilium Node IP       │
 * │    daddr: Pod Endpoint IP      │
 * ├────────────────────────────────┤
 * │  ICMPv6 Header:                │
 * │    type: PKT_TOO_BIG (2)       │
 * ├────────────────────────────────┤
 * │  IPV6 Header (Inner):          │
 * │    saddr: Cilium Node IP       │
 * │    daddr: Remote Endpoint IP   │
 * ├────────────────────────────────┤
 * │  TCP Header:                   │
 * │  ...                           │
 * └────────────────────────────────┘
 *
 * Ref: https://datatracker.ietf.org/doc/html/rfc4443#section-3.2
 */
__always_inline int gen_pmtu_pkt(struct pktgen *builder, int l4_type)
{
	struct ethhdr *l2;
	struct ipv6hdr *outer_l3;
	struct ipv6hdr *inner_l3;
	struct icmp6hdr *l4;
	struct tcphdr *inner_l4;
	struct udphdr *inner_l4_udp = NULL; /* compiler complains if this isn't init to null? */
	struct sctphdr *inner_l4_sctp;
	void *data;

	l2 = pktgen__push_ethhdr(builder);
	if (!l2)
		return TEST_FAIL;

	outer_l3 = pktgen__push_default_ipv6hdr(builder);
	if (!outer_l3)
		return TEST_FAIL;

	outer_l3->nexthdr = IPPROTO_ICMPV6;
	ipv6hdr__set_addrs(outer_l3, (__u8 *)v6_ext_node_one, (__u8 *)v6_node_one);

	l4 = pktgen__push_icmp6hdr(builder);
	if (!l4)
		return TEST_FAIL;

	l4->icmp6_type = ICMPV6_PKT_TOOBIG;

	inner_l3 = pktgen__push_default_ipv6hdr(builder);
	if (!inner_l3)
		return TEST_FAIL;

	inner_l3->nexthdr = (__u8)l4_type;
	ipv6hdr__set_addrs(inner_l3, (__u8 *)v6_node_one, (__u8 *)v6_ext_node_one);

	switch (l4_type) {
	case IPPROTO_TCP:
		inner_l4 = pktgen__push_default_tcphdr(builder);
		if (!inner_l4)
			return TEST_FAIL;
		/* original source */
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
	case IPPROTO_SCTP:
		inner_l4_sctp = pktgen__push_default_sctphdr(builder);
		if (!inner_l4_udp)
			return TEST_FAIL;
		inner_l4_sctp->dest = 1234;
		inner_l4_sctp->source = 30001;
		break;
	default:
		return TEST_FAIL;
	}

	data = pktgen__push_data(builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_FAIL;

	return TEST_PASS;
}

PKTGEN("tc", "snat_v6_tcp_pmtu")
int snat_v6_pmtu_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	gen_pmtu_pkt(&builder, IPPROTO_TCP);
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP("tc", "snat_v6_tcp_pmtu")
int snat_v6_pmtu_setup(struct __ctx_buff *ctx)
{
	int ret;
	struct ipv6_nat_entry entry = {
		.to_daddr = POD_IP,
	};
	entry.to_sport = 0;
	entry.to_dport = 20;
	struct ipv6_ct_tuple tuple = {
		.daddr   = NODE_ONE,
		.saddr   = EXT_IP,
		.dport   = 30001, /* SNAT remapped port */
		.sport   = 1234,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_IN,
	};
	ret = map_update_elem(&SNAT_MAPPING_IPV6, &tuple, &entry, BPF_ANY);
	if (ret < 0)
		return TEST_FAIL;
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_PASS;
}

CHECK("tc", "snat_v6_tcp_pmtu")
int snat_v6_pmtu_check(const struct __ctx_buff *ctx)
{
	test_init();
	struct ipv6hdr *l3;
	struct ipv6hdr *inner_l3;
	struct tcphdr *l4;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
		sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr) +
		sizeof(struct tcphdr) > data_end)
		test_fatal("status code + eth + ipv6 out of bounds");

	l3 = (struct ipv6hdr *)(data + sizeof(__u32) + sizeof(struct ethhdr));

	assert(memcmp(&l3->daddr, (void *)v6_pod_one, 16) == 0);
	assert(memcmp(&l3->saddr, (void *)v6_ext_node_one, 16) == 0);
	assert(l3->nexthdr == IPPROTO_ICMPV6);

	inner_l3 = (struct ipv6hdr *)(data + sizeof(__u32) + sizeof(struct ethhdr)
		+ sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr));
	assert(memcmp(&inner_l3->daddr, (void *)v6_ext_node_one, 16) == 0);
	assert(memcmp(&inner_l3->saddr, (void *)v6_pod_one, 16) == 0);
	l4 = (struct tcphdr *)(data + sizeof(__u32) + sizeof(struct ethhdr)
		+ sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr));
	assert(l4->dest == 1234);
	assert(l4->source == 20); /* should be remapped entry.dport value. */

	test_finish();

	return 0;
}

PKTGEN("tc", "snat_v6_udp_pmtu")
int snat_v6_pmtu_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	gen_pmtu_pkt(&builder, IPPROTO_UDP);
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP("tc", "snat_v6_udp_pmtu")
int snat_v6_pmtu_udp_setup(struct __ctx_buff *ctx)
{
	int ret;
	struct ipv6_nat_entry entry = {
		.to_daddr = POD_IP,
	};
	entry.to_sport = 0;
	entry.to_dport = 20;
	struct ipv6_ct_tuple tuple = {
		.daddr   = NODE_ONE,
		.saddr   = EXT_IP,
		.dport   = 30001, /* SNAT remapped port */
		.sport   = 1234,
		.nexthdr = IPPROTO_UDP,
		.flags = TUPLE_F_IN,
	};
	ret = map_update_elem(&SNAT_MAPPING_IPV6, &tuple, &entry, BPF_ANY);
	if (ret < 0)
		return TEST_FAIL;
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_PASS;
}

CHECK("tc", "snat_v6_udp_pmtu")
int snat_v6_pmtu_udp_check(const struct __ctx_buff *ctx)
{
	test_init();
	struct ipv6hdr *l3;
	struct ipv6hdr *inner_l3;
	struct udphdr *l4;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
		sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr) +
		sizeof(struct udphdr) > data_end)
		test_fatal("status code + eth + ipv6 out of bounds");

	l3 = (struct ipv6hdr *)(data + sizeof(__u32) + sizeof(struct ethhdr));
	assert(memcmp(&l3->daddr, (void *)v6_pod_one, 16) == 0);
	assert(memcmp(&l3->saddr, (void *)v6_ext_node_one, 16) == 0);
	assert(l3->nexthdr == IPPROTO_ICMPV6);

	inner_l3 = (struct ipv6hdr *)(data + sizeof(__u32) +
		sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
		sizeof(struct icmp6hdr));
	assert(memcmp(&inner_l3->daddr, (void *)v6_ext_node_one, 16) == 0);
	assert(memcmp(&inner_l3->saddr, (void *)v6_pod_one, 16) == 0);
	l4 = (struct udphdr *)(data + sizeof(__u32) +
		sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
		sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr));
	assert(l4->dest == 1234);
	assert(l4->source == 20); /* should be remapped entry.dport value. */

	test_finish();

	return 0;
}

