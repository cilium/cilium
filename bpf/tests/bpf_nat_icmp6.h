/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_SCTP
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_MASQUERADE_IPV6		1

#include "lib/bpf_host.h"

#include <bpf/config/node.h>

#define DEBUG

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

#include <bpf/helpers.h>
#include <bpf/api.h>

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <bpf/config/node.h>

#define DEBUG

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

#include "scapy.h"

#include "bpf_nat_tuples.h"

#define NODE_ONE6 { .addr = v6_node_one_addr }
#define EXT_IP6 { .addr = v6_ext_node_one_addr }
#define POD_IP6 { .addr = v6_pod_one_addr }

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
const __u8 icmp6_err_nodeport_revnat_full_tcp[] = {
	SCAPY_BUF_BYTES(icmp6_err_nodeport_revnat_full_tcp)
};
const __u8 icmp6_err_nodeport_revnat_full_tcp_after[] = {
	SCAPY_BUF_BYTES(icmp6_err_nodeport_revnat_full_tcp_after)
};
const __u8 icmp6_err_nodeport_revnat_full_udp[] = {
	SCAPY_BUF_BYTES(icmp6_err_nodeport_revnat_full_udp)
};
const __u8 icmp6_err_nodeport_revnat_full_udp_after[] = {
	SCAPY_BUF_BYTES(icmp6_err_nodeport_revnat_full_udp_after)
};

int snat_v6_insert_ct_nat(__u8 proto)
{
	struct ipv6_nat_entry entry = {
		.to_daddr = POD_IP6,
	};
	entry.to_sport = 0;
	entry.to_dport = bpf_htons(20);
	struct ipv6_ct_tuple tuple = {
		.daddr   = NODE_ONE6,
		.saddr   = EXT_IP6,
		.dport   = bpf_htons(30001), /* SNAT remapped port */
		.sport   = bpf_htons(1234),
		.nexthdr = proto,
		.flags   = TUPLE_F_IN,
	};
	return map_update_elem(&cilium_snat_v6_external, &tuple, &entry, BPF_ANY);
}

int do_icmp6_pkt_too_big_check(const struct __ctx_buff *ctx)
{
	struct ipv6hdr *l3 = NULL;
	struct ipv6hdr *inner_l3 = NULL;
	void *l4 = NULL;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
		sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr) +
		2 * sizeof(__u16) > data_end)
		return TEST_FAIL;

	l3 = (struct ipv6hdr *)(data + sizeof(__u32) + sizeof(struct ethhdr));
	if (memcmp(&l3->daddr, (void *)v6_pod_one, 16) > 0)
		return TEST_FAIL;

	if (memcmp(&l3->saddr, (void *)v6_ext_node_one, 16) > 0)
		return TEST_FAIL;

	if (l3->nexthdr != IPPROTO_ICMPV6)
		return TEST_FAIL;

	inner_l3 = (struct ipv6hdr *)(data + sizeof(__u32) +
		sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
		sizeof(struct icmp6hdr));

	if (memcmp(&inner_l3->daddr, (void *)v6_ext_node_one, 16) > 0)
		return TEST_FAIL;

	if (memcmp(&inner_l3->saddr, (void *)v6_pod_one, 16) > 0)
		return TEST_FAIL;

	l4 = (void *)(data + sizeof(__u32) +
		sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
		sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr));
	if (*((__u16 *)l4) != bpf_htons(20))
		return TEST_FAIL;
	if (*((__u16 *)(l4 + sizeof(__u16))) != bpf_htons(1234))
		return TEST_FAIL;
	return 0;
}

PKTGEN("tc", "snat_v6_tcp_pmtu")
int snat_v6_pmtu_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp6_err_nodeport_revnat_full_tcp,
			sizeof(icmp6_err_nodeport_revnat_full_tcp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP("tc", "snat_v6_tcp_pmtu")
int snat_v6_pmtu_setup(struct __ctx_buff *ctx)
{
	int ret;

	ret = snat_v6_insert_ct_nat(IPPROTO_TCP);
	if (ret < 0)
		return TEST_FAIL;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "snat_v6_tcp_pmtu")
int snat_v6_pmtu_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v6_tcp_pmtu", "Ether", ctx, sizeof(__u32),
			   icmp6_err_nodeport_revnat_full_tcp_after,
			   sizeof(icmp6_err_nodeport_revnat_full_tcp_after));
	test_finish();

	return 0;
}

PKTGEN("tc", "snat_v6_udp_pmtu")
int snat_v6_pmtu_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp6_err_nodeport_revnat_full_udp,
			sizeof(icmp6_err_nodeport_revnat_full_udp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP("tc", "snat_v6_udp_pmtu")
int snat_v6_pmtu_udp_setup(struct __ctx_buff *ctx)
{
	int ret;

	ret = snat_v6_insert_ct_nat(IPPROTO_UDP);
	if (ret < 0)
		return TEST_FAIL;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "snat_v6_udp_pmtu")
int snat_v6_pmtu_udp_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v6_udp_pmtu", "Ether", ctx, sizeof(__u32),
			   icmp6_err_nodeport_revnat_full_udp_after,
			   sizeof(icmp6_err_nodeport_revnat_full_udp_after));
	test_finish();

	return 0;
}

