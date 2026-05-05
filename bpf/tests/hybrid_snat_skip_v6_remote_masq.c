// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/*
 * Test Matrix for hybrid SNAT skip logic with enable_remote_node_masquerade=true (IPv6):
 *
 * This file tests scenarios where NAT_NEEDED is expected by using
 * enable_remote_node_masquerade=true to override the hybrid skip logic.
 *
 * | Test Case              | src_subnet_id | dst_subnet_id | hybrid_enabled | remote_masq | Expected   |
 * |------------------------|---------------|---------------|----------------|-------------|------------|
 * | same_subnet_override   | 100           | 100           | true           | true        | NAT_NEEDED |
 * | different_subnet       | 100           | 200           | true           | true        | NAT_NEEDED |
 * | zero_subnet            | 0             | 0             | true           | true        | NAT_NEEDED |
 *
 * Note: This is a separate compilation unit from hybrid_snat_skip_v6.c because
 * ASSIGN_CONFIG can only be used once per config variable per compilation unit.
 */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENCAP_IFINDEX 1
#define TUNNEL_MODE
#include <bpf/config/global.h>
#include <bpf/config/node.h>

#define DEBUG

#define ENABLE_BPF_MASQUERADE 1
#define ENABLE_MASQUERADE_IPV6 1
#define IS_BPF_HOST 1

#include <lib/dbg.h>
#include <lib/time.h>
#include <lib/ipv6.h>

#define IPV6_MASQUERADE_ADDR { .p1 = 0x0A000001, .p2 = 0, .p3 = 0, .p4 = 0 }
#define IPV6_SRC_ADDR { .p1 = bpf_htonl(0x2001), .p2 = bpf_htonl(0x0DB8), .p3 = bpf_htonl(0x0001), .p4 = bpf_htonl(0x0001) }
#define IPV6_DST_ADDR { .p1 = bpf_htonl(0x2001), .p2 = bpf_htonl(0x0DB8), .p3 = bpf_htonl(0x0002), .p4 = bpf_htonl(0x0001) }

#include <lib/conntrack.h>
#include <lib/nat.h>

#include "lib/ipcache.h"
#include "lib/subnet.h"

ASSIGN_CONFIG(union v6addr, nat_ipv6_masquerade, IPV6_MASQUERADE_ADDR)
ASSIGN_CONFIG(bool, enable_remote_node_masquerade, true)
ASSIGN_CONFIG(bool, hybrid_routing_enabled, true)
ASSIGN_CONFIG(__u32, trace_payload_len, 128UL)
ASSIGN_CONFIG(bool, enable_extended_ip_protocols, false)

static __always_inline void
init_ipv6_tuple(struct ipv6_ct_tuple *tuple, const union v6addr *src,
		const union v6addr *dst, __u8 nexthdr, __be16 sport, __be16 dport)
{
	ipv6_addr_copy(&tuple->saddr, src);
	ipv6_addr_copy(&tuple->daddr, dst);
	tuple->nexthdr = nexthdr;
	tuple->sport = sport;
	tuple->dport = dport;
	tuple->flags = NAT_DIR_EGRESS;
}

/* Test 1: Same subnet with remote_masq=true should NOT skip SNAT */
CHECK("tc", "hybrid_snat_v6_same_subnet_override")
int test_hybrid_snat_v6_same_subnet_override(__maybe_unused struct __ctx_buff *ctx)
{
	struct ipv6_ct_tuple tuple __align_stack_8 = {};
	fraginfo_t fraginfo = 0;
	int l4_off = 0, ret;

	union v6addr src_addr = IPV6_SRC_ADDR;
	union v6addr dst_addr = IPV6_DST_ADDR;
	union v6addr masq_addr = IPV6_MASQUERADE_ADDR;

	test_init();

	subnet_v6_add_entry(&src_addr, 100);
	subnet_v6_add_entry(&dst_addr, 100);
	ipcache_v6_add_entry(&dst_addr, 0, REMOTE_NODE_ID, 0, 0);

	init_ipv6_tuple(&tuple, &src_addr, &dst_addr, IPPROTO_TCP,
			bpf_htons(12345), bpf_htons(443));

	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};
	ipv6_addr_copy(&target.addr, &masq_addr);

	ret = __snat_v6_needs_masquerade(ctx, &tuple, fraginfo, l4_off, &target);
	test_log("ret=%d src_subnet=100 dst_subnet=100 remote_masq=true", ret);
	assert(ret == NAT_NEEDED);

	test_finish();
	return 0;
}

/* Test 2: Different subnet with remote_masq=true should NOT skip SNAT */
CHECK("tc", "hybrid_snat_v6_different_subnet_override")
int test_hybrid_snat_v6_different_subnet_override(__maybe_unused struct __ctx_buff *ctx)
{
	struct ipv6_ct_tuple tuple __align_stack_8 = {};
	fraginfo_t fraginfo = 0;
	int l4_off = 0, ret;

	union v6addr src_addr = IPV6_SRC_ADDR;
	union v6addr dst_addr = IPV6_DST_ADDR;
	union v6addr masq_addr = IPV6_MASQUERADE_ADDR;

	test_init();

	subnet_v6_add_entry(&src_addr, 100);
	subnet_v6_add_entry(&dst_addr, 200);
	ipcache_v6_add_entry(&dst_addr, 0, REMOTE_NODE_ID, 0, 0);

	init_ipv6_tuple(&tuple, &src_addr, &dst_addr, IPPROTO_TCP,
			bpf_htons(12345), bpf_htons(443));

	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};
	ipv6_addr_copy(&target.addr, &masq_addr);

	ret = __snat_v6_needs_masquerade(ctx, &tuple, fraginfo, l4_off, &target);
	test_log("ret=%d src_subnet=100 dst_subnet=200 remote_masq=true", ret);
	assert(ret == NAT_NEEDED);

	test_finish();
	return 0;
}

/* Test 3: Zero subnet with remote_masq=true should NOT skip SNAT */
CHECK("tc", "hybrid_snat_v6_zero_subnet_override")
int test_hybrid_snat_v6_zero_subnet_override(__maybe_unused struct __ctx_buff *ctx)
{
	struct ipv6_ct_tuple tuple __align_stack_8 = {};
	fraginfo_t fraginfo = 0;
	int l4_off = 0, ret;

	union v6addr src_addr = IPV6_SRC_ADDR;
	union v6addr dst_addr = IPV6_DST_ADDR;
	union v6addr masq_addr = IPV6_MASQUERADE_ADDR;

	test_init();

	/* No subnet entries -> both return subnet_id=0 */
	ipcache_v6_add_entry(&dst_addr, 0, REMOTE_NODE_ID, 0, 0);

	init_ipv6_tuple(&tuple, &src_addr, &dst_addr, IPPROTO_TCP,
			bpf_htons(12345), bpf_htons(443));

	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};
	ipv6_addr_copy(&target.addr, &masq_addr);

	ret = __snat_v6_needs_masquerade(ctx, &tuple, fraginfo, l4_off, &target);
	test_log("ret=%d src_subnet=0 dst_subnet=0 remote_masq=true", ret);
	assert(ret == NAT_NEEDED);

	test_finish();
	return 0;
}