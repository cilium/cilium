/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_SCTP			1
#define ENABLE_IPV4			1
#define ENABLE_IPV6			1
#define ENABLE_NODEPORT			1
#define ENABLE_MASQUERADE_IPV6		1

#define NODE_ONE6 { .addr = v6_node_one_addr }
#define EXT_IP6 { .addr = v6_ext_node_one_addr }
#define POD_IP6 { .addr = v6_pod_one_addr }

#define POD6_SEC_IDENTITY 112244

#include <bpf/config/node.h>

#define DEBUG

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

ASSIGN_CONFIG(union v6addr, nat_ipv6_masquerade, { .addr = v6_node_one_addr })

#include "scapy.h"

#include "bpf_nat_tuples.h"

#include "lib/endpoint.h"

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
const __u8 icmp6_err_revnat_egress_tcp[] = {
	SCAPY_BUF_BYTES(icmp6_err_revnat_egress_tcp)
};

const __u8 icmp6_err_revnat_egress_post_tcp[] = {
	SCAPY_BUF_BYTES(icmp6_err_revnat_egress_post_tcp)
};

const __u8 icmp6_err_revnat_egress_udp[] = {
	SCAPY_BUF_BYTES(icmp6_err_revnat_egress_udp)
};

const __u8 icmp6_err_revnat_egress_post_udp[] = {
	SCAPY_BUF_BYTES(icmp6_err_revnat_egress_post_udp)
};

const __u8 icmp6_err_revnat_full_tcp[] = {
	SCAPY_BUF_BYTES(icmp6_err_revnat_full_tcp)
};

const __u8 icmp6_err_revnat_full_tcp_after[] = {
	SCAPY_BUF_BYTES(icmp6_err_revnat_full_tcp_after)
};

const __u8 icmp6_err_revnat_full_udp[] = {
	SCAPY_BUF_BYTES(icmp6_err_revnat_full_udp)
};

const __u8 icmp6_err_revnat_full_udp_after[] = {
	SCAPY_BUF_BYTES(icmp6_err_revnat_full_udp_after)
};

/*
 * Push an egressing pod->external TCP packet through to-netdev and let the
 * datapath set up nat mappings due to node ip masquerading.
 * Exploit the fact that tests are run in alphabetical order to ensure this
 * happens before we check the icmp pmtud revSNAT mappings.
 */
PKTGEN(PROG_TYPE, "00_snat_v6_tcp_egress")
int snat_v6_egress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp6_err_revnat_egress_tcp,
			sizeof(icmp6_err_revnat_egress_tcp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "00_snat_v6_tcp_egress")
int snat_v6_egress_setup(struct __ctx_buff *ctx)
{
	union v6addr pod_ip = POD_IP6;

	endpoint_v6_add_entry(&pod_ip, 0, 0, 0, POD6_SEC_IDENTITY,
			      (__u8 *)mac_one, (__u8 *)mac_one);

	return netdev_send_packet(ctx);
}

/*
 * Add a check prior to moving onto actual icmp pmtu icmp testing
 * to quickly fail if priror steps did not setup expected nat state
 */
CHECK(PROG_TYPE, "00_snat_v6_tcp_egress")
int snat_v6_egress_check(const struct __ctx_buff *ctx)
{
	test_init();

	ASSERT_CTX_BUF_OFF("snat_v6_egress", "Ether", ctx, sizeof(__u32),
			   icmp6_err_revnat_egress_post_tcp,
			   sizeof(icmp6_err_revnat_egress_post_tcp));

	union v6addr pod_ip = POD_IP6;
	struct ipv6_ct_tuple tuple = {
		.daddr   = NODE_ONE6,
		.saddr   = EXT_IP6,
		.dport   = tcp_src_two,
		.sport   = tcp_dst_one,
		.nexthdr = IPPROTO_TCP,
		.flags   = NAT_DIR_INGRESS,
	};
	struct ipv6_nat_entry *entry = map_lookup_elem(&cilium_snat_v6_external,
						      &tuple);

	if (!entry)
		test_fatal("no revSNAT entry created by to-netdev");
	if (!ipv6_addr_equals(&entry->to_daddr, &pod_ip))
		test_fatal("revSNAT entry to_daddr is not the pod IP");
	if (entry->to_dport != tcp_src_two)
		test_fatal("revSNAT entry to_dport is not the pod source port");

	test_finish();
}

PKTGEN(PROG_TYPE, "01_snat_v6_udp_egress")
int snat_v6_egress_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp6_err_revnat_egress_udp,
			sizeof(icmp6_err_revnat_egress_udp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "01_snat_v6_udp_egress")
int snat_v6_egress_udp_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "01_snat_v6_udp_egress")
int snat_v6_egress_udp_check(const struct __ctx_buff *ctx)
{
	test_init();

	ASSERT_CTX_BUF_OFF("snat_v6_egress_udp", "Ether", ctx, sizeof(__u32),
			   icmp6_err_revnat_egress_post_udp,
			   sizeof(icmp6_err_revnat_egress_post_udp));

	union v6addr pod_ip = POD_IP6;
	struct ipv6_ct_tuple tuple = {
		.daddr   = NODE_ONE6,
		.saddr   = EXT_IP6,
		.dport   = tcp_src_two,
		.sport   = tcp_dst_one,
		.nexthdr = IPPROTO_UDP,
		.flags   = NAT_DIR_INGRESS,
	};
	struct ipv6_nat_entry *entry = map_lookup_elem(&cilium_snat_v6_external,
						      &tuple);

	if (!entry)
		test_fatal("no revSNAT entry created by to-netdev");
	if (!ipv6_addr_equals(&entry->to_daddr, &pod_ip))
		test_fatal("revSNAT entry to_daddr is not the pod IP");
	if (entry->to_dport != tcp_src_two)
		test_fatal("revSNAT entry to_dport is not the pod source port");

	test_finish();
}

PKTGEN(PROG_TYPE, "snat_v6_tcp_pmtu")
int snat_v6_pmtu_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp6_err_revnat_full_tcp,
			sizeof(icmp6_err_revnat_full_tcp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v6_tcp_pmtu")
int snat_v6_pmtu_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v6_tcp_pmtu")
int snat_v6_pmtu_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v6_tcp_pmtu", "Ether", ctx, sizeof(__u32),
			   icmp6_err_revnat_full_tcp_after,
			   sizeof(icmp6_err_revnat_full_tcp_after));
	test_finish();

	return 0;
}

PKTGEN(PROG_TYPE, "snat_v6_udp_pmtu")
int snat_v6_pmtu_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp6_err_revnat_full_udp,
			sizeof(icmp6_err_revnat_full_udp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v6_udp_pmtu")
int snat_v6_pmtu_udp_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v6_udp_pmtu")
int snat_v6_pmtu_udp_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v6_udp_pmtu", "Ether", ctx, sizeof(__u32),
			   icmp6_err_revnat_full_udp_after,
			   sizeof(icmp6_err_revnat_full_udp_after));
	test_finish();

	return 0;
}

