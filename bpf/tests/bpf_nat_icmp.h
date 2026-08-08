/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4			1
#define ENABLE_NODEPORT			1
#define ENABLE_MASQUERADE_IPV4		1

#define EXT_IP  v4_ext_one
#define NODE_IP v4_node_one
#define POD_IP  v4_pod_one

#define POD_SEC_IDENTITY 112233

#include "lib/bpf_host.h"

#include <bpf/config/node.h>

#define DEBUG

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, { .be32 = NODE_IP })

#include "nodeport_defaults.h"
#include "bpf_nat_tuples.h"
#include "scapy.h"

#include "lib/endpoint.h"

const __u8 icmp4_err_revnat_egress_tcp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_egress_tcp)
};
const __u8 icmp4_err_revnat_full_tcp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_full_tcp)
};
const __u8 icmp4_err_revnat_full_tcp_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_full_tcp_after)
};
const __u8 icmp4_err_revnat_min_tcp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_min_tcp)
};
const __u8 icmp4_err_revnat_min_tcp_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_min_tcp_after)
};

/*
 * Push an egressing pod->external TCP packet through to-netdev and let the
 * datapath set up nat mappings due to node ip masquerading. 
 * Exploit the fact that tests are run in alphabetical order to ensure this
 * happens before we check the icmp pmtud revSNAT mappings.
 */
PKTGEN(PROG_TYPE, "00_snat_v4_tcp_egress")
int snat_v4_egress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_revnat_egress_tcp,
			sizeof(icmp4_err_revnat_egress_tcp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "00_snat_v4_tcp_egress")
int snat_v4_egress_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(POD_IP, 0, 0, 0, POD_SEC_IDENTITY,
			      0, (__u8 *)mac_one, (__u8 *)mac_one);

	return netdev_send_packet(ctx);
}

/*
 * Add a check prior to moving onto actual icmp pmtu icmp testing
 * to quickly fail if priror steps did not setup expected nat state
 */
CHECK(PROG_TYPE, "00_snat_v4_tcp_egress")
int snat_v4_egress_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = EXT_IP,
		.dport   = tcp_src_two,
		.sport   = tcp_dst_one,
		.nexthdr = IPPROTO_TCP,
		.flags   = NAT_DIR_INGRESS,
	};
	struct ipv4_nat_entry *entry = map_lookup_elem(&cilium_snat_v4_external,
						      &tuple);

	if (!entry)
		test_fatal("no revSNAT entry created by to-netdev");
	if (entry->to_daddr != POD_IP)
		test_fatal("revSNAT entry to_daddr is not the pod IP");
	if (entry->to_dport != tcp_src_two)
		test_fatal("revSNAT entry to_dport is not the pod source port");

	test_finish();
}

/*
 * Full inner TCP header + data payload variant.
 */
PKTGEN(PROG_TYPE, "snat_v4_tcp_pmtu")
int snat_v4_pmtu_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_revnat_full_tcp,
			sizeof(icmp4_err_revnat_full_tcp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_tcp_pmtu")
int snat_v4_pmtu_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_tcp_pmtu")
int snat_v4_pmtu_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_tcp_pmtu", "Ether", ctx, sizeof(__u32),
			   icmp4_err_revnat_full_tcp_after,
			   sizeof(icmp4_err_revnat_full_tcp_after));
	test_finish();

	return 0;
}

/*
 * Minimal inner TCP (8 bytes: sport + dport + seq) variant.
 * Tests that revSNAT handles the RFC 792 minimum embedded header correctly.
 */
PKTGEN(PROG_TYPE, "snat_v4_tcp_pmtu_min_hdr")
int snat_v4_pmtu_min_hdr_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_revnat_min_tcp,
			sizeof(icmp4_err_revnat_min_tcp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_tcp_pmtu_min_hdr")
int snat_v4_pmtu_min_hdr_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_tcp_pmtu_min_hdr")
int snat_v4_pmtu_min_hdr_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_tcp_pmtu_min_hdr", "Ether", ctx, sizeof(__u32),
			   icmp4_err_revnat_min_tcp_after,
			   sizeof(icmp4_err_revnat_min_tcp_after));
	test_finish();

	return 0;
}
