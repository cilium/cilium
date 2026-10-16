/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4			1
#define ENABLE_NODEPORT			1

#define EXT_IP  v4_ext_one
#define NODE_IP v4_node_one
#define POD_IP  v4_pod_one

#define POD_SEC_IDENTITY 112233

#include "lib/bpf_host.h"

#include <bpf/config/node.h>


#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, { .be32 = NODE_IP })
ASSIGN_CONFIG(bool, enable_masquerade_ipv4, true)

#include "nodeport_defaults.h"
#include "bpf_nat_tuples.h"
#include "scapy.h"

#include "lib/endpoint.h"

const __u8 icmp4_err_revnat_egress_tcp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_egress_tcp)
};
const __u8 icmp4_err_revnat_egress_post_tcp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_egress_post_tcp)
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

const __u8 icmp4_tcp_ingress[] = {
	SCAPY_BUF_BYTES(icmp4_tcp_ingress)
};

const __u8 icmp4_tcp_ingress_post_revnat[] = {
	SCAPY_BUF_BYTES(icmp4_tcp_ingress_post_revnat)
};

const __u8 icmp4_err_nat_full_tcp[] = {
	SCAPY_BUF_BYTES(icmp4_err_nat_full_tcp)
};

const __u8 icmp4_err_nat_full_tcp_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_nat_full_tcp_after)
};

const __u8 icmp4_err_revnat_egress_icmp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_egress_icmp)
};

const __u8 icmp4_err_revnat_egress_post_icmp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_egress_post_icmp)
};

const __u8 icmp4_err_revnat_egress_sctp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_egress_sctp)
};

const __u8 icmp4_err_revnat_egress_post_sctp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_egress_post_sctp)
};

const __u8 icmp4_err_revnat_full_icmp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_full_icmp)
};

const __u8 icmp4_err_revnat_full_icmp_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_full_icmp_after)
};

const __u8 icmp4_err_revnat_full_sctp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_full_sctp)
};

const __u8 icmp4_err_revnat_full_sctp_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_full_sctp_after)
};

const __u8 icmp4_err_nat_full_icmp[] = {
	SCAPY_BUF_BYTES(icmp4_err_nat_full_icmp)
};

const __u8 icmp4_err_nat_full_icmp_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_nat_full_icmp_after)
};

const __u8 icmp4_err_nat_full_sctp[] = {
	SCAPY_BUF_BYTES(icmp4_err_nat_full_sctp)
};

const __u8 icmp4_err_nat_full_sctp_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_nat_full_sctp_after)
};

const __u8 icmp4_err_nat_id_icmp[] = {
	SCAPY_BUF_BYTES(icmp4_err_nat_id_icmp)
};

const __u8 icmp4_err_nat_id_icmp_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_nat_id_icmp_after)
};

const __u8 icmp4_err_revnat_egress_udp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_egress_udp)
};

const __u8 icmp4_err_revnat_egress_post_udp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_egress_post_udp)
};

const __u8 icmp4_err_revnat_egress_udp_zerocsum[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_egress_udp_zerocsum)
};

const __u8 icmp4_err_revnat_egress_post_udp_zerocsum[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_egress_post_udp_zerocsum)
};

const __u8 icmp4_err_revnat_full_udp[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_full_udp)
};

const __u8 icmp4_err_revnat_full_udp_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_full_udp_after)
};

const __u8 icmp4_err_revnat_full_udp_zerocsum[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_full_udp_zerocsum)
};

const __u8 icmp4_err_revnat_full_udp_zerocsum_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_revnat_full_udp_zerocsum_after)
};

const __u8 icmp4_udp_ingress[] = {
	SCAPY_BUF_BYTES(icmp4_udp_ingress)
};

const __u8 icmp4_udp_ingress_post_revnat[] = {
	SCAPY_BUF_BYTES(icmp4_udp_ingress_post_revnat)
};

const __u8 icmp4_err_nat_full_udp[] = {
	SCAPY_BUF_BYTES(icmp4_err_nat_full_udp)
};

const __u8 icmp4_err_nat_full_udp_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_nat_full_udp_after)
};

const __u8 icmp4_err_nat_full_udp_zerocsum[] = {
	SCAPY_BUF_BYTES(icmp4_err_nat_full_udp_zerocsum)
};

const __u8 icmp4_err_nat_full_udp_zerocsum_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_nat_full_udp_zerocsum_after)
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
int snat_v4_egress_check(const struct __ctx_buff *ctx)
{
	test_init();

	ASSERT_CTX_BUF_OFF("snat_v4_egress", "Ether", ctx, sizeof(__u32),
			   icmp4_err_revnat_egress_post_tcp,
			   sizeof(icmp4_err_revnat_egress_post_tcp));

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

/*
 * Receive a packet and forward it to the pod. The pod rejects it, sends an ICMP error,
 * ICMP error is fully NATed on the way out.
 */
PKTGEN(PROG_TYPE, "snat_v4_tcp_unreach_1")
int snat_v4_tcp_unreach_1_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_tcp_ingress,
			sizeof(icmp4_tcp_ingress));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_tcp_unreach_1")
int snat_v4_tcp_unreach_1_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_tcp_unreach_1")
int snat_v4_tcp_unreach_1_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_tcp_unreach_1", "Ether", ctx, sizeof(__u32),
			   icmp4_tcp_ingress_post_revnat,
			   sizeof(icmp4_tcp_ingress_post_revnat));
	test_finish();

	return 0;
}

PKTGEN(PROG_TYPE, "snat_v4_tcp_unreach_2")
int snat_v4_tcp_unreach_2_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_nat_full_tcp,
			sizeof(icmp4_err_nat_full_tcp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_tcp_unreach_2")
int snat_v4_tcp_unreach_2_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_tcp_unreach_2")
int snat_v4_tcp_unreach_2_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_tcp_unreach_2", "Ether", ctx, sizeof(__u32),
			   icmp4_err_nat_full_tcp_after,
			   sizeof(icmp4_err_nat_full_tcp_after));
	test_finish();

	return 0;
}

/* Inner ICMP tests. */

PKTGEN(PROG_TYPE, "00_snat_v4_icmp_egress")
int snat_v4_icmp_egress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_revnat_egress_icmp,
			sizeof(icmp4_err_revnat_egress_icmp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "00_snat_v4_icmp_egress")
int snat_v4_icmp_egress_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(POD_IP, 0, 0, 0, POD_SEC_IDENTITY,
			      0, (__u8 *)mac_one, (__u8 *)mac_one);

	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "00_snat_v4_icmp_egress")
int snat_v4_icmp_egress_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_icmp_egress", "Ether", ctx, sizeof(__u32),
			   icmp4_err_revnat_egress_post_icmp,
			   sizeof(icmp4_err_revnat_egress_post_icmp));
	test_finish();

	return 0;
}

PKTGEN(PROG_TYPE, "snat_v4_icmp_pmtu")
int snat_v4_icmp_pmtu_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_revnat_full_icmp,
			sizeof(icmp4_err_revnat_full_icmp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_icmp_pmtu")
int snat_v4_icmp_pmtu_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_icmp_pmtu")
int snat_v4_icmp_pmtu_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_icmp_pmtu", "Ether", ctx, sizeof(__u32),
			   icmp4_err_revnat_full_icmp_after,
			   sizeof(icmp4_err_revnat_full_icmp_after));
	test_finish();

	return 0;
}

PKTGEN(PROG_TYPE, "snat_v4_icmp_unreach_1")
int snat_v4_icmp_unreach_1_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_nat_full_icmp,
			sizeof(icmp4_err_nat_full_icmp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_icmp_unreach_1")
int snat_v4_icmp_unreach_1_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_icmp_unreach_1")
int snat_v4_icmp_unreach_1_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_icmp_unreach_1", "Ether", ctx, sizeof(__u32),
			   icmp4_err_nat_full_icmp_after,
			   sizeof(icmp4_err_nat_full_icmp_after));
	test_finish();

	return 0;
}

PKTGEN(PROG_TYPE, "snat_v4_icmp_unreach_id")
int snat_v4_icmp_unreach_id_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_nat_id_icmp,
			sizeof(icmp4_err_nat_id_icmp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_icmp_unreach_id")
int snat_v4_icmp_unreach_id_setup(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {
		.saddr   = POD_IP,
		.daddr   = EXT_IP,
		.sport   = bpf_htons(789),
		.dport   = 0,
		.nexthdr = IPPROTO_ICMP,
	};
	struct ipv4_nat_entry entry = {
		.to_saddr = NODE_IP,
		.to_sport = bpf_htons(456),
	};

	map_update_elem(&cilium_snat_v4_external, &tuple, &entry, BPF_ANY);
	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_icmp_unreach_id")
int snat_v4_icmp_unreach_id_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_icmp_unreach_id", "Ether", ctx, sizeof(__u32),
			   icmp4_err_nat_id_icmp_after,
			   sizeof(icmp4_err_nat_id_icmp_after));
	test_finish();
	return 0;
}

/* Inner SCTP tests. */

PKTGEN(PROG_TYPE, "00_snat_v4_sctp_egress")
int snat_v4_sctp_egress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_revnat_egress_sctp,
			sizeof(icmp4_err_revnat_egress_sctp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "00_snat_v4_sctp_egress")
int snat_v4_sctp_egress_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(POD_IP, 0, 0, 0, POD_SEC_IDENTITY,
			      0, (__u8 *)mac_one, (__u8 *)mac_one);

	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "00_snat_v4_sctp_egress")
int snat_v4_sctp_egress_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_sctp_egress", "Ether", ctx, sizeof(__u32),
			   icmp4_err_revnat_egress_post_sctp,
			   sizeof(icmp4_err_revnat_egress_post_sctp));
	test_finish();

	return 0;
}

PKTGEN(PROG_TYPE, "snat_v4_sctp_pmtu")
int snat_v4_sctp_pmtu_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_revnat_full_sctp,
			sizeof(icmp4_err_revnat_full_sctp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_sctp_pmtu")
int snat_v4_sctp_pmtu_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_sctp_pmtu")
int snat_v4_sctp_pmtu_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_sctp_pmtu", "Ether", ctx, sizeof(__u32),
			   icmp4_err_revnat_full_sctp_after,
			   sizeof(icmp4_err_revnat_full_sctp_after));
	test_finish();

	return 0;
}

PKTGEN(PROG_TYPE, "snat_v4_sctp_unreach_1")
int snat_v4_sctp_unreach_1_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_nat_full_sctp,
			sizeof(icmp4_err_nat_full_sctp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_sctp_unreach_1")
int snat_v4_sctp_unreach_1_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_sctp_unreach_1")
int snat_v4_sctp_unreach_1_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_sctp_unreach_1", "Ether", ctx, sizeof(__u32),
			   icmp4_err_nat_full_sctp_after,
			   sizeof(icmp4_err_nat_full_sctp_after));
	test_finish();

	return 0;
}

/* Inner UDP tests. */

/*
 * Push an egressing pod->external UDP packet through to-netdev and let the
 * datapath set up the nat mapping due to node ip masquerading.
 */
PKTGEN(PROG_TYPE, "00_snat_v4_udp_egress")
int snat_v4_udp_egress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_revnat_egress_udp,
			sizeof(icmp4_err_revnat_egress_udp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "00_snat_v4_udp_egress")
int snat_v4_udp_egress_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(POD_IP, 0, 0, 0, POD_SEC_IDENTITY,
			      0, (__u8 *)mac_one, (__u8 *)mac_one);

	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "00_snat_v4_udp_egress")
int snat_v4_udp_egress_check(const struct __ctx_buff *ctx)
{
	test_init();

	ASSERT_CTX_BUF_OFF("snat_v4_udp_egress", "Ether", ctx, sizeof(__u32),
			   icmp4_err_revnat_egress_post_udp,
			   sizeof(icmp4_err_revnat_egress_post_udp));

	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = EXT_IP,
		.dport   = tcp_src_two,
		.sport   = tcp_dst_one,
		.nexthdr = IPPROTO_UDP,
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
 * Same as above, but with a zero UDP checksum. Masquerading must not
 * compute a checksum for a packet that never had one.
 */
PKTGEN(PROG_TYPE, "00_snat_v4_udp_egress_zerocsum")
int snat_v4_udp_egress_zerocsum_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_revnat_egress_udp_zerocsum,
			sizeof(icmp4_err_revnat_egress_udp_zerocsum));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "00_snat_v4_udp_egress_zerocsum")
int snat_v4_udp_egress_zerocsum_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(POD_IP, 0, 0, 0, POD_SEC_IDENTITY,
			      0, (__u8 *)mac_one, (__u8 *)mac_one);

	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "00_snat_v4_udp_egress_zerocsum")
int snat_v4_udp_egress_zerocsum_check(const struct __ctx_buff *ctx)
{
	test_init();

	ASSERT_CTX_BUF_OFF("snat_v4_udp_egress_zerocsum", "Ether", ctx, sizeof(__u32),
			   icmp4_err_revnat_egress_post_udp_zerocsum,
			   sizeof(icmp4_err_revnat_egress_post_udp_zerocsum));

	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = EXT_IP,
		.dport   = tcp_src_three,
		.sport   = tcp_dst_two,
		.nexthdr = IPPROTO_UDP,
		.flags   = NAT_DIR_INGRESS,
	};
	struct ipv4_nat_entry *entry = map_lookup_elem(&cilium_snat_v4_external,
						      &tuple);

	if (!entry)
		test_fatal("no revSNAT entry created by to-netdev");
	if (entry->to_daddr != POD_IP)
		test_fatal("revSNAT entry to_daddr is not the pod IP");
	if (entry->to_dport != tcp_src_three)
		test_fatal("revSNAT entry to_dport is not the pod source port");

	test_finish();
}

/*
 * Full inner UDP header + data payload variant. Ingress/revNAT: the inner
 * UDP checksum is updated for the pseudo-header address change.
 */
PKTGEN(PROG_TYPE, "snat_v4_udp_pmtu")
int snat_v4_udp_pmtu_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_revnat_full_udp,
			sizeof(icmp4_err_revnat_full_udp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_udp_pmtu")
int snat_v4_udp_pmtu_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_udp_pmtu")
int snat_v4_udp_pmtu_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_udp_pmtu", "Ether", ctx, sizeof(__u32),
			   icmp4_err_revnat_full_udp_after,
			   sizeof(icmp4_err_revnat_full_udp_after));
	test_finish();

	return 0;
}

/*
 * Zero-csum variant: the inner UDP checksum must remain zero after revSNAT.
 * The outer ICMP checksum is unchanged by the inner rewrite: the inner IP
 * checksum update cancels the address change and the UDP checksum does not
 * contribute.
 */
PKTGEN(PROG_TYPE, "snat_v4_udp_pmtu_zerocsum")
int snat_v4_udp_pmtu_zerocsum_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_revnat_full_udp_zerocsum,
			sizeof(icmp4_err_revnat_full_udp_zerocsum));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_udp_pmtu_zerocsum")
int snat_v4_udp_pmtu_zerocsum_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_udp_pmtu_zerocsum")
int snat_v4_udp_pmtu_zerocsum_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_udp_pmtu_zerocsum", "Ether", ctx, sizeof(__u32),
			   icmp4_err_revnat_full_udp_zerocsum_after,
			   sizeof(icmp4_err_revnat_full_udp_zerocsum_after));
	test_finish();

	return 0;
}

/*
 * Receive a UDP packet from the external peer and forward it to the pod.
 * The pod rejects it and sends an ICMP error, which is fully NATed on the
 * way out (see snat_v4_udp_unreach_2 below).
 */
PKTGEN(PROG_TYPE, "snat_v4_udp_unreach_1")
int snat_v4_udp_unreach_1_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_udp_ingress,
			sizeof(icmp4_udp_ingress));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_udp_unreach_1")
int snat_v4_udp_unreach_1_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_udp_unreach_1")
int snat_v4_udp_unreach_1_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_udp_unreach_1", "Ether", ctx, sizeof(__u32),
			   icmp4_udp_ingress_post_revnat,
			   sizeof(icmp4_udp_ingress_post_revnat));
	test_finish();

	return 0;
}

/*
 * The pod's ICMP error quoting the packet as the pod saw it. On the way
 * out, SNAT rewrites the outer saddr and the inner daddr to the node IP
 * and updates the inner UDP checksum.
 *
 * The SNAT mapping for the quoted flow (pod:33440 -> ext:22331) was
 * established by 00_snat_v4_udp_egress above: datapath maps persist
 * across tests within a program run, and the 00_ prefix makes the
 * state-establishing tests run first.
 */
PKTGEN(PROG_TYPE, "snat_v4_udp_unreach_2")
int snat_v4_udp_unreach_2_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_nat_full_udp,
			sizeof(icmp4_err_nat_full_udp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_udp_unreach_2")
int snat_v4_udp_unreach_2_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_udp_unreach_2")
int snat_v4_udp_unreach_2_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_udp_unreach_2", "Ether", ctx, sizeof(__u32),
			   icmp4_err_nat_full_udp_after,
			   sizeof(icmp4_err_nat_full_udp_after));
	test_finish();

	return 0;
}

/*
 * Zero-csum variant of the unreach flow: the inner UDP checksum must
 * remain zero through SNAT. The SNAT mapping for the quoted flow
 * (pod:44550 -> ext:33441) was established by
 * 00_snat_v4_udp_egress_zerocsum above.
 */
PKTGEN(PROG_TYPE, "snat_v4_udp_unreach_zerocsum_2")
int snat_v4_udp_unreach_zerocsum_2_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_nat_full_udp_zerocsum,
			sizeof(icmp4_err_nat_full_udp_zerocsum));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP(PROG_TYPE, "snat_v4_udp_unreach_zerocsum_2")
int snat_v4_udp_unreach_zerocsum_2_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "snat_v4_udp_unreach_zerocsum_2")
int snat_v4_udp_unreach_zerocsum_2_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_udp_unreach_zerocsum_2", "Ether", ctx, sizeof(__u32),
			   icmp4_err_nat_full_udp_zerocsum_after,
			   sizeof(icmp4_err_nat_full_udp_zerocsum_after));
	test_finish();

	return 0;
}

