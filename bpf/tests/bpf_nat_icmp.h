/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_MASQUERADE_IPV4		1

#include "lib/bpf_host.h"

#include <bpf/config/node.h>

#define DEBUG

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

#include "nodeport_defaults.h"
#include "bpf_nat_tuples.h"
#include "scapy.h"

const __u8 icmp4_err_nodeport_revnat_full_tcp[] = {
	SCAPY_BUF_BYTES(icmp4_err_nodeport_revnat_full_tcp)
};
const __u8 icmp4_err_nodeport_revnat_full_tcp_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_nodeport_revnat_full_tcp_after)
};
const __u8 icmp4_err_nodeport_revnat_min_tcp[] = {
	SCAPY_BUF_BYTES(icmp4_err_nodeport_revnat_min_tcp)
};
const __u8 icmp4_err_nodeport_revnat_min_tcp_after[] = {
	SCAPY_BUF_BYTES(icmp4_err_nodeport_revnat_min_tcp_after)
};

#define EXT_IP  v4_ext_one
#define NODE_IP v4_node_one
#define POD_IP  v4_pod_one

static int snat_v4_insert_nodeport_nat(void)
{
	/* The revSNAT lookup key for the ICMP error path is built from the
	 * inner IP+TCP headers: saddr/daddr are swapped relative to the inner
	 * packet, and the inner sport/dport are loaded directly into
	 * tuple.dport/sport via l4_load_ports.
	 *
	 * Inner packet: saddr=node_ip, daddr=ext_ip, sport=32768, dport=22330
	 * Tuple key:    saddr=ext_ip,  daddr=node_ip, dport=32768, sport=22330
	 *               flags=NAT_DIR_INGRESS
	 */
	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = EXT_IP,
		.dport   = bpf_htons(32768), /* NODEPORT_PORT_MIN_NAT */
		.sport   = bpf_htons(22330), /* tcp_src_one */
		.nexthdr = IPPROTO_TCP,
		.flags   = NAT_DIR_INGRESS,
	};
	/* to_daddr: rewrite inner saddr (and outer daddr) to pod IP.
	 * to_dport: restore inner sport to original pre-SNAT value.
	 */
	struct ipv4_nat_entry entry = {
		.to_daddr = POD_IP,
		.to_dport = bpf_htons(22330), /* tcp_src_one */
	};

	return map_update_elem(&cilium_snat_v4_external, &tuple, &entry, BPF_ANY);
}

/*
 * Full inner TCP header + data payload variant.
 */
PKTGEN("tc", "snat_v4_tcp_pmtu")
int snat_v4_pmtu_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_nodeport_revnat_full_tcp,
			sizeof(icmp4_err_nodeport_revnat_full_tcp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP("tc", "snat_v4_tcp_pmtu")
int snat_v4_pmtu_setup(struct __ctx_buff *ctx)
{
	if (snat_v4_insert_nodeport_nat() < 0)
		return TEST_FAIL;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "snat_v4_tcp_pmtu")
int snat_v4_pmtu_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_tcp_pmtu", "Ether", ctx, sizeof(__u32),
			   icmp4_err_nodeport_revnat_full_tcp_after,
			   sizeof(icmp4_err_nodeport_revnat_full_tcp_after));
	test_finish();

	return 0;
}

/*
 * Minimal inner TCP (8 bytes: sport + dport + seq) variant.
 * Tests that revSNAT handles the RFC 792 minimum embedded header correctly.
 */
PKTGEN("tc", "snat_v4_tcp_pmtu_min_hdr")
int snat_v4_pmtu_min_hdr_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	scapy_push_data(&builder,
			icmp4_err_nodeport_revnat_min_tcp,
			sizeof(icmp4_err_nodeport_revnat_min_tcp));
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP("tc", "snat_v4_tcp_pmtu_min_hdr")
int snat_v4_pmtu_min_hdr_setup(struct __ctx_buff *ctx)
{
	if (snat_v4_insert_nodeport_nat() < 0)
		return TEST_FAIL;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "snat_v4_tcp_pmtu_min_hdr")
int snat_v4_pmtu_min_hdr_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_CTX_BUF_OFF("snat_v4_tcp_pmtu_min_hdr", "Ether", ctx, sizeof(__u32),
			   icmp4_err_nodeport_revnat_min_tcp_after,
			   sizeof(icmp4_err_nodeport_revnat_min_tcp_after));
	test_finish();

	return 0;
}
