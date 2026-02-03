// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT
#include <bpf/config/global.h>
#include <bpf/config/node.h>

#define DEBUG

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

#include "bpf_nat_tuples.h"
#include "scapy.h"

/* IP addresses mapping to Scapy definitions (in host byte order):
 * v4_node_one   = "10.0.10.1"  -> IP_ENDPOINT (node/endpoint)
 * v4_pod_one    = "192.168.0.1" -> IP_HOST (pod being SNATed)
 * v4_pod_two    = "192.168.0.2" -> IP_ROUTER (pod sending ICMP error)
 */
#define IP_ENDPOINT ((10 << 24) | (0 << 16) | (10 << 8) | 1)    /* 10.0.10.1 */
#define IP_HOST     ((192 << 24) | (168 << 16) | (0 << 8) | 1)  /* 192.168.0.1 */
#define IP_ROUTER   ((192 << 24) | (168 << 16) | (0 << 8) | 2)  /* 192.168.0.2 */
#define IP_WORLD    IP_ROUTER  /* same as router for this test */

/* Test snat_v4_rev_nat() with ICMP error containing embedded TCP packet
 *
 * Flow:
 * 1. Simulate an outgoing connection: endpoint (10.0.10.1:3030) -> pod (192.168.0.2:80)
 *    This gets SNATed to: pod (192.168.0.1:NODEPORT_PORT_MIN_NAT) -> pod (192.168.0.2:80)
 * 2. Pod sends back ICMP Frag Needed error about the SNATed packet
 * 3. snat_v4_rev_nat() should reverse the NAT in both outer and inner (embedded) packets
 * 4. Result: ICMP error should be addressed to endpoint (10.0.10.1)
 *            with embedded packet showing original src (10.0.10.1:3030)
 */
PKTGEN("tc", "nat4_icmp_error_tcp_snat_revnat")
int nat4_icmp_error_tcp_snat_revnat_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	/* Use Scapy-generated ICMP error packet */
	BUF_DECL(ICMP4_ERR_FRAG_NEEDED_FOR_REVNAT, icmp4_err_frag_needed_for_revnat);
	BUILDER_PUSH_BUF(builder, ICMP4_ERR_FRAG_NEEDED_FOR_REVNAT);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "nat4_icmp_error_tcp_snat_revnat")
int nat4_icmp_error_tcp_snat_revnat_setup(struct __ctx_buff *ctx)
{
	/* Set up NAT mapping to simulate prior outgoing connection.
	 * Original tuple: endpoint -> pod
	 */
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.saddr = bpf_htonl(IP_ENDPOINT),  /* 10.0.10.1 */
		.daddr = bpf_htonl(IP_WORLD),      /* 192.168.0.2 */
		.sport = bpf_htons(3030),
		.dport = bpf_htons(80),
		.flags = 0,
	};

	/* NAT target: translate to pod IP */
	struct ipv4_nat_target target = {
		.addr = bpf_htonl(IP_HOST),  /* 192.168.0.1 */
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MIN_NAT,
	};

	struct ipv4_nat_entry state;
	struct trace_ctx trace;
	void *map;
	int ret;

	/* Get SNAT map */
	map = get_cluster_snat_map_v4(target.cluster_id);
	if (!map)
		return TEST_ERROR;

	/* Create NAT mapping */
	ret = snat_v4_new_mapping(ctx, map, &tuple, &state, &target,
				  false, NULL);
	if (ret != 0)
		return TEST_ERROR;

	/* Now call snat_v4_rev_nat() - this is the function under test.
	 * It should:
	 * 1. Reverse NAT the outer IP dst: pod -> endpoint
	 * 2. Reverse NAT the embedded IP src: pod -> endpoint
	 * 3. Restore the embedded TCP sport: NODEPORT_PORT_MIN_NAT -> 3030
	 */
	ret = snat_v4_rev_nat(ctx, &target, &trace, NULL);
	if (ret != 0)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "nat4_icmp_error_tcp_snat_revnat")
int nat4_icmp_error_tcp_snat_revnat_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/* First 4 bytes contain the return code from SETUP */
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Verify SETUP succeeded */
	if (*status_code != TEST_PASS)
		test_fatal("SETUP failed with status code: %d", *status_code);

	/* Compare the packet with expected output after rev-NAT.
	 * Note: offset sizeof(__u32) to skip the return code prepended by framework.
	 */
	BUF_DECL(ICMP4_ERR_FRAG_NEEDED_AFTER_REVNAT, icmp4_err_frag_needed_after_revnat);
	ASSERT_CTX_BUF_OFF("icmp4_revnat_ok", "Ether", ctx, sizeof(__u32),
			   ICMP4_ERR_FRAG_NEEDED_AFTER_REVNAT,
			   sizeof(BUF(ICMP4_ERR_FRAG_NEEDED_AFTER_REVNAT)));

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
