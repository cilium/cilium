/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Tests the cil_to_host IPsec recirculation path with hostFW and NodePort
 * enabled. These cases verify the marked path returns without an error; they
 * do not seed LB/NAT state or assert revDNAT rewrites.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4			1
#define ENABLE_IPV6			1
#define ENABLE_HOST_FIREWALL		1
#define ENABLE_NODEPORT			1
#define ENABLE_MASQUERADE_IPV4		1

#define LOCAL_NODE_IP			v4_node_one
#define REMOTE_NODE_IP			v4_node_two

#define POD_LOCAL_IP			v4_pod_one
#define POD_REMOTE_IP			v4_pod_one_on_node_two
#define POD_LOCAL_IDENTITY		(CIDR_IDENTITY_RANGE_START - 1)
#define POD_REMOTE_IDENTITY		(CIDR_IDENTITY_RANGE_START - 2)

#define CLIENT_PORT			bpf_htons(54321)
#define BACKEND_PORT			bpf_htons(8080)

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *peer_mac = mac_two;

#include "lib/bpf_host.h"

#include "lib/ipcache.h"
#include "lib/policy.h"

ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

/* Build a TCP packet shaped like an IPsec-decrypted backend reply. The
 * NodePort path only needs parseable IPv4/TCP headers here.
 */
static __always_inline int build_inner_tcp_v4(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)peer_mac, (__u8 *)node_mac,
					  POD_LOCAL_IP, POD_REMOTE_IP,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/*
 * Test 1: ipsec_recirc_to_host_nodeport_path_runs
 *
 * MARK_MAGIC_ENCRYPT enters the IPsec NodePort revDNAT path. No LB/NAT
 * state is seeded, so handle_nat_fwd returns without rewrite and hostFW
 * ingress skips the pod-bound packet.
 */
PKTGEN("tc", "ipsec_recirc_to_host_nodeport_path_runs")
int ipsec_recirc_to_host_nodeport_path_runs_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_tcp_v4(ctx);
}

SETUP("tc", "ipsec_recirc_to_host_nodeport_path_runs")
int ipsec_recirc_to_host_nodeport_path_runs_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(POD_LOCAL_IP, 0, POD_LOCAL_IDENTITY, 0, 0);
	ipcache_v4_add_entry(POD_REMOTE_IP, 0, POD_REMOTE_IDENTITY,
			     REMOTE_NODE_IP, 0);
	ipcache_v4_add_world_entry();

	/* Mark the skb as IPsec-decrypted recirculation. */
	ctx->mark = MARK_MAGIC_ENCRYPT;

	return host_receive_packet(ctx);
}

CHECK("tc", "ipsec_recirc_to_host_nodeport_path_runs")
int ipsec_recirc_to_host_nodeport_path_runs_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* No LB/NAT state is seeded, so the packet is returned unmodified (CTX_ACT_OK). */
	assert(*status_code == CTX_ACT_OK);

	test_finish();
}

/*
 * Test 2: ipsec_recirc_to_host_no_encrypt_skips_nodeport_block
 *
 * Scope guard: without MARK_MAGIC_ENCRYPT, the IPsec NodePort revDNAT block
 * is skipped and regular pod-bound ingress still returns OK.
 */
PKTGEN("tc", "ipsec_recirc_to_host_no_encrypt_skips_nodeport_block")
int ipsec_recirc_to_host_no_encrypt_skips_nodeport_block_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_tcp_v4(ctx);
}

SETUP("tc", "ipsec_recirc_to_host_no_encrypt_skips_nodeport_block")
int ipsec_recirc_to_host_no_encrypt_skips_nodeport_block_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(POD_LOCAL_IP, 0, POD_LOCAL_IDENTITY, 0, 0);
	ipcache_v4_add_entry(POD_REMOTE_IP, 0, POD_REMOTE_IDENTITY,
			     REMOTE_NODE_IP, 0);
	ipcache_v4_add_world_entry();

	/* Regular ingress, not IPsec recirculation. */
	ctx->mark = 0;

	return host_receive_packet(ctx);
}

CHECK("tc", "ipsec_recirc_to_host_no_encrypt_skips_nodeport_block")
int ipsec_recirc_to_host_no_encrypt_skips_nodeport_block_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	test_finish();
}
