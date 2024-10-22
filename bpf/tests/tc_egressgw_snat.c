// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_EGRESS_GATEWAY
#define ENABLE_MASQUERADE_IPV4
#define ENCAP_IFINDEX		42
#define SECONDARY_IFACE_IFINDEX	44

#define SECCTX_FROM_IPCACHE 1

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused);

#define fib_lookup mock_fib_lookup
static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused);

#include "bpf_host.c"

#include "lib/egressgw.h"
#include "lib/ipcache.h"

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if (ifindex == ENCAP_IFINDEX)
		return CTX_ACT_REDIRECT;
	if (ifindex == SECONDARY_IFACE_IFINDEX)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_DROP;
}

static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	if (params && params->ipv4_src == EGRESS_IP2)
		params->ifindex = SECONDARY_IFACE_IFINDEX;

	return 0;
}

#define TO_NETDEV 0
#define FROM_NETDEV 1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_NETDEV] = &cil_to_netdev,
		[FROM_NETDEV] = &cil_from_netdev,
	},
};

/* Test that a packet matching an egress gateway policy on the to-netdev program
 * gets correctly SNATed with the egress IP of the policy.
 */
PKTGEN("tc", "tc_egressgw_snat1")
int egressgw_snat1_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT1,
		});
}

SETUP("tc", "tc_egressgw_snat1")
int egressgw_snat1_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24,
				  GATEWAY_NODE_IP, EGRESS_IP);

	/* Jump into the entrypoint */
	ctx_egw_done_set(ctx);
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_snat1")
int egressgw_snat1_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT1,
			.packets = 1,
			.status_code = CTX_ACT_OK
		});
}

/* Test that a packet matching an egress gateway policy on the from-netdev program
 * gets correctly revSNATed and connection tracked.
 */
PKTGEN("tc", "tc_egressgw_snat1_2_reply")
int egressgw_snat1_2_reply_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT1,
			.dir = CT_INGRESS,
		});
}

SETUP("tc", "tc_egressgw_snat1_2_reply")
int egressgw_snat1_2_reply_setup(struct __ctx_buff *ctx)
{
	/* install ipcache entry for the CLIENT_IP: */
	ipcache_v4_add_entry(CLIENT_IP, 0, 0, CLIENT_NODE_IP, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_snat1_2_reply")
int egressgw_snat1_2_reply_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT1,
			.dir = CT_INGRESS,
			.packets = 2,
			.status_code = CTX_ACT_REDIRECT,
		});
}

PKTGEN("tc", "tc_egressgw_snat2")
int egressgw_snat2_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT2,
		});
}

SETUP("tc", "tc_egressgw_snat2")
int egressgw_snat2_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	ctx_egw_done_set(ctx);
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_snat2")
int egressgw_snat2_check(struct __ctx_buff *ctx)
{
	int ret = egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT2,
			.packets = 1,
			.status_code = CTX_ACT_OK
		});

	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0Xffffff, 24);

	return ret;
}

/* Test that a packet matching an egress gateway policy on the to-netdev program
 * gets correctly SNATed with the desired egress IP of the policy, event if the
 * packet hits a stale NAT entry.
 */
PKTGEN("tc", "tc_egressgw_tuple_collision1")
int egressgw_tuple_collision1_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_TUPLE_COLLISION,
		});
}

SETUP("tc", "tc_egressgw_tuple_collision1")
int egressgw_tuple_collision1_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24,
				  GATEWAY_NODE_IP, EGRESS_IP);

	/* Jump into the entrypoint */
	ctx_egw_done_set(ctx);
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_tuple_collision1")
int egressgw_tuple_collision1_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_TUPLE_COLLISION,
			.packets = 1,
			.status_code = CTX_ACT_OK
		});

	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0Xffffff, 24);

	return ret;
}

PKTGEN("tc", "tc_egressgw_tuple_collision2")
int egressgw_tuple_collision2_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_TUPLE_COLLISION,
		});
}

SETUP("tc", "tc_egressgw_tuple_collision2")
int egressgw_tuple_collision2_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24,
				  GATEWAY_NODE_IP, EGRESS_IP3);

	/* Jump into the entrypoint */
	ctx_egw_done_set(ctx);
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_tuple_collision2")
int egressgw_tuple_collision2_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_TUPLE_COLLISION,
			.tuple_collision = true,
			.packets = 2,
			.status_code = CTX_ACT_OK
		});
}

/* Test that a packet matching an egress gateway policy on the from-netdev program
 * gets correctly revSNATed and connection tracked, even if the packet hits a
 * stale NAT entry.
 */
PKTGEN("tc", "tc_egressgw_tuple_collision2_reply")
int egressgw_tuple_collision2_reply_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_TUPLE_COLLISION,
			.tuple_collision = true,
			.dir = CT_INGRESS,
		});
}

SETUP("tc", "tc_egressgw_tuple_collision2_reply")
int egressgw_tuple_collision2_reply_setup(struct __ctx_buff *ctx)
{
	/* install ipcache entry for the CLIENT_IP: */
	ipcache_v4_add_entry(CLIENT_IP, 0, 0, CLIENT_NODE_IP, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_tuple_collision2_reply")
int egressgw_tuple_collision2_reply_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_TUPLE_COLLISION,
			.dir = CT_INGRESS,
			.packets = 3,
			.status_code = CTX_ACT_REDIRECT,
		});

	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0Xffffff, 24);

	return ret;
}

/* Test that a packet matching an excluded CIDR egress gateway policy on the
 * to-netdev program does not get SNATed with the egress IP of the policy.
 */
PKTGEN("tc", "tc_egressgw_skip_excluded_cidr_snat")
int egressgw_skip_excluded_cidr_snat_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_EXCL_CIDR,
		});
}

SETUP("tc", "tc_egressgw_skip_excluded_cidr_snat")
int egressgw_skip_excluded_cidr_snat_setup(struct __ctx_buff *ctx)
{

	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, GATEWAY_NODE_IP, 0);
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32, EGRESS_GATEWAY_EXCLUDED_CIDR, 0);

	/* Jump into the entrypoint */
	ctx_egw_done_set(ctx);
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_skip_excluded_cidr_snat")
int egressgw_skip_excluded_cidr_snat_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->check != bpf_htons(0x4112))
		test_fatal("L3 checksum is invalid: %d", bpf_htons(l3->check));

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the client MAC")

	if (memcmp(l2->h_dest, (__u8 *)ext_svc_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the external svc MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != EXTERNAL_SVC_IP)
		test_fatal("dst IP has changed");

	if (l4->source != client_port(TEST_SNAT_EXCL_CIDR))
		test_fatal("src TCP port has changed");

	if (l4->dest != EXTERNAL_SVC_PORT)
		test_fatal("dst port has changed");

	test_finish();
}

PKTGEN("tc", "tc_egressgw_fib_redirect")
int egressgw_fib_redirect_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_FIB,
			.redirect = true,
		});
}

SETUP("tc", "tc_egressgw_fib_redirect")
int egressgw_fib_redirect_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24,
				  GATEWAY_NODE_IP, EGRESS_IP2);

	/* Jump into the entrypoint */
	ctx_egw_done_set(ctx);
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_fib_redirect")
int egressgw_fib_redirect_check(const struct __ctx_buff *ctx __maybe_unused)
{
	int ret = egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_FIB,
			.redirect = true,
			.packets = 1,
			.status_code = CTX_ACT_REDIRECT,
		});

	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);

	return ret;
}

