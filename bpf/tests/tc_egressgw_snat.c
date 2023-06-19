// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define HAVE_LPM_TRIE_MAP_TYPE
#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"
#include "config_replacement.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_EGRESS_GATEWAY
#define ENABLE_MASQUERADE
#define ENCAP_IFINDEX		42

#define SECCTX_FROM_IPCACHE 1

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused);

#include "bpf_host.c"

#include "lib/egressgw.h"

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if (ifindex == ENCAP_IFINDEX)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_DROP;
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
	tail_call_static(ctx, &entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_snat1")
int egressgw_snat1_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT1,
			.tx_packets = 1,
			.rx_packets = 0,
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
	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = CLIENT_IP,
	};
	struct remote_endpoint_info cache_value = {
		.tunnel_endpoint = CLIENT_NODE_IP,
	};
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_snat1_2_reply")
int egressgw_snat1_2_reply_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT1,
			.dir = CT_INGRESS,
			.tx_packets = 1,
			.rx_packets = 1,
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
	tail_call_static(ctx, &entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_snat2")
int egressgw_snat2_check(struct __ctx_buff *ctx)
{
	int ret = egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT2,
			.tx_packets = 1,
			.rx_packets = 0,
			.status_code = CTX_ACT_OK
		});

	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0Xffffff, 24);

	return ret;
}
