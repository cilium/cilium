// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_NODEPORT_ACCELERATION

#define ENABLE_EGRESS_GATEWAY
#define ENABLE_MASQUERADE

#define TUNNEL_PROTOCOL		TUNNEL_PROTOCOL_VXLAN
#define ENCAP_IFINDEX		42

/* Skip ingress policy checks */
#define USE_BPF_PROG_FOR_INGRESS_POLICY

#define IPV4_DIRECT_ROUTING	v4_node_one /* gateway node */
#define MASQ_PORT		__bpf_htons(NODEPORT_PORT_MIN_NAT + 1)
#define DIRECT_ROUTING_IFINDEX	25

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __ctx_buff *ctx __maybe_unused, int ifindex __maybe_unused,
		  __u32 flags __maybe_unused);

#define fib_lookup mock_fib_lookup
static __always_inline __maybe_unused long
mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		__maybe_unused int plen, __maybe_unused __u32 flags);

#include <bpf_xdp.c>

#include "lib/egressgw.h"
#include "lib/ipcache.h"

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __ctx_buff *ctx __maybe_unused, int ifindex __maybe_unused,
		  __u32 flags __maybe_unused)
{
	if (ifindex != DIRECT_ROUTING_IFINDEX)
		return CTX_ACT_DROP;

	return CTX_ACT_REDIRECT;
}

static __always_inline __maybe_unused long
mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		__maybe_unused int plen, __maybe_unused __u32 flags)
{
	params->ifindex = DIRECT_ROUTING_IFINDEX;

	if (params->ipv4_dst == CLIENT_NODE_IP) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)gateway_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
	} else {
		return CTX_ACT_DROP;
	}

	return 0;
}

#define FROM_NETDEV	0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_xdp_entry,
	},
};

/* Test that a EgressGW reply gets RevSNATed, and forwarded to the
 * worker node via tunnel.
 */
PKTGEN("xdp", "xdp_egressgw_reply_bench_example")
int egressgw_reply_pktgen(struct __ctx_buff *ctx)
{
	/* Add a new NAT entry so that pktgen can figure out the correct destination port */
	struct ipv4_ct_tuple tuple = {
		.saddr   = CLIENT_IP,
		.daddr   = EXTERNAL_SVC_IP,
		.dport   = EXTERNAL_SVC_PORT,
		.sport   = client_port(TEST_XDP_REPLY),
		.nexthdr = IPPROTO_TCP,
	};

	struct ipv4_nat_entry nat_entry = {
		.to_saddr = EGRESS_IP,
		.to_sport = MASQ_PORT,
	};

	map_update_elem(&cilium_snat_v4_external, &tuple, &nat_entry, BPF_ANY);

	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_XDP_REPLY,
			.dir = CT_INGRESS,
		});
}

BENCH("xdp", "xdp_egressgw_reply_bench_example")
int egressgw_reply_setup(struct __ctx_buff *ctx)
{
	/* install EgressGW policy for the connection: */
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, GATEWAY_NODE_IP, 0);

	/* install RevSNAT entry */
	struct ipv4_ct_tuple snat_tuple = {
		.daddr   = EGRESS_IP,
		.saddr   = EXTERNAL_SVC_IP,
		.dport   = MASQ_PORT,
		.sport   = EXTERNAL_SVC_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags   = NAT_DIR_INGRESS,
	};

	struct ipv4_nat_entry snat_entry = {
		.to_daddr = CLIENT_IP,
		.to_dport = client_port(TEST_XDP_REPLY),
	};

	map_update_elem(&cilium_snat_v4_external, &snat_tuple, &snat_entry, BPF_ANY);

	/* install ipcache entry for the CLIENT_IP: */
	ipcache_v4_add_entry(CLIENT_IP, 0, 0, CLIENT_NODE_IP, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}
