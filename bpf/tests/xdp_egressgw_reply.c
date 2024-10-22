// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/xdp.h>
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_NODEPORT_ACCELERATION

#define ENABLE_EGRESS_GATEWAY
#define ENABLE_MASQUERADE

#define TUNNEL_PROTOCOL		TUNNEL_PROTOCOL_VXLAN
#define ENCAP_IFINDEX		42

#define DISABLE_LOOPBACK_LB

/* Skip ingress policy checks, not needed to validate hairpin flow */
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
PKTGEN("xdp", "xdp_egressgw_reply")
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

	map_update_elem(&SNAT_MAPPING_IPV4, &tuple, &nat_entry, BPF_ANY);

	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_XDP_REPLY,
			.dir = CT_INGRESS,
		});
}

SETUP("xdp", "xdp_egressgw_reply")
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

	map_update_elem(&SNAT_MAPPING_IPV4, &snat_tuple, &snat_entry, BPF_ANY);

	/* install ipcache entry for the CLIENT_IP: */
	ipcache_v4_add_entry(CLIENT_IP, 0, 0, CLIENT_NODE_IP, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "xdp_egressgw_reply")
int egressgw_reply_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *inner_l4;
	struct udphdr *l4;
	struct ethhdr *l2, *inner_l2;
	struct iphdr *l3, *inner_l3;
	struct vxlanhdr *vxlan;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	vxlan = (void *)l4 + sizeof(*l4);
	if ((void *)vxlan + sizeof(*vxlan) > data_end)
		test_fatal("vxlan out of bounds");

	inner_l2 = (void *)vxlan + sizeof(*vxlan);
	if ((void *)inner_l2 + sizeof(*inner_l2) > data_end)
		test_fatal("inner l2 out of bounds");

	inner_l3 = (void *)inner_l2 + sizeof(*inner_l2);
	if ((void *)inner_l3 + sizeof(*inner_l3) > data_end)
		test_fatal("inner l3 out of bounds");

	inner_l4 = (void *)inner_l3 + sizeof(*inner_l3);
	if ((void *)inner_l4 + sizeof(*inner_l4) > data_end)
		test_fatal("inner l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)gateway_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the gateway MAC")
	if (memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the client node MAC")

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 doesn't have correct proto type")

	if (l3->protocol != IPPROTO_UDP)
		test_fatal("outer IP doesn't have correct L4 protocol")

	if (l3->check != bpf_htons(0x527e))
		test_fatal("L3 checksum is invalid: %d", bpf_htons(l3->check));

	if (l3->saddr != IPV4_DIRECT_ROUTING)
		test_fatal("outerSrcIP is not correct")

	if (l3->daddr != CLIENT_NODE_IP)
		test_fatal("outerDstIP is not correct")

	if (l4->dest != bpf_htons(TUNNEL_PORT))
		test_fatal("outerDstPort is not tunnel port")

	if (inner_l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("inner L2 doesn't have correct ethertype")

	if (inner_l3->protocol != IPPROTO_TCP)
		test_fatal("inner IP doesn't have correct L4 protocol")

	if (inner_l3->saddr != EXTERNAL_SVC_IP)
		test_fatal("innerSrcIP is not the external SVC IP");

	if (inner_l3->daddr != CLIENT_IP)
		test_fatal("innerDstIP hasn't been revNATed to the client IP");

	if (inner_l3->check != bpf_htons(0x4212))
		test_fatal("inner L3 checksum is invalid: %d", bpf_htons(inner_l3->check));

	if (inner_l4->source != EXTERNAL_SVC_PORT)
		test_fatal("innerSrcPort is not the external SVC port");

	if (inner_l4->dest != client_port(TEST_XDP_REPLY))
		test_fatal("innerDstPort hasn't been revNATed to client port");

	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);

	test_finish();
}
