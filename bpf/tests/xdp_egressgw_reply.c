// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/xdp.h>
#include "pktgen.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

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

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)
#define CLIENT_NODE_IP		v4_node_one

#define EXTERNAL_SVC_IP		v4_ext_one
#define EXTERNAL_SVC_PORT	__bpf_htons(1234)

#define GATEWAY_NODE_IP		v4_node_two
#define IPV4_DIRECT_ROUTING	GATEWAY_NODE_IP

#define MASQ_IP			GATEWAY_NODE_IP
#define MASQ_PORT		__bpf_htons(NODEPORT_PORT_MIN_NAT + 1)

#define DIRECT_ROUTING_IFINDEX	25

#define fib_lookup mock_fib_lookup

static volatile const __u8 *client_node_mac = mac_one;
/* this matches the default node_config.h: */
static volatile const __u8 gateway_node_mac[ETH_ALEN]	= { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 };

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __ctx_buff *ctx __maybe_unused, int ifindex __maybe_unused,
		  __u32 flags __maybe_unused)
{
	if (ifindex != DIRECT_ROUTING_IFINDEX)
		return CTX_ACT_DROP;

	return CTX_ACT_REDIRECT;
}

long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	params->ifindex = DIRECT_ROUTING_IFINDEX;

	if (params->ipv4_dst == CLIENT_NODE_IP) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)gateway_node_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_node_mac, ETH_ALEN);
	} else {
		return CTX_ACT_DROP;
	}

	return 0;
}

#include <bpf_xdp.c>

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
	struct pktgen builder;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = EXTERNAL_SVC_IP;
	l3->daddr = MASQ_IP;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = EXTERNAL_SVC_PORT;
	l4->dest = MASQ_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("xdp", "xdp_egressgw_reply")
int egressgw_reply_setup(struct __ctx_buff *ctx)
{
	/* install EgressGW policy for the connection: */
	struct egress_gw_policy_key egressgw_key = {
		.lpm_key = { EGRESS_PREFIX_LEN(24), {} },
		.saddr   = CLIENT_IP,
		.daddr   = EXTERNAL_SVC_IP & 0Xffffff,
	};

	struct egress_gw_policy_entry egressgw_value = {
		.egress_ip  = 0, /* not needed */
		.gateway_ip = GATEWAY_NODE_IP,
	};

	map_update_elem(&EGRESS_POLICY_MAP, &egressgw_key, &egressgw_value, 0);

	/* install RevSNAT entry */
	struct ipv4_ct_tuple snat_tuple = {
		.daddr   = MASQ_IP,
		.saddr   = EXTERNAL_SVC_IP,
		.dport   = MASQ_PORT,
		.sport   = EXTERNAL_SVC_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags   = NAT_DIR_INGRESS,
	};

	struct ipv4_nat_entry snat_entry = {
		.to_daddr = CLIENT_IP,
		.to_dport = CLIENT_PORT,
	};

	map_update_elem(&SNAT_MAPPING_IPV4, &snat_tuple, &snat_entry, BPF_ANY);

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

	if (memcmp(l2->h_source, (__u8 *)gateway_node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the gateway MAC")
	if (memcmp(l2->h_dest, (__u8 *)client_node_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the client node MAC")

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 doesn't have correct proto type")

	if (l3->protocol != IPPROTO_UDP)
		test_fatal("outer IP doesn't have correct L4 protocol")

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

	if (inner_l4->source != EXTERNAL_SVC_PORT)
		test_fatal("innerSrcPort is not the external SVC port");

	if (inner_l4->dest != CLIENT_PORT)
		test_fatal("innerDstPort hasn't been revNATed to client port");

	test_finish();
}
