// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

/* Enable CT debug output */
#undef QUIET_CT

#define DEBUG

#include "pktgen.h"

/* Enable code paths under test*/
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_MASQUERADE_IPV4	1
#define ENABLE_ROUTING

#define PRIMARY_IFACE 1
#define SECONDARY_IFACE 2
#define BACKEND_IFACE 123

#define BACKEND_EP_ID 127

#define DEFAULT_ROUTE_MAC mac_one
#define NODE_MAC mac_two
#define LOCAL_BACKEND_MAC mac_three

#define ctx_redirect mock_ctx_redirect

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} redirect_ifindex_map __section_maps_btf;

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	__u32 key = 0;
	__u32 *value = map_lookup_elem(&redirect_ifindex_map, &key);

	if (value)
		*value = ifindex;

	return CTX_ACT_REDIRECT;
}

#include <bpf_host.c>

#include "lib/endpoint.h"
#include "lib/ipcache.h"

#define TO_NETDEV	0

ASSIGN_CONFIG(__u32, interface_ifindex, PRIMARY_IFACE)

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_NETDEV] = &cil_to_netdev,
	},
};

/* Setup for this test:
 *
 * +-------World IP---------+    +----------Pod IP---------+
 * | v4_ext_one:tcp_src_one | -> | v4_pod_one:tcp_dst_one |
 * +------------------------+    +------------------------+
 *          ^                            |
 *          \---------------------------/
 *
 * This happens when in ENI mode and we get traffic via a NLB in ip-mode + preserve-client-ip.
 * NLB NAT'ing is invisible to us, so we effectively see world to pod IP traffic.
 * We need to make sure that in BPF masquerade mode, we do not masquerade the pod IP for the return traffic
 * and route it out of the interface associated with the pod IP, even though egress traffic to
 * the world is normally routed via the primary interface.
 *
 * This test simulates an original incoming packet already traversed the ingress path
 * and was accepted, leaving a CT entry. We act as if the packet here is entering the
 * cil_to_netdev on the wrong device, and we expect it to be redirected to the correct
 * secondary device.
 */

/* Create a boring TCP packet */
PKTGEN("tc", "eni_nlb_symetric_routing_egress_v4_setup")
int eni_nlb_symetric_routing_egress_v4_setup_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_zero, (__u8 *)mac_zero,
					  v4_pod_one, v4_ext_one,
					  tcp_dst_one, tcp_src_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

/* Setup IPCache / Endpoint map / CT state according to the scenario */
SETUP("tc", "eni_nlb_symetric_routing_egress_v4_setup")
int eni_nlb_symetric_routing_egress_v4_setup_setup(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple ct = {
		.daddr = v4_ext_one,
		.saddr = v4_pod_one,
		.dport = tcp_dst_one,
		.sport = tcp_src_one,
		.nexthdr = IPPROTO_TCP,
		.flags = 1,
	};
	struct ct_state state = {0};

	state.src_sec_id = WORLD_ID;

	endpoint_v4_add_entry(v4_pod_one, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      SECONDARY_IFACE, (__u8 *)LOCAL_BACKEND_MAC, (__u8 *)NODE_MAC);

	ipcache_v4_add_entry(v4_pod_one, 0, SECLABEL, 0, 0);

	ct_create4(&cilium_ct4_global, NULL, &ct, ctx, CT_INGRESS, &state, NULL);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "eni_nlb_symetric_routing_egress_v4_setup")
int eni_nlb_symetric_routing_egress_v4_setup_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct tcphdr *l4;
	__u32 key = 0;
	__u32 *redirect_ifindex;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != TC_ACT_REDIRECT)
		test_fatal("packet has not been redirected");

	redirect_ifindex = map_lookup_elem(&redirect_ifindex_map, &key);
	if (!redirect_ifindex)
		test_fatal("redirect_ifindex not found");

	if (*redirect_ifindex != SECONDARY_IFACE)
		test_fatal("redirected to ifindex %d, expected %d", *redirect_ifindex,
			   SECONDARY_IFACE);

	l3 =  data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != v4_pod_one)
		test_fatal("src IP changed");

	if (l3->daddr != v4_ext_one)
		test_fatal("dest IP changed");

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_dst_one)
		test_fatal("src TCP port changed");

	if (l4->dest != tcp_src_one)
		test_fatal("dst TCP port changed");

	test_finish();
}

/* The same test, but for ICMP */
PKTGEN("tc", "eni_nlb_symetric_routing_egress_v4_setup_icmp")
int eni_nlb_symetric_routing_egress_v4_setup_icmp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_icmp_packet(&builder,
					   (__u8 *)mac_zero, (__u8 *)mac_zero,
					   v4_pod_one, v4_ext_one,
					   ICMP_ECHOREPLY);
	if (!l4)
		return TEST_ERROR;
	l4->un.echo.id = bpf_htons(1);

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "eni_nlb_symetric_routing_egress_v4_setup_icmp")
int eni_nlb_symetric_routing_egress_v4_setup_icmp_setup(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple ct = {
		.daddr = v4_ext_one,
		.saddr = v4_pod_one,
		.dport = 0,
		.sport = bpf_htons(1),
		.nexthdr = IPPROTO_ICMP,
		.flags = TUPLE_F_IN,
	};
	struct ct_state state = {0};

	state.src_sec_id = WORLD_ID;

	endpoint_v4_add_entry(v4_pod_one, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      SECONDARY_IFACE, (__u8 *)LOCAL_BACKEND_MAC, (__u8 *)NODE_MAC);

	ipcache_v4_add_entry(v4_pod_one, 0, SECLABEL, 0, 0);

	ct_create4(&cilium_ct_any4_global, NULL, &ct, ctx, CT_INGRESS, &state, NULL);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "eni_nlb_symetric_routing_egress_v4_setup_icmp")
int eni_nlb_symetric_routing_egress_v4_setup_icmp_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct icmphdr *l4;
	__u32 key = 0;
	__u32 *redirect_ifindex;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != TC_ACT_REDIRECT)
		test_fatal("packet has not been redirected");

	redirect_ifindex = map_lookup_elem(&redirect_ifindex_map, &key);
	if (!redirect_ifindex)
		test_fatal("redirect_ifindex not found");

	if (*redirect_ifindex != SECONDARY_IFACE)
		test_fatal("redirected to ifindex %d, expected %d", *redirect_ifindex,
			   SECONDARY_IFACE);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != v4_pod_one)
		test_fatal("src IP changed");

	if (l3->daddr != v4_ext_one)
		test_fatal("dest IP changed");

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct icmphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->un.echo.id != bpf_htons(1))
		test_fatal("ICMP identifier changed");

	test_finish();
}
