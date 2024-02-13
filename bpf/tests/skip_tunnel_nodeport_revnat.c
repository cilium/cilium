// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */
#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"

/*
 * Datapath configuration settings to setup tunneling with VXLan
 * and nodeport
 */
#define ENCAP_IFINDEX 1  /* Set dummy ifindex for tunnel device */
#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define TUNNEL_MODE 1
#define ENABLE_NODEPORT 1

/*
 * Now include testing defaults
 */
#define ROUTER_IP
#include "config_replacement.h"
#undef ROUTER_IP
#include "node_config.h"

/*
 * Simulate sending traffic from pod_one on node_one to pod_two
 * on node_two, through a nodeport on node_three, as well as sending
 * reply from pod_two to pod_one through node_three.
 *
 * Tests are written from the perspective of node_three.
 * This will give us access to nodeport_lb{4,6} with the
 * following scenarios:
 *
 *     1. Sending packet to remote backend on node_two,
 *        requiring NAT (cil_from_netdev).
 *     2. Sending reply packet from remote backend on node_two
 *        back to pod_one, requiring revNAT (cil_from_netdev).
 *
 * This file is responsible for testing the second scenario.
 *
 * The macros below are defined from the perspective of scenario two.
 */
#define SRC_IPV4 v4_pod_one
#define SRC_IPV6 v6_pod_one
#define SRC_TUNNEL_IP v4_node_one
#define NODEPORT_MAC mac_three
#define NODEPORT_IPV4 v4_node_three
#define NODEPORT_IPV6 v6_node_three
#define NODEPORT_NAT_PORT tcp_src_two
#define DST_MAC mac_four
#define DST_IPV4 v4_pod_two
#define DST_IPV6 v6_pod_two
#define DST_PORT tcp_svc_one

/*
 * Sometimes fib_redirect returns CTX_ACT_REDIRECT, depending on the state of the
 * host. Mock fib_lookup to always return CTX_ACT_DROP.
 */

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(const __maybe_unused void *ctx, const struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	/* The (void)param lines prevent gcc from complaining about them being unused. */
	(void)ctx;
	(void)params;
	(void)plen;
	(void)flags;
	return CTX_ACT_DROP;
}

/*
 * Include entrypoint into host stack
 */
#include "bpf_host.c"

/*
 * Include test helpers
 */
#include "lib/lb.h"
#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"
#include "lib/clear.h"

/*
 * Include conntrack table, SNAT, nodeport helpers
 */
#include "lib/conntrack_map.h"
#include "lib/conntrack.h"
#include "lib/nat.h"
#include "lib/nodeport.h"

#define FROM_NETDEV 0
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
	},
};

static __always_inline int
pktgen(struct __ctx_buff *ctx, bool v4)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	if (v4)
		l4 = pktgen__push_ipv4_tcp_packet(&builder,
						  (__u8 *)DST_MAC,
						  (__u8 *)NODEPORT_MAC,
						  DST_IPV4, NODEPORT_IPV4,
						  DST_PORT, NODEPORT_NAT_PORT);
	else
		l4 = pktgen__push_ipv6_tcp_packet(&builder,
						  (__u8 *)DST_MAC, (__u8 *)NODEPORT_MAC,
						  (__u8 *)DST_IPV6,
						  (__u8 *)NODEPORT_IPV6,
						  DST_PORT, NODEPORT_NAT_PORT);

	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/*
 * Setup scenario where NODEPORT_IP is receiving reply traffic from DST_IP
 * that needs to be redirected to SRC_IP on node through tunnel SRC_TUNNEL_IP
 */
static __always_inline int
setup(struct __ctx_buff *ctx, bool v4, bool flag_skip_tunnel)
{
	/*
	 * Reset maps before the test.
	 * Otherwise, leftover state from previous tests will have an impact,
	 * as the tests and checks assume we have a fresh state every time.
	 */
	clear_map(&METRICS_MAP);
	clear_map(&CT_MAP_TCP4);
	clear_map(&CT_MAP_TCP6);
	clear_map(get_cluster_snat_map_v4(0));
	clear_map(get_cluster_snat_map_v6(0));

	policy_add_egress_allow_all_entry();

	if (v4) {
		/*
		 * Create SNAT entry to put packet into revSNAT stack.
		 * Here's how this works:
		 * SNAT mappings are created from the perspective of a packet that needs SNAT in order to
		 * be forwarded out of the node. This is why the tuple below is opposite of the packet we
		 * constructed in pktgen, and why it includes SRC_IPV4 as the source address.
		 * We are able to deterministically understand the SNAT source port, because the SNAT stack
		 * attempts to reuse the snatted packet's source port, if the port is available. Since we are
		 * just in a test environment, the port will always be available and therefore always be
		 * chosen.
		 *
		 * This is what the hypothetical traffic flow would look like here:
		 *
		 *     ip=SRC_IPV4,src_port=NODEPORT_NAT_PORT -> ip=NODEPORT_IPV4,dst_port=<a NodePort>
		 *     ip=NODEPORT_IPV4,src_port=NODEPORT_NAT_PORT -> ip=DST_IPV4,dst_port=DST_PORT
		 *     ip=DST_IPV4,src_port=DST_PORT -> ip=NODEPORT_IPV4,dst_port=NODEPORT_NAT_PORT
		 *     ip=NODEPORT_IPV4,src_port=<a NodePort> -> ip=SRC_IPV4,dst_port=NODEPORT_NAT_PORT
		 */
		struct ipv4_ct_tuple otuple = {
			.nexthdr = IPPROTO_TCP,
			.flags = TUPLE_F_OUT,
			.saddr = SRC_IPV4,
			.sport = NODEPORT_NAT_PORT,
			.daddr = DST_IPV4,
			.dport = DST_PORT,
		};

		/*
		 * When moving through the revSNAT stack while processing our generated reply packet, a check
		 * will be performed to see if the destination port is in the range defined by [min_port, max_port].
		 * This is why NODEPORT_NAT_PORT is used for both of these fields, as it'll be the source
		 * port for the SNAT.
		 */
		struct ipv4_nat_target target = {
			.addr = NODEPORT_IPV4,
			.min_port = NODEPORT_NAT_PORT,
			.max_port = NODEPORT_NAT_PORT,
		};

		void *map = get_cluster_snat_map_v4(0);

		struct ipv4_nat_entry state;

		snat_v4_new_mapping(ctx, map, &otuple, &state, &target, true, NULL);

		/*
		 * The conntrack entry is used to understand that the packet being received is a reply.
		 * This will put the packet to where it needs to be in the revDNAT stack.
		 * NodePort related traffic requires that the CT state is flagged with the node_port field
		 * and that a rev_nat_index is set.
		 */
		struct ct_state ct_state = {
			.node_port = true,
			.rev_nat_index = 123,
		};

		/*
		 * We need to swap addresses here, because the conntrack-related functions have
		 * the source and destination addresses set up for reply direction traffic.
		 * See bpf/lib/common.h
		 */
		ipv4_ct_tuple_swap_addrs(&otuple);
		ct_create4(get_ct_map4(&otuple), NULL, &otuple, ctx, CT_EGRESS, &ct_state, NULL);

		ipcache_v4_add_entry_with_flags(SRC_IPV4,
						0, 1230, SRC_TUNNEL_IP, 0, flag_skip_tunnel);
	} else {
		struct ipv6_ct_tuple otuple = {
			.nexthdr = IPPROTO_TCP,
			.flags = TUPLE_F_OUT,
			.saddr = *((union v6addr *)SRC_IPV6),
			.sport = NODEPORT_NAT_PORT,
			.daddr = *((union v6addr *)DST_IPV6),
			.dport = DST_PORT,
		};
		struct ipv6_nat_target target = {
			.addr = *((union v6addr *)NODEPORT_IPV6),
			.min_port = NODEPORT_NAT_PORT,
			.max_port = NODEPORT_NAT_PORT,
		};

		struct ipv6_nat_entry state;

		snat_v6_new_mapping(ctx, &otuple, &state, &target, true, NULL);

		struct ct_state ct_state = {
			.node_port = true,
			.rev_nat_index = 123,
		};
		ipv6_ct_tuple_swap_addrs(&otuple);
		ct_create6(get_ct_map6(&otuple), NULL, &otuple, ctx, CT_EGRESS, &ct_state, NULL);

		ipcache_v6_add_entry_with_flags((union v6addr *)SRC_IPV6,
						0, 1230, SRC_TUNNEL_IP, 0, flag_skip_tunnel);
	}

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

static __always_inline int
check_ctx(const struct __ctx_buff *ctx, bool v4, __u32 expected_result)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct tcphdr *l4;
	__u8 *payload;

	struct metrics_value *entry = NULL;
	struct metrics_key key = {};

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/*
	 * Check the returned status is correct.
	 * The appropriate value for "expected_result" should be set
	 * by the caller.
	 * If flag_skip_tunnel=false, then we need CTX_ACT_REDIRECT
	 * If flag_skip_tunnel=true, then we need CTX_ACT_DROP
	 * Skipping encapsulation should trigger trying a
	 * fib redirect, which, since we haven't set up, should fail.
	 */
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == expected_result);

	/*
	 * Check that the packet was recorded in the metrics.
	 * This only needs to be done if the packet was encapsulated,
	 * as there is no unique metric recorded when the packet is
	 * not encapsulated.
	 */
	if (expected_result == CTX_ACT_REDIRECT) {
		key.reason = REASON_FORWARDED;
		key.dir = METRIC_EGRESS;

		entry = map_lookup_elem(&METRICS_MAP, &key);
		if (!entry)
			test_fatal("metrics entry not found")

		__u64 count = 1;

		assert_metrics_count(key, count);
	}

	/* Sanity checks on packet integrity. */
	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds")

	if (v4 && l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 proto hasn't been set to ETH_P_IP")

	if (!v4 && l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IPV6")

	if (memcmp(l2->h_source, (__u8 *)DST_MAC, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to dst ep's mac");

	/*
	 * We rely on the kernel to set the destination mac address, therefore
	 * from our perspective it should stay the same.
	 */
	if (memcmp(l2->h_dest, (__u8 *)NODEPORT_MAC, ETH_ALEN) != 0)
		test_fatal("dst mac has changed")

	if (v4) {
		struct iphdr *l3;

		l3 = (void *)l2 + sizeof(struct ethhdr);

		if ((void *)l3 + sizeof(struct iphdr) > data_end)
			test_fatal("l3 out of bounds");

		/*
		 * We don't have revDNAT, so the reply source should stay the same.
		 */
		if (l3->saddr != DST_IPV4)
			test_fatal("src IP was changed");

		if (l3->daddr != SRC_IPV4)
			test_fatal("dest IP was not rev snatted");

		l4 = (void *)l3 + sizeof(struct iphdr);
	} else {
		struct ipv6hdr *l3;

		l3 = (void *)l2 + sizeof(struct ethhdr);

		if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
			test_fatal("l3 out of bounds");

		if (memcmp((__u8 *)&l3->saddr, (__u8 *)DST_IPV6, 16) != 0)
			test_fatal("src IP was changed");

		if (memcmp((__u8 *)&l3->daddr, (__u8 *)SRC_IPV6, 16) != 0)
			test_fatal("dest IP was not rev snatted");

		l4 = (void *)l3 + sizeof(struct ipv6hdr);
	}

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	/*
	 * We don't have revDNAT here so this should stay the same.
	 */
	if (l4->source != DST_PORT)
		test_fatal("src TCP port was changed");

	if (l4->dest != NODEPORT_NAT_PORT)
		test_fatal("dest TCP port was not set correctly");

	payload = (void *)l4 + sizeof(struct tcphdr);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("payload out of bounds");

	if (memcmp(payload, default_data, sizeof(default_data)) != 0)
		test_fatal("tcp payload was changed")

	test_finish();
}

PKTGEN("tc", "01_ipv4_nodeport_ingress_no_flags")
int ipv4_nodeport_ingress_no_flags_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, true);
}

SETUP("tc", "01_ipv4_nodeport_ingress_no_flags")
int ipv4_nodeport_ingress_no_flags_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, true, false);
}

CHECK("tc", "01_ipv4_nodeport_ingress_no_flags")
int ipv4_nodeport_ingress_no_flags_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, true, CTX_ACT_REDIRECT);
}

PKTGEN("tc", "02_ipv4_nodeport_ingress_skip_tunnel")
int ipv4_nodeport_ingress_skip_tunnel_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, true);
}

SETUP("tc", "02_ipv4_nodeport_ingress_skip_tunnel")
int ipv4_nodeport_ingress_skip_tunnel_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, true, true);
}

CHECK("tc", "02_ipv4_nodeport_ingress_skip_tunnel")
int ipv4_nodeport_ingress_skip_tunnel_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, true, CTX_ACT_DROP);
}

PKTGEN("tc", "03_ipv6_nodeport_ingress_no_flags")
int ipv6_nodeport_ingress_no_flags_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, false);
}

SETUP("tc", "03_ipv6_nodeport_ingress_no_flags")
int ipv6_nodeport_ingress_no_flags_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, false, false);
}

CHECK("tc", "03_ipv6_nodeport_ingress_no_flags")
int ipv6_nodeport_ingress_no_flags_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, false, CTX_ACT_REDIRECT);
}

PKTGEN("tc", "04_ipv6_nodeport_ingress_skip_tunnel")
int ipv6_nodeport_ingress_skip_tunnel_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, false);
}

SETUP("tc", "04_ipv6_nodeport_ingress_skip_tunnel")
int ipv6_nodeport_ingress_skip_tunnel_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, false, true);
}

CHECK("tc", "04_ipv6_nodeport_ingress_skip_tunnel")
int ipv6_nodeport_ingress_skip_tunnel_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, false, CTX_ACT_DROP);
}
