// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */
#include "common.h"
#include <bpf/ctx/skb.h>
#include "linux/bpf.h"
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
 * This file is responsible for testing the first scenario.
 *
 * The macros below are defined from the perspective of scenario one.
 */
#define SRC_MAC mac_one
#define SRC_IPV4 v4_pod_one
#define SRC_IPV6 v6_pod_one
#define SRC_PORT tcp_src_one
#define NODEPORT_MAC mac_three
#define NODEPORT_IPV4 v4_node_three
#define NODEPORT_IPV6 v6_node_three
#define NODEPORT_PORT tcp_dst_one
#define DST_IPV4 v4_pod_two
#define DST_IPV6 v6_pod_two
#define DST_PORT tcp_svc_one
#define DST_TUNNEL_IP v4_node_two

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
						  (__u8 *)SRC_MAC,
						  (__u8 *)NODEPORT_MAC,
						  SRC_IPV4, NODEPORT_IPV4,
						  SRC_PORT, NODEPORT_PORT);
	else
		l4 = pktgen__push_ipv6_tcp_packet(&builder,
						  (__u8 *)SRC_MAC, (__u8 *)NODEPORT_MAC,
						  (__u8 *)SRC_IPV6,
						  (__u8 *)NODEPORT_IPV6,
						  SRC_PORT, NODEPORT_PORT);

	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/*
 * Setup scenario where NODEPORT_IP is receiving nodeport traffic from SRC_IP
 * that needs to be redirected to DST_IP on node with IP DST_TUNNEL:
 *
 *     SRC_IP -> NODEPORT_IP:NODEPORT_PORT -> DST_IP:DST_PORT
 *
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

	/*
	 * NodePort services get the following IPs added into the map:
	 *
	 *     1. 0.0.0.0 and/or ::
	 *     2. IP of the node
	 *     3. ClusterIP of the service
	 *
	 * For this scenario, we'll just add the IP of the nodeport node
	 * and generate packets with that destination address.
	 */

	if (v4) {
		lb_v4_add_service(NODEPORT_IPV4, NODEPORT_PORT, 1, 1);
		lb_v4_add_backend(NODEPORT_IPV4, NODEPORT_PORT, 1, 124,
				  DST_IPV4, DST_PORT, IPPROTO_TCP, 0);
		ipcache_v4_add_entry_with_flags(DST_IPV4,
						0, 1230, DST_TUNNEL_IP, 0, flag_skip_tunnel);
	} else {
		lb_v6_add_service((union v6addr *)NODEPORT_IPV6, NODEPORT_PORT, 1, 1);
		lb_v6_add_backend((union v6addr *)NODEPORT_IPV6, NODEPORT_PORT, 1, 123,
				  (union v6addr *)DST_IPV6, DST_PORT, IPPROTO_TCP, 0);
		ipcache_v6_add_entry_with_flags((union v6addr *)DST_IPV6,
						0, 1230, DST_TUNNEL_IP, 0, flag_skip_tunnel);
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

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds")

	if (v4 && l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 proto hasn't been set to ETH_P_IP")

	if (!v4 && l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IPV6")

	if (memcmp(l2->h_source, (__u8 *)SRC_MAC, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to source ep's mac");

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
		 * The value of the source address changes depending on if we are sending
		 * through a tunnel.
		 */

		if (expected_result == CTX_ACT_REDIRECT && l3->saddr != IPV4_GATEWAY)
			test_fatal("src IP was not changed to IPV4_GATEWAY");

		if (expected_result == CTX_ACT_DROP && l3->saddr != IPV4_DIRECT_ROUTING)
			test_fatal("src IP was not changed to IPV4_DIRECT_ROUTING");

		if (l3->daddr != DST_IPV4)
			test_fatal("dest IP was not dnatted");

		l4 = (void *)l3 + sizeof(struct iphdr);
	} else {
		struct ipv6hdr *l3;

		l3 = (void *)l2 + sizeof(struct ethhdr);

		if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
			test_fatal("l3 out of bounds");

		if (expected_result == CTX_ACT_REDIRECT) {
			union v6addr router_ip;

			BPF_V6(router_ip, ROUTER_IP);

			if (memcmp((__u8 *)&l3->saddr, &router_ip, 16) != 0)
				test_fatal("src IP was not changed to IPV6_GATEWAY");
		}

		if (expected_result == CTX_ACT_DROP &&
		    memcmp((__u8 *)&l3->saddr, &((union v6addr)IPV6_DIRECT_ROUTING), 16) != 0) {
			test_fatal("src IP was not changed to IPV6_DIRECT_ROUTING")
		}

		if (memcmp((__u8 *)&l3->daddr, (__u8 *)DST_IPV6, 16) != 0)
			test_fatal("dest IP was not dnatted");

		l4 = (void *)l3 + sizeof(struct ipv6hdr);
	}

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	/*
	 * The SNAT stack prefers to reuse the source port of the packet for SNAT if the port is
	 * available for use and in the range [NODEPORT_PORT_MIN_NAT, NODEPORT_PORT_MAX_NAT].
	 * If the port is not available, or not in the NAT range, then the source port will be
	 * mapped to an available port in the NAT range.
	 *
	 * In our case, there are no existing SNAT mappings, but the source port of our generated
	 * packet does not fall within the NAT range. This is why we assert that the source port
	 * changes. If the value of SRC_PORT changes to fall within the NAT range, then this
	 * assertion will fail, as it relies on SRC_PORT being outside of the NAT range.
	 */
	if (l4->source == SRC_PORT)
		test_fatal("src TCP port was not snatted");

	if (l4->dest != DST_PORT)
		test_fatal("dest TCP port was not dnatted");

	payload = (void *)l4 + sizeof(struct tcphdr);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("payload out of bounds");

	if (memcmp(payload, default_data, sizeof(default_data)) != 0)
		test_fatal("tcp payload was changed")

	test_finish();
}

PKTGEN("tc", "01_ipv4_nodeport_egress_no_flags")
int ipv4_nodeport_egress_no_flags_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, true);
}

SETUP("tc", "01_ipv4_nodeport_egress_no_flags")
int ipv4_nodeport_egress_no_flags_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, true, false);
}

CHECK("tc", "01_ipv4_nodeport_egress_no_flags")
int ipv4_nodeport_egress_no_flags_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, true, CTX_ACT_REDIRECT);
}

PKTGEN("tc", "02_ipv4_nodeport_egress_skip_tunnel")
int ipv4_nodeport_egress_skip_tunnel_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, true);
}

SETUP("tc", "02_ipv4_nodeport_egress_skip_tunnel")
int ipv4_nodeport_egress_skip_tunnel_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, true, true);
}

CHECK("tc", "02_ipv4_nodeport_egress_skip_tunnel")
int ipv4_nodeport_egress_skip_tunnel_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, true, CTX_ACT_DROP);
}

PKTGEN("tc", "03_ipv6_nodeport_egress_no_flags")
int ipv6_nodeport_egress_no_flags_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, false);
}

SETUP("tc", "03_ipv6_nodeport_egress_no_flags")
int ipv6_nodeport_egress_no_flags_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, false, false);
}

CHECK("tc", "03_ipv6_nodeport_egress_no_flags")
int ipv6_nodeport_egress_no_flags_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, false, CTX_ACT_REDIRECT);
}

PKTGEN("tc", "04_ipv6_nodeport_egress_skip_tunnel")
int ipv6_nodeport_egress_skip_tunnel_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, false);
}

SETUP("tc", "04_ipv6_nodeport_egress_skip_tunnel")
int ipv6_nodeport_egress_skip_tunnel_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, false, true);
}

CHECK("tc", "04_ipv6_nodeport_egress_skip_tunnel")
int ipv6_nodeport_egress_skip_tunnel_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, false, CTX_ACT_DROP);
}
