// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
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
#define ENABLE_MASQUERADE_IPV4 1
#define ENABLE_MASQUERADE_IPV6 1

/*
 * Simulate sending traffic from pod_one on node_one directly to
 * node_two. Tests are written from the perspective of node_one,
 * allowing us access to nodeport_snat_fwd_ipv{4,6}.
 */
#define SRC_MAC mac_one
#define SRC_IPV4 v4_pod_one
#define SRC_IPV6 v6_pod_one
#define SRC_PORT tcp_src_one
#define DST_MAC mac_three
#define DST_IPV4 v4_node_two
#define DST_IPV6 v6_node_two
#define DST_PORT tcp_svc_one

/*
 * Include entrypoint into host stack
 */
#include "bpf_host.c"

ASSIGN_CONFIG(union v6addr, nat_ipv6_masquerade, {.addr = v6_node_one_addr})

/*
 * Include test helpers
 */
#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"
#include "lib/clear.h"

#define TO_NETDEV 0
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
						  (__u8 *)DST_MAC,
						  SRC_IPV4, DST_IPV4,
						  SRC_PORT, DST_PORT);
	else
		l4 = pktgen__push_ipv6_tcp_packet(&builder,
						  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
						  (__u8 *)SRC_IPV6,
						  (__u8 *)DST_IPV6,
						  SRC_PORT, DST_PORT);

	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/*
 * Setup scenario where pod with SRC_IP on node is sending traffic directly
 * to a remote node with the address DST_IP. In the case of tunnel mode where
 * flag_skip_tunnel=true, bpf masquerading should be skipped.
 */
static __always_inline int
setup(struct __ctx_buff *ctx, bool v4, bool flag_skip_tunnel)
{
	/*
	 * Reset maps before the test.
	 * Otherwise, leftover state from previous tests will have an impact,
	 * as the tests and checks assume we have a fresh state every time.
	 */
	clear_map(&cilium_metrics);
	clear_map(&cilium_ct4_global);
	clear_map(&cilium_ct6_global);
	clear_map(get_cluster_snat_map_v4(0));
	clear_map(get_cluster_snat_map_v6(0));

	policy_add_egress_allow_all_entry();

	/*
	 * For this scenario, an endpoint for the source addresses needs
	 * to be created. Additionally, the destination's security identity in the ipcache
	 * must reflect that it is a remote node. This information is used by the SNAT stack to
	 * determine if SNAT needs to be performed for the given packet. See snat_v{4,6}_needs_masquerade.
	 */

	if (v4) {
		endpoint_v4_add_entry(SRC_IPV4, 0, 0, 0, 0, 0, (__u8 *)SRC_MAC, (__u8 *)SRC_MAC);
		ipcache_v4_add_entry_with_flags(DST_IPV4,
						0, REMOTE_NODE_ID, 0,
						0, flag_skip_tunnel);
	} else {
		endpoint_v6_add_entry((union v6addr *)SRC_IPV6, 0, 0, 0, 0,
				      (__u8 *)SRC_MAC, (__u8 *)SRC_MAC);
		ipcache_v6_add_entry_with_flags((union v6addr *)DST_IPV6,
						0, REMOTE_NODE_ID, 0,
						0, flag_skip_tunnel);
	}

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

static __always_inline int
check_ctx(const struct __ctx_buff *ctx, bool v4, bool snat)
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

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	key.reason = REASON_FORWARDED;
	key.dir = METRIC_EGRESS;

	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found")

	__u64 count = 1;

	assert_metrics_count(key, count);

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds")

	if (v4 && l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 proto hasn't been set to ETH_P_IP")

	if (!v4 && l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IPV6")

	if (memcmp(l2->h_source, (__u8 *)SRC_MAC, ETH_ALEN) != 0)
		test_fatal("src mac was changed");

	if (memcmp(l2->h_dest, (__u8 *)DST_MAC, ETH_ALEN) != 0)
		test_fatal("dst mac has changed")

	if (v4) {
		struct iphdr *l3;

		l3 = (void *)l2 + sizeof(struct ethhdr);

		if ((void *)l3 + sizeof(struct iphdr) > data_end)
			test_fatal("l3 out of bounds");

		if (snat) {
			if (l3->saddr != CONFIG(nat_ipv4_masquerade).be32)
				test_fatal("src IP was not snatted");
		} else {
			if (l3->saddr != SRC_IPV4)
				test_fatal("src IP was changed");
		}

		if (l3->daddr != DST_IPV4)
			test_fatal("dest IP was changed");

		l4 = (void *)l3 + sizeof(struct iphdr);
	} else {
		struct ipv6hdr *l3;
		union v6addr masq_addr = CONFIG(nat_ipv6_masquerade);

		l3 = (void *)l2 + sizeof(struct ethhdr);

		if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
			test_fatal("l3 out of bounds");

		if (snat) {
			if (memcmp((__u8 *)&l3->saddr, (__u8 *)&masq_addr, 16) != 0)
				test_fatal("src IP was not snatted");
		} else {
			if (memcmp((__u8 *)&l3->saddr, (__u8 *)SRC_IPV6, 16) != 0)
				test_fatal("src IP was changed");
		}

		if (memcmp((__u8 *)&l3->daddr, (__u8 *)DST_IPV6, 16) != 0)
			test_fatal("dest IP was changed");

		l4 = (void *)l3 + sizeof(struct ipv6hdr);
	}

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (snat) {
		__be16 p = bpf_ntohs(l4->source);

#ifdef ENABLE_DUAL_PORT_RANGE
		bool in_range1 = (p >= NODEPORT_PORT_NAT_IPV4_RANGE1_MIN &&
				  p <= NODEPORT_PORT_NAT_IPV4_RANGE1_MAX);
		bool in_range2 = (p >= NODEPORT_PORT_NAT_IPV4_RANGE2_MIN &&
				  p <= NODEPORT_PORT_NAT_IPV4_RANGE2_MAX);
    	if (!(in_range1 || in_range2))
        	test_fatal("src port was not snatted into the correct NodePort masquerade ranges");
#else
		if (p < NODEPORT_PORT_MIN_NAT || p > NODEPORT_PORT_MAX_NAT)
			test_fatal("src port was not snatted");
#endif
	} else {
		if (l4->source != SRC_PORT)
			test_fatal("src port was changed");
	}

	if (l4->dest != DST_PORT)
		test_fatal("dest port was changed");

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
	return check_ctx(ctx, true, true);
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
	return check_ctx(ctx, true, false);
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
	return check_ctx(ctx, false, true);
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
	return check_ctx(ctx, false, false);
}
