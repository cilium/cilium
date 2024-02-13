// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */
#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"

/*
 * Datapath configuration settings to setup tunneling with VXLan
 */
#define ENCAP_IFINDEX 1  /* Set dummy ifindex for tunnel device */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define TUNNEL_MODE

/*
 * Now include testing defaults
 */
#define ROUTER_IP
#include "config_replacement.h"
#undef ROUTER_IP
#include "node_config.h"

/*
 * Test Configuration Settings
 * Simulate sending traffic from node_one to pod_two.
 *
 * cil_from_host will lead us to handle_ipv{4,6}_cont,
 * which rewrites the destination mac address to
 * CIILUM_NET_MAC to send the packet to the
 * cilium_net interface.
 *
 * CILIUM_NET_MAC is set in node_config.h, so below we pull
 * it into a format that pktgen can use.
 */
#define SRC_MAC mac_one
#define SRC_IPV4 v4_node_one
#define SRC_IPV6 v6_node_one
#define SRC_TCP_PORT tcp_src_one
#define DST_IPV4 v4_pod_two
#define DST_IPV6 v6_pod_two
#define DST_TCP_PORT tcp_svc_one
#define TUNNEL_IPV4 v4_node_two
#define TUNNEL_IPV6 v6_node_two

#include "lib/eth.h"
static volatile const union macaddr __cilium_net_mac = CILIUM_NET_MAC;
#define DST_MAC __cilium_net_mac.addr

/*
 * Include entrypoint into host stack.
 */
#include "bpf_host.c"

/*
 * Include test helpers
 */
#include "lib/ipcache.h"
#include "lib/policy.h"

#define FROM_HOST 0
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_HOST] = &cil_from_host,
	},
};

static __always_inline int
pktgen_from_host(struct __ctx_buff *ctx, bool v4)
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
						  SRC_TCP_PORT, DST_TCP_PORT);
	else
		l4 = pktgen__push_ipv6_tcp_packet(&builder,
						  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
						  (__u8 *)SRC_IPV6, (__u8 *)DST_IPV6,
						  SRC_TCP_PORT, DST_TCP_PORT);

	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
setup(struct __ctx_buff *ctx, bool flag_skip_tunnel, bool v4)
{
	/*
	 * Reset metric values before the test, if applicable.
	 * Otherwise, the metric we want to check would increase by one
	 * after each test.
	 */
	struct metrics_key key = {};

	key.reason = REASON_FORWARDED;
	key.dir = METRIC_EGRESS;

	map_delete_elem(&METRICS_MAP, &key);

	policy_add_egress_allow_all_entry();

	if (v4)
		ipcache_v4_add_entry_with_flags(DST_IPV4,
						0, 1230, v4_node_two, 0, flag_skip_tunnel);
	else
		ipcache_v6_add_entry_with_flags((union v6addr *)DST_IPV6,
						0, 1230, v4_node_two, 0, flag_skip_tunnel);

	tail_call_static(ctx, entry_call_map, FROM_HOST);
	return TEST_ERROR;
}

static __always_inline int
check_ctx(const struct __ctx_buff *ctx, __u32 expected_result, bool v4)
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
	 * If flag_skip_tunnel=true, then we need CTX_ACT_OK
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

	if (memcmp(l2->h_source, (__u8 *)SRC_MAC, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to source ep's mac");

	if (memcmp(l2->h_dest, (__u8 *)DST_MAC, ETH_ALEN) != 0)
		test_fatal("dst mac hasn't been set to dest ep's mac")

	if (v4) {
		struct iphdr *l3;

		l3 = (void *)l2 + sizeof(struct ethhdr);

		if ((void *)l3 + sizeof(struct iphdr) > data_end)
			test_fatal("l3 out of bounds");

		if (l3->saddr != SRC_IPV4)
			test_fatal("src IP was changed");

		if (l3->daddr != DST_IPV4)
			test_fatal("dest IP was changed");

		l4 = (void *)l3 + sizeof(struct iphdr);
	} else {
		struct ipv6hdr *l3;

		l3 = (void *)l2 + sizeof(struct ethhdr);

		if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
			test_fatal("l3 out of bounds");

		if (memcmp((__u8 *)&l3->saddr, (__u8 *)SRC_IPV6, 16) != 0)
			test_fatal("src IP was changed");

		if (memcmp((__u8 *)&l3->daddr, (__u8 *)DST_IPV6, 16) != 0)
			test_fatal("dest IP was changed");

		l4 = (void *)l3 + sizeof(struct ipv6hdr);
	}

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != SRC_TCP_PORT)
		test_fatal("src TCP port was changed");

	if (l4->dest != DST_TCP_PORT)
		test_fatal("dest TCP port was changed");

	payload = (void *)l4 + sizeof(struct tcphdr);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("payload out of bounds");

	if (memcmp(payload, default_data, sizeof(default_data)) != 0)
		test_fatal("tcp payload was changed")

	test_finish();
}

PKTGEN("tc", "01_ipv4_from_host_no_flags")
int ipv4_from_host_no_flags_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx, true);
}

SETUP("tc", "01_ipv4_from_host_no_flags")
int ipv4_from_host_no_flags_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, false, true);
}

CHECK("tc", "01_ipv4_from_host_no_flags")
int ipv4_from_host_no_flags_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, CTX_ACT_REDIRECT, true);
}

PKTGEN("tc", "02_ipv4_from_host_skip_tunnel")
int ipv4_from_host_skip_tunnel_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx, true);
}

SETUP("tc", "02_ipv4_from_host_skip_tunnel")
int ipv4_from_host_skip_tunnel_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, true, true);
}

CHECK("tc", "02_ipv4_from_host_skip_tunnel")
int ipv4_from_host_skip_tunnel_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, CTX_ACT_OK, true);
}

PKTGEN("tc", "03_ipv6_from_host_no_flags")
int ipv6_from_host_no_flags_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx, false);
}

SETUP("tc", "03_ipv6_from_host_no_flags")
int ipv6_from_host_no_flags_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, false, false);
}

CHECK("tc", "03_ipv6_from_host_no_flags")
int ipv6_from_host_no_flags_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, CTX_ACT_REDIRECT, false);
}

PKTGEN("tc", "04_ipv6_from_host_skip_tunnel")
int ipv6_from_host_skip_tunnel_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx, false);
}

SETUP("tc", "04_ipv6_from_host_skip_tunnel")
int ipv6_from_host_skip_tunnel_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, true, false);
}

CHECK("tc", "04_ipv6_from_host_skip_tunnel")
int ipv6_from_host_skip_tunnel_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, CTX_ACT_OK, false);
}
