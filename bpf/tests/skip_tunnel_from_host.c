// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/*
 * Test Matrix:
 * This file tests the interaction between skip_tunnel flag and subnet-based routing.
 *
 * | IP Type | skip_tunnel_flag | Source Subnet ID | Dest Subnet ID | Expected Result   |
 * |---------|------------------|------------------|----------------|-------------------|
 * | v4      | true             | 100              | 100            | CTX_ACT_OK        |
 * | v4      | true             | 100              | 101            | CTX_ACT_OK        |
 * | v4      | false            | 100              | 100            | CTX_ACT_OK        |
 * | v4      | false            | 100              | 101            | CTX_ACT_REDIRECT  |
 * | v6      | true             | 100              | 100            | CTX_ACT_OK        |
 * | v6      | true             | 100              | 101            | CTX_ACT_OK        |
 * | v6      | false            | 100              | 100            | CTX_ACT_OK        |
 * | v6      | false            | 100              | 101            | CTX_ACT_REDIRECT  |
 *
 * Key behaviors:
 * - When skip_tunnel=true: Always skip tunneling (CTX_ACT_OK)
 * - When skip_tunnel=false and same subnet: Skip tunneling (CTX_ACT_OK)
 * - When skip_tunnel=false and different subnet: Use tunnel (CTX_ACT_REDIRECT)
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/*
 * Datapath configuration settings to setup tunneling with VXLan
 */
#define ENCAP_IFINDEX 1  /* Set dummy ifindex for tunnel device */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define TUNNEL_MODE

/*
 * Test Configuration Settings
 * Simulate sending traffic from node_one to pod_two.
 *
 * cil_from_host will lead us to handle_ipv{4,6}_cont,
 * which rewrites the destination mac address to
 * cilium_net_mac to send the packet to the
 * cilium_net interface.
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

/*
 * Include entrypoint into host stack.
 */
#include "lib/bpf_host.h"

const union macaddr cilium_net_mac = { .addr = {0xce, 0x72, 0xa7, 0x03, 0x88, 0x57} };
ASSIGN_CONFIG(union macaddr, cilium_net_mac, cilium_net_mac)

#include "lib/eth.h"
#define DST_MAC CONFIG(cilium_net_mac).addr

/*
 * Include test helpers
 */
#include "lib/ipcache.h"
#include "lib/subnet.h"

ASSIGN_CONFIG(bool, hybrid_routing_enabled, true)

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

	map_delete_elem(&cilium_metrics, &key);

	if (v4)
		ipcache_v4_add_entry_with_flags(DST_IPV4,
						0, 1230, v4_node_two, 0, flag_skip_tunnel);
	else
		ipcache_v6_add_entry_with_flags((union v6addr *)DST_IPV6,
						0, 1230, v4_node_two, 0, flag_skip_tunnel);

	return host_send_packet(ctx);
}

static __always_inline void
setup_subnet_table_v4(__u32 src_id, __u32 dst_id)
{
	subnet_v4_add_entry(SRC_IPV4, src_id);
	subnet_v4_add_entry(DST_IPV4, dst_id);
}

static __always_inline void
setup_subnet_table_v6(__u32 src_id, __u32 dst_id)
{
	subnet_v6_add_entry((union v6addr *)SRC_IPV6, src_id);
	subnet_v6_add_entry((union v6addr *)DST_IPV6, dst_id);
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

		entry = map_lookup_elem(&cilium_metrics, &key);
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

		if (l3->check != bpf_htons(0xa611))
			test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

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

PKTGEN("tc", "05_ipv4_from_host_no_flags_same_subnet")
int ipv4_from_host_no_flags_same_subnet_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx, true);
}

SETUP("tc", "05_ipv4_from_host_no_flags_same_subnet")
int ipv4_from_host_no_flags_same_subnet_setup(struct __ctx_buff *ctx)
{
	setup_subnet_table_v4(100, 100);
	return setup(ctx, false, true);
}

CHECK("tc", "05_ipv4_from_host_no_flags_same_subnet")
int ipv4_from_host_no_flags_same_subnet_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, CTX_ACT_OK, true);
}

PKTGEN("tc", "06_ipv4_from_host_skip_tunnel_same_subnet")
int ipv4_from_host_skip_tunnel_same_subnet_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx, true);
}

SETUP("tc", "06_ipv4_from_host_skip_tunnel_same_subnet")
int ipv4_from_host_skip_tunnel_same_subnet_setup(struct __ctx_buff *ctx)
{
	setup_subnet_table_v4(100, 100);
	return setup(ctx, true, true);
}

CHECK("tc", "06_ipv4_from_host_skip_tunnel_same_subnet")
int ipv4_from_host_skip_tunnel_same_subnet_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, CTX_ACT_OK, true);
}

PKTGEN("tc", "07_ipv4_from_host_no_flags_different_subnet")
int ipv4_from_host_no_flags_different_subnet_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx, true);
}

SETUP("tc", "07_ipv4_from_host_no_flags_different_subnet")
int ipv4_from_host_no_flags_different_subnet_setup(struct __ctx_buff *ctx)
{
	setup_subnet_table_v4(100, 101);
	return setup(ctx, false, true);
}

CHECK("tc", "07_ipv4_from_host_no_flags_different_subnet")
int ipv4_from_host_no_flags_different_subnet_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, CTX_ACT_REDIRECT, true);
}

PKTGEN("tc", "08_ipv4_from_host_skip_tunnel_different_subnet")
int ipv4_from_host_skip_tunnel_different_subnet_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx, true);
}

SETUP("tc", "08_ipv4_from_host_skip_tunnel_different_subnet")
int ipv4_from_host_skip_tunnel_different_subnet_setup(struct __ctx_buff *ctx)
{
	setup_subnet_table_v4(100, 101);
	return setup(ctx, true, true);
}

CHECK("tc", "08_ipv4_from_host_skip_tunnel_different_subnet")
int ipv4_from_host_skip_tunnel_different_subnet_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, CTX_ACT_OK, true);
}

PKTGEN("tc", "09_ipv6_from_host_no_flags_same_subnet")
int ipv6_from_host_no_flags_same_subnet_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx, false);
}

SETUP("tc", "09_ipv6_from_host_no_flags_same_subnet")
int ipv6_from_host_no_flags_same_subnet_setup(struct __ctx_buff *ctx)
{
	setup_subnet_table_v6(100, 100);
	return setup(ctx, false, false);
}

CHECK("tc", "09_ipv6_from_host_no_flags_same_subnet")
int ipv6_from_host_no_flags_same_subnet_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, CTX_ACT_OK, false);
}

PKTGEN("tc", "10_ipv6_from_host_no_flags_different_subnet")
int ipv6_from_host_no_flags_different_subnet_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx, false);
}

SETUP("tc", "10_ipv6_from_host_no_flags_different_subnet")
int ipv6_from_host_no_flags_different_subnet_setup(struct __ctx_buff *ctx)
{
	setup_subnet_table_v6(100, 101);
	return setup(ctx, false, false);
}

CHECK("tc", "10_ipv6_from_host_no_flags_different_subnet")
int ipv6_from_host_no_flags_different_subnet_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, CTX_ACT_REDIRECT, false);
}

PKTGEN("tc", "11_ipv6_from_host_skip_tunnel_same_subnet")
int ipv6_from_host_same_subnet_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx, false);
}

SETUP("tc", "11_ipv6_from_host_skip_tunnel_same_subnet")
int ipv6_from_host_same_subnet_setup(struct __ctx_buff *ctx)
{
	setup_subnet_table_v6(100, 100);
	return setup(ctx, true, false);
}

CHECK("tc", "11_ipv6_from_host_skip_tunnel_same_subnet")
int ipv6_from_host_same_subnet_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, CTX_ACT_OK, false);
}

PKTGEN("tc", "12_ipv6_from_host_skip_tunnel_different_subnet")
int ipv6_from_host_skip_tunnel_different_subnet_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx, false);
}

SETUP("tc", "12_ipv6_from_host_skip_tunnel_different_subnet")
int ipv6_from_host_skip_tunnel_different_subnet_setup(struct __ctx_buff *ctx)
{
	setup_subnet_table_v6(100, 101);
	return setup(ctx, true, false);
}

CHECK("tc", "12_ipv6_from_host_skip_tunnel_different_subnet")
int ipv6_from_host_skip_tunnel_different_subnet_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_ctx(ctx, CTX_ACT_OK, false);
}
