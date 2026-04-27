// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/*
 * Tests for the NAT excluded-ports feature:
 *   - __nat_excluded_port() helper (tunnel and wireguard paths)
 *   - snat_v4_new_mapping() never selects an excluded port
 *   - snat_v6_new_mapping() never selects an excluded port
 *
 * Strategy: enable TUNNEL_MODE and assign a known tunnel_port (EXCLUDED_PORT)
 * that falls inside the narrow SNAT range [TEST_MIN_PORT, TEST_MAX_PORT].
 * Allocate ALLOC_ITERS mappings and assert that EXCLUDED_PORT is never chosen
 * as the SNAT source port.
 */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"
#include "lib/clear.h"

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define TUNNEL_MODE 1
#define ENABLE_WIREGUARD 1
#include <bpf/config/global.h>

#include "nodeport_defaults.h"

#define DEBUG
#include <lib/dbg.h>
#include <lib/nat.h>

/* ── test parameters ─────────────────────────────────────────────────────── */

/* Narrow SNAT range: [32768, 32868] — 101 ports total. */
#define TEST_MIN_PORT  32768
#define TEST_MAX_PORT  32868

/*
 * The tunnel port that must never be selected.  We reuse the tunnel_port
 * config to inject this value so that __nat_excluded_port() returns true for
 * it without needing a separate runtime-configurable excluded-ports array.
 */
#define EXCLUDED_TUNNEL_PORT  32800

/*
 * The WireGuard port that must never be selected.
 */
#define EXCLUDED_WG_PORT      32820

ASSIGN_CONFIG(__u16, tunnel_port, EXCLUDED_TUNNEL_PORT)
ASSIGN_CONFIG(__u16, wg_port, EXCLUDED_WG_PORT)

/* Number of allocations to perform. */
#define ALLOC_ITERS    25

/* ── helpers ─────────────────────────────────────────────────────────────── */

/* IPv4 SNAT address used in all v4 tests. */
#define SNAT_ADDR_V4  bpf_htonl(0x0A000101) /* 10.0.1.1 */

#define SNAT_ERR "snat_v%d_new_mapping: ret=%d err=%d i=%u"

/* ── __nat_excluded_port unit tests ─────────────────────────────────────── */

/*
 * Directly exercise __nat_excluded_port() for both the tunnel port and the
 * WireGuard port (which must be excluded) and a selection of ports that must
 * NOT be excluded.
 */
CHECK("tc", "nat_excluded_ports_helper")
int test_nat_excluded_ports_helper_check(const struct __ctx_buff *ctx)
{
	(void)ctx;
	test_init();

	/* The tunnel port must be recognised as excluded. */
	assert(__nat_excluded_port(EXCLUDED_TUNNEL_PORT));

	/* The WireGuard port must be recognised as excluded. */
	assert(__nat_excluded_port(EXCLUDED_WG_PORT));

	/* Ports just below and above the excluded ports must be allowed. */
	assert(!__nat_excluded_port(EXCLUDED_TUNNEL_PORT - 1));
	assert(!__nat_excluded_port(EXCLUDED_TUNNEL_PORT + 1));
	assert(!__nat_excluded_port(EXCLUDED_WG_PORT - 1));
	assert(!__nat_excluded_port(EXCLUDED_WG_PORT + 1));

	/* Boundary ports of the SNAT range must be allowed. */
	assert(!__nat_excluded_port(TEST_MIN_PORT));
	assert(!__nat_excluded_port(TEST_MAX_PORT));

	/* Well-known ports outside the SNAT range must be allowed. */
	assert(!__nat_excluded_port(6081));  /* Geneve (not our tunnel_port) */
	assert(!__nat_excluded_port(0));
	assert(!__nat_excluded_port(65535));

	test_finish();
}

/* ── snat_v4_new_mapping exclusion ──────────────────────────────────────── */

CHECK("tc", "nat4_excluded_port_never_selected")
int test_nat4_excluded_port_never_selected_check(struct __ctx_buff *ctx)
{
	test_init();

	clear_map(get_cluster_snat_map_v4(0));

	struct ipv4_nat_target target = {
		.addr      = SNAT_ADDR_V4,
		.min_port  = TEST_MIN_PORT,
		.max_port  = TEST_MAX_PORT,
		.needs_ct  = false,
	};

	for (__u16 i = 0; i < ALLOC_ITERS; i++) {
		struct ipv4_ct_tuple otuple = {
			.nexthdr = IPPROTO_UDP,
			.saddr   = bpf_htonl(0xC0A80001), /* 192.168.0.1 */
			.daddr   = bpf_htonl(0x08080808), /* 8.8.8.8 */
			.sport   = bpf_htons(1024 + i),
			.dport   = bpf_htons(53),
			.flags   = NAT_DIR_EGRESS,
		};
		struct ipv4_nat_entry ostate;
		__s8 ext_err = 0;

		int ret = snat_v4_new_mapping(ctx, get_cluster_snat_map_v4(0),
					      &otuple, &ostate, &target,
					      false, &ext_err);
		if (ret != 0)
			test_fatal(SNAT_ERR, 4, ret, (__s32)ext_err, (__u32)i);

		__u16 chosen = bpf_ntohs(ostate.to_sport);

		assert(chosen >= TEST_MIN_PORT);
		assert(chosen <= TEST_MAX_PORT);

		if (chosen == EXCLUDED_TUNNEL_PORT)
			test_fatal("snat_v4_new_mapping chose excluded tunnel port %u",
				   EXCLUDED_TUNNEL_PORT);

		if (chosen == EXCLUDED_WG_PORT)
			test_fatal("snat_v4_new_mapping chose excluded wg port %u",
				   EXCLUDED_WG_PORT);
	}

	test_finish();
}

/* ── snat_v6_new_mapping exclusion ──────────────────────────────────────── */

CHECK("tc", "nat6_excluded_port_never_selected")
int test_nat6_excluded_port_never_selected_check(struct __ctx_buff *ctx)
{
	test_init();

	clear_map(get_cluster_snat_map_v6(0));

	union v6addr snat_addr = {};
	/* 2001:db8::1 */
	snat_addr.addr[0]  = 0x20; snat_addr.addr[1]  = 0x01;
	snat_addr.addr[2]  = 0x0d; snat_addr.addr[3]  = 0xb8;
	snat_addr.addr[15] = 0x01;

	union v6addr pod_addr = {};
	/* fc00::1 */
	pod_addr.addr[0] = 0xfc; pod_addr.addr[15] = 0x01;

	union v6addr world_addr = {};
	/* 2606:4700:4700::1111  (Cloudflare DNS) */
	world_addr.addr[0]  = 0x26; world_addr.addr[1]  = 0x06;
	world_addr.addr[2]  = 0x47; world_addr.addr[3]  = 0x00;
	world_addr.addr[4]  = 0x47; world_addr.addr[5]  = 0x00;
	world_addr.addr[14] = 0x11; world_addr.addr[15] = 0x11;

	struct ipv6_nat_target target = {
		.addr      = snat_addr,
		.min_port  = TEST_MIN_PORT,
		.max_port  = TEST_MAX_PORT,
		.needs_ct  = false,
	};

	for (__u16 i = 0; i < ALLOC_ITERS; i++) {
		struct ipv6_ct_tuple otuple = {
			.nexthdr = IPPROTO_UDP,
			.saddr   = pod_addr,
			.daddr   = world_addr,
			.sport   = bpf_htons(1024 + i),
			.dport   = bpf_htons(53),
			.flags   = NAT_DIR_EGRESS,
		};
		struct ipv6_nat_entry ostate;
		__s8 ext_err = 0;

		int ret = snat_v6_new_mapping(ctx, &otuple, &ostate, &target,
					      false, &ext_err);
		if (ret != 0)
			test_fatal(SNAT_ERR, 6, ret, (__s32)ext_err, (__u32)i);

		__u16 chosen = bpf_ntohs(ostate.to_sport);

		assert(chosen >= TEST_MIN_PORT);
		assert(chosen <= TEST_MAX_PORT);

		if (chosen == EXCLUDED_TUNNEL_PORT)
			test_fatal("snat_v6_new_mapping chose excluded tunnel port %u",
				   EXCLUDED_TUNNEL_PORT);

		if (chosen == EXCLUDED_WG_PORT)
			test_fatal("snat_v6_new_mapping chose excluded wg port %u",
				   EXCLUDED_WG_PORT);
	}

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
