// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

/* Prepare the config for the test */
#define ENABLE_SCTP
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define IS_BPF_HOST 1
#define ENABLE_BPF_MASQUERADE 1
#define ENABLE_MASQUERADE_IPV4 1
#define ENABLE_MASQUERADE_IPV6 1

#include <bpf/config/node.h>
#include <bpf/config/global.h>

#define DEBUG

#include <lib/eps.h>

/* Ensure lookups treat src as local endpoint */
static struct endpoint_info mocked_local_ep = {};
#undef __lookup_ip4_endpoint
#define __lookup_ip4_endpoint(addr) (&mocked_local_ep)
#undef __lookup_ip6_endpoint
#define __lookup_ip6_endpoint(addr) (&mocked_local_ep)

/* No remote endpoint specifics needed for this test */
#undef lookup_ip4_remote_endpoint
#define lookup_ip4_remote_endpoint(addr, cluster_id) (NULL)
#undef lookup_ip6_remote_endpoint
#define lookup_ip6_remote_endpoint(addr, cluster_id) (NULL)

#include <lib/dbg.h>
#include <lib/time.h>
#include "bpf_nat_tuples.h"
#include <lib/conntrack.h>
#include <lib/nat.h>
#include <lib/common.h>

/*
 * Test: SNAT source exclusion (IPv4 + IPv6)
 * Validate that egress flows whose source IP matches configured exclusion CIDRs
 * are not subject to SNAT.
 *
 * Program cilium_nat_exclusion_v4 with 10.0.0.0/8
 * and cilium_nat_exclusion_v6 with fd00::/8.
 * Build minimal tuples and call snat_v{4,6}_needs_masquerade() for two
 * scenarios per family:
 * 1) Source inside exclusion -> expect NAT_PUNT_TO_STACK
 * 2) Source outside exclusion -> expect NAT_NEEDED.
 */

/* IPv4 /8 exclusion: 10.0.0.0/8 */
#define EXCL_V4_PREFIX 8
#define EXCL_V4_ADDR   bpf_htonl(0x0A000000)

/* IPv6 /8-like prefix: fd00::/8 */
static const __u8 excl_v6_addr[16] = { 0xfd, 0x00, 0 }; /* rest zero by default */
#define EXCL_V6_PREFIX 8

static __always_inline void insert_nat_excl_v4(__be32 addr, __u8 prefix)
{
	struct lpm_v4_key k = { .lpm = { prefix, {} }, .addr = { 0 } };
	/* Add IPv4 source-exclusion prefix key */
	memcpy(k.addr, &addr, 4);
	struct lpm_val v = { .flags = 0 };

	map_update_elem(&cilium_nat_exclusion_v4, &k, &v, 0);
}

#ifdef ENABLE_IPV6
static __always_inline void insert_nat_excl_v6(const __u8 addr[16], __u8 prefix)
{
	struct lpm_v6_key k = { .lpm = { prefix, {} }, .addr = { 0 } };
	/* Add IPv6 source-exclusion prefix key */
	memcpy(k.addr + 0,  addr + 0,  4);
	memcpy(k.addr + 4,  addr + 4,  4);
	memcpy(k.addr + 8,  addr + 8,  4);
	memcpy(k.addr + 12, addr + 12, 4);
	struct lpm_val v = { .flags = 0 };

	map_update_elem(&cilium_nat_exclusion_v6, &k, &v, 0);
}
#endif

CHECK("tc", "nat_src_exclusion_v4_test")
int test_nat_src_exclusion_v4(__maybe_unused struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	struct iphdr ip4 = { .protocol = IPPROTO_TCP };
	fraginfo_t fraginfo = 0;
	int l4_off = 0;
	int ret;

	test_init();

	/* Program the source-exclusion CIDR for IPv4 (10.0.0.0/8). All egress
	 * flows whose source is within this prefix must not be SNATed by
	 * snat_v4_needs_masquerade().
	 */
	insert_nat_excl_v4(EXCL_V4_ADDR, EXCL_V4_PREFIX);

	/* Case 1 (IPv4): source within exclusion -> no SNAT
	 * - Source 10.1.2.3 is in 10.0.0.0/8
	 * - Destination is some remote address.
	 * - Expectation: NAT_PUNT_TO_STACK
	 */
	tuple.saddr = bpf_htonl(0x0A010203); /* 10.1.2.3 */
	tuple.daddr = bpf_htonl(0x02020202); /* remote */
	tuple.nexthdr = IPPROTO_TCP;
	tuple.sport = bpf_htons(12345);
	tuple.dport = bpf_htons(80);
	tuple.flags = NAT_DIR_EGRESS;

	struct ipv4_nat_target target1 = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.addr = 0,
		.from_local_endpoint = false,
		.egress_gateway = false,
		.needs_ct = false,
		.ifindex = 0,
	};

	ret = snat_v4_needs_masquerade(ctx, &tuple, &ip4, fraginfo, l4_off, &target1);
	assert(ret == NAT_PUNT_TO_STACK);
	assert(target1.addr == 0);

	/* Case 2 (IPv4): source outside exclusion -> SNAT is needed
	 * - Source 192.168.1.100 is not in 10.0.0.0/8
	 * Expectation: NAT_NEEDED
	 */
	tuple.saddr = bpf_htonl(0xC0A80164); /* 192.168.1.100 */

	/* Clone target, reuse same config. */
	struct ipv4_nat_target target2 = target1;

	ret = snat_v4_needs_masquerade(ctx, &tuple, &ip4, fraginfo, l4_off, &target2);
	assert(ret == NAT_NEEDED);

	test_finish();
	return 0;
}

#ifdef ENABLE_IPV6
CHECK("tc", "nat_src_exclusion_v6_test")
int test_nat_src_exclusion_v6(__maybe_unused struct __ctx_buff *ctx)
{
	struct ipv6_ct_tuple tuple = {};
	struct ipv6hdr ip6 = { .nexthdr = IPPROTO_TCP };
	fraginfo_t fraginfo = 0;
	int l4_off = 0;
	int ret;

	test_init();

	/* Program the source-exclusion CIDR for IPv6 (fd00::/8). Egress flows with
	 * source in this prefix must not be SNATed.
	 */
	insert_nat_excl_v6(excl_v6_addr, EXCL_V6_PREFIX);

	/* Case 1 (IPv6): source within exclusion -> no SNAT
	 * - Source fd00::1 is in fd00::/8
	 * - Destination is some remote address.
	 * Expectation: NAT_PUNT_TO_STACK
	 */
	tuple.saddr.addr[0] = 0xfd;
	/* Destination set to a non-local/remote address to exercise egress path. */
	tuple.daddr.addr[15] = 0x1;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.sport = bpf_htons(12345);
	tuple.dport = bpf_htons(443);
	tuple.flags = NAT_DIR_EGRESS;

	struct ipv6_nat_target target1 = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.addr = {},
		.from_local_endpoint = false,
		.egress_gateway = false,
		.needs_ct = false,
		.ifindex = 0,
	};

	ret = snat_v6_needs_masquerade(ctx, &tuple, &ip6, fraginfo, l4_off, &target1);
	assert(ret == NAT_PUNT_TO_STACK);

	/* Case 2 (IPv6): source outside exclusion -> SNAT is needed
	 * - Source 2001:db8::1 is not in fd00::/8
	 * - Expectation: NAT_NEEDED
	 */
	memset(&tuple.saddr, 0, sizeof(tuple.saddr));
	tuple.saddr.addr[0] = 0x20;
	tuple.saddr.addr[1] = 0x01;
	tuple.saddr.addr[2] = 0x0d;
	tuple.saddr.addr[3] = 0xb8;

	/* Clone target, reuse same config. */
	struct ipv6_nat_target target2 = target1;

	ret = snat_v6_needs_masquerade(ctx, &tuple, &ip6, fraginfo, l4_off, &target2);
	assert(ret == NAT_NEEDED);

	test_finish();
	return 0;
}
#endif

BPF_LICENSE("Dual BSD/GPL");
