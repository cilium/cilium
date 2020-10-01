/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2020 Authors of Cilium */

#include "lib/ipv6.h"
#include "lib/maps.h"

static void test_ipv6_addr_clear_suffix(void)
{
	union v6addr v6;

	memset(&v6, 0xff, sizeof(v6));
	ipv6_addr_clear_suffix(&v6, 128);
	assert(ntohl(v6.p1) == 0xffffffff);
	assert(ntohl(v6.p2) == 0xffffffff);
	assert(ntohl(v6.p3) == 0xffffffff);
	assert(ntohl(v6.p4) == 0xffffffff);

	memset(&v6, 0xff, sizeof(v6));
	ipv6_addr_clear_suffix(&v6, 127);
	assert(ntohl(v6.p1) == 0xffffffff);
	assert(ntohl(v6.p2) == 0xffffffff);
	assert(ntohl(v6.p3) == 0xffffffff);
	assert(ntohl(v6.p4) == 0xfffffffe);

	memset(&v6, 0xff, sizeof(v6));
	ipv6_addr_clear_suffix(&v6, 95);
	assert(ntohl(v6.p1) == 0xffffffff);
	assert(ntohl(v6.p2) == 0xffffffff);
	assert(ntohl(v6.p3) == 0xfffffffe);
	assert(ntohl(v6.p4) == 0x00000000);

	memset(&v6, 0xff, sizeof(v6));
	ipv6_addr_clear_suffix(&v6, 1);
	assert(ntohl(v6.p1) == 0x80000000);
	assert(ntohl(v6.p2) == 0x00000000);
	assert(ntohl(v6.p3) == 0x00000000);
	assert(ntohl(v6.p4) == 0x00000000);

	memset(&v6, 0xff, sizeof(v6));
	ipv6_addr_clear_suffix(&v6, -1);
	assert(ntohl(v6.p1) == 0x00000000);
	assert(ntohl(v6.p2) == 0x00000000);
	assert(ntohl(v6.p3) == 0x00000000);
	assert(ntohl(v6.p4) == 0x00000000);
}

static __be32 *dummy_map;

static __be32 match_dummy_prefix(const void *map, __be32 addr, __u32 prefix)
{
	return (addr & GET_PREFIX(prefix)) == *dummy_map;
}
#define PREFIX32 32,
#define PREFIX31 31,
#define PREFIX22 22,
#define PREFIX11 11,
#define PREFIX0  0,
LPM_LOOKUP_FN(lpm4_lookup32, __be32, PREFIX32, dummy_map, match_dummy_prefix)
LPM_LOOKUP_FN(lpm4_lookup31, __be32, PREFIX31, dummy_map, match_dummy_prefix)
LPM_LOOKUP_FN(lpm4_lookup22, __be32, PREFIX22, dummy_map, match_dummy_prefix)
LPM_LOOKUP_FN(lpm4_lookup11, __be32, PREFIX11, dummy_map, match_dummy_prefix)
LPM_LOOKUP_FN(lpm4_lookup0, __be32, PREFIX0, dummy_map, match_dummy_prefix)

static void test_lpm_lookup(void)
{
	__be32 addr;

	dummy_map = &addr;

	addr = htonl(0xFFFFFFFF);
	assert(__lpm4_lookup32(htonl(0xFFFFFFFF)));
	assert(!__lpm4_lookup32(htonl(0xFFF00000)));
	addr = htonl(0xFFFFFFFE);
	assert(__lpm4_lookup31(htonl(0xFFFFFFFE)));
	assert(__lpm4_lookup31(htonl(0xFFFFFFFF)));
	assert(!__lpm4_lookup31(htonl(0xFFF00000)));
	addr = htonl(0xFFFFFC00);
	assert(__lpm4_lookup22(htonl(0xFFFFFC00)));
	assert(__lpm4_lookup22(htonl(0xFFFFFFFF)));
	assert(!__lpm4_lookup22(htonl(0xFFF00000)));
	addr = htonl(0xFFE00000);
	assert(__lpm4_lookup11(htonl(0xFFE00000)));
	assert(__lpm4_lookup11(htonl(0xFFFFFFFF)));
	assert(__lpm4_lookup11(htonl(0xFFF00000)));
	addr = htonl(0xF0000000);
	assert(__lpm4_lookup11(htonl(0xF0000000)));
	addr = htonl(0x00000000);
	assert(__lpm4_lookup0(addr));
	assert(__lpm4_lookup0(htonl(0xFFFFFFFF)));
}
