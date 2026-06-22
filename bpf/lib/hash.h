/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "jhash.h"

#ifdef __BIG_ENDIAN_BITFIELD
#define HASH_WORD16_LE(v) ((__u16)__builtin_bswap16((__u16)(v)))
#define HASH_WORD32_LE(v) ((__u32)__builtin_bswap32((__u32)(v)))
#else
#define HASH_WORD16_LE(v) ((__u16)(v))
#define HASH_WORD32_LE(v) ((__u32)(v))
#endif

/* The daddr is explicitly excluded from the hash here in order to allow for
 * backend selection to choose the same backend even on different service VIPs.
 */
static __always_inline __u32
__hash_from_tuple_v4(const struct ipv4_ct_tuple *tuple, __be16 sport, __be16 dport)
{
	return jhash_3words(HASH_WORD32_LE(tuple->saddr), ((__u32)HASH_WORD16_LE(dport) << 16) | HASH_WORD16_LE(sport),
			    tuple->nexthdr, CONFIG(hash_init4_seed));
}

static __always_inline __u32 hash_from_tuple_v4(const struct ipv4_ct_tuple *tuple)
{
	return __hash_from_tuple_v4(tuple, tuple->sport, tuple->dport);
}

static __always_inline __u32
__hash_from_tuple_v6(const struct ipv6_ct_tuple *tuple, __be16 sport, __be16 dport)
{
	__u32 a, b, c;

	a = HASH_WORD32_LE(tuple->saddr.p1);
	b = HASH_WORD32_LE(tuple->saddr.p2);
	c = HASH_WORD32_LE(tuple->saddr.p3);
	__jhash_mix(a, b, c);
	a += HASH_WORD32_LE(tuple->saddr.p4);
	b += ((__u32)HASH_WORD16_LE(dport) << 16) | HASH_WORD16_LE(sport);
	c += tuple->nexthdr;
	__jhash_mix(a, b, c);
	a += CONFIG(hash_init6_seed);
	__jhash_final(a, b, c);
	return c;
}

static __always_inline __u32 hash_from_tuple_v6(const struct ipv6_ct_tuple *tuple)
{
	return __hash_from_tuple_v6(tuple, tuple->sport, tuple->dport);
}

#undef HASH_WORD16_LE
#undef HASH_WORD32_LE
