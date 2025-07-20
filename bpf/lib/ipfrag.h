/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/ip.h>
#include "common.h"

/* IP fragment information is packed in a single __s64:
 *
 *  63    62...42 41     40     39...32 31...    ...0
 * +-----+-------+------+------+-------+-------------+
 * | err |  ...  | nol4 | frag | proto | fragment id |
 * +-----+-------+------+------+-------+-------------+
 *
 * err: Sign bit, negative values encode error codes.
 * nol4: The packet doesn't have an L4 header (i.e. not the first fragment).
 * frag: The packet is fragmented.
 * proto: L4 protocol (the last nexthdr for IPv6).
 * fragment id: 32-bit for IPv6, 16-bit for IPv4 (lower 16 bits).
 *
 * This information is extracted from the IPv4 header or from the IPv6
 * NEXTHDR_FRAGMENT extension header. The latter is an expensive operation (in
 * terms of verifier complexity and CPU cycles), so we aim to extract it once
 * and pass the __s64 bitmask around (aliased as fraginfo_t).
 *
 * proto should only be used by the fragment tracker, making 0 a valid default
 * value for a non-fragmented packet.
 *
 * This file contains an abstraction level over IPv4 and IPv6 fragments.
 */

typedef __s64 fraginfo_t;

#define IPFRAG_BIT_FRAGMENTED (1LL << 40)
#define IPFRAG_BIT_NO_L4_HEADER (1LL << 41)

struct ipv6_frag_hdr {
	__u8 nexthdr;
	__u8 reserved;
	__be16 frag_off;
	__be32 id;
} __packed;

/* This function doesn't return errors. */
static __always_inline fraginfo_t ipfrag_encode_ipv4(const struct iphdr *ip4)
{
	fraginfo_t fraginfo = (__u16)ip4->id; /* Store in network byte order. */

	fraginfo |= (__u64)ip4->protocol << 32;

	/* The frag_off portion of the IPv4 header consists of:
	 *
	 * +---+----+----+----------------------------------+
	 * | 0 | DF | MF | ...13 bits of fragment offset... |
	 * +---+----+----+----------------------------------+
	 *
	 * If "More fragments" or the offset is nonzero, then this is an IP
	 * fragment (RFC791). If the offset is nonzero, it's not the first
	 * fragment, therefore it doesn't have an L4 header.
	 */
	if (ip4->frag_off & bpf_htons(0x3fff))
		fraginfo |= IPFRAG_BIT_FRAGMENTED;
	if (ip4->frag_off & bpf_htons(0x1fff))
		fraginfo |= IPFRAG_BIT_NO_L4_HEADER;

	return fraginfo;
}

/* This function doesn't return errors. */
static __always_inline fraginfo_t ipfrag_encode_ipv6(const struct ipv6_frag_hdr *exthdr)
{
	fraginfo_t fraginfo = (__u32)exthdr->id; /* Store in network byte order. */

	fraginfo |= (__u64)exthdr->nexthdr << 32;

	/* frag_off of the IPv6 fragment extension header:
	 *
	 * +----------------------------------+---+---+----+
	 * | ...13 bits of fragment offset... | 0 | 0 | MF |
	 * +----------------------------------+---+---+----+
	 */
	if (exthdr->frag_off & bpf_htons(0xfff9))
		fraginfo |= IPFRAG_BIT_FRAGMENTED;
	if (exthdr->frag_off & bpf_htons(0xfff8))
		fraginfo |= IPFRAG_BIT_NO_L4_HEADER;

	return fraginfo;
}

static __always_inline bool ipfrag_is_fragment(fraginfo_t fraginfo)
{
	return fraginfo & IPFRAG_BIT_FRAGMENTED;
}

static __always_inline bool ipfrag_has_l4_header(fraginfo_t fraginfo)
{
	return !(fraginfo & IPFRAG_BIT_NO_L4_HEADER);
}

static __always_inline __u8 ipfrag_get_protocol(fraginfo_t fraginfo)
{
	return (fraginfo >> 32) & 0xff;
}

/* Downcast to __be16 for IPv4. */
static __always_inline __be32 ipfrag_get_id(fraginfo_t fraginfo)
{
	return (__be32)(fraginfo & 0xffffffff);
}
