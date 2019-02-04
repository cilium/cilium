/*
 *  Copyright (C) 2016-2017 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __LIB_IPV6__
#define __LIB_IPV6__

#include <linux/ipv6.h>

#include "dbg.h"
#define IPV6_FLOWINFO_MASK              bpf_htonl(0x0FFFFFFF)
#define IPV6_FLOWLABEL_MASK             bpf_htonl(0x000FFFFF)
#define IPV6_FLOWLABEL_STATELESS_FLAG   bpf_htonl(0x00080000)

#define IPV6_TCLASS_MASK (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK)
#define IPV6_TCLASS_SHIFT       20

/* Number of extension headers that can be skipped */
#define IPV6_MAX_HEADERS 4

#define NEXTHDR_HOP             0       /* Hop-by-hop option header. */
#define NEXTHDR_TCP             6       /* TCP segment. */
#define NEXTHDR_UDP             17      /* UDP message. */
#define NEXTHDR_IPV6            41      /* IPv6 in IPv6 */
#define NEXTHDR_ROUTING         43      /* Routing header. */
#define NEXTHDR_FRAGMENT        44      /* Fragmentation/reassembly header. */
#define NEXTHDR_GRE             47      /* GRE header. */
#define NEXTHDR_ESP             50      /* Encapsulating security payload. */
#define NEXTHDR_AUTH            51      /* Authentication header. */
#define NEXTHDR_ICMP            58      /* ICMP for IPv6. */
#define NEXTHDR_NONE            59      /* No next header */
#define NEXTHDR_DEST            60      /* Destination options header. */
#define NEXTHDR_SCTP            132     /* SCTP message. */
#define NEXTHDR_MOBILITY        135     /* Mobility header. */

#define NEXTHDR_MAX             255

static inline int ipv6_optlen(struct ipv6_opt_hdr *opthdr)
{
	return (opthdr->hdrlen + 1) << 3;
}

static inline int ipv6_authlen(struct ipv6_opt_hdr *opthdr)
{
	return (opthdr->hdrlen + 2) << 2;
}

static inline int __inline__ ipv6_hdrlen(struct __sk_buff *skb, int l3_off, __u8 *nexthdr)
{
	int i, len = sizeof(struct ipv6hdr);
	struct ipv6_opt_hdr opthdr;
	__u8 nh = *nexthdr;

#pragma unroll
	for (i = 0; i < IPV6_MAX_HEADERS; i++) {
		switch (nh) {
		case NEXTHDR_NONE:
			return DROP_INVALID_EXTHDR;

		case NEXTHDR_FRAGMENT:
			return DROP_FRAG_NOSUPPORT;

		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_AUTH:
		case NEXTHDR_DEST:
			if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
				return DROP_INVALID;

			nh = opthdr.nexthdr;
			if (nh == NEXTHDR_AUTH)
				len += ipv6_authlen(&opthdr);
			else
				len += ipv6_optlen(&opthdr);
			break;

		default:
			*nexthdr = nh;
			return len;
		}
	}

	/* Reached limit of supported extension headers */
	return DROP_INVALID_EXTHDR;
}

static inline void ipv6_addr_copy(union v6addr *dst, union v6addr *src)
{
	dst->p1 = src->p1;
	dst->p2 = src->p2;
	dst->p3 = src->p3;
	dst->p4 = src->p4;
}

static inline int ipv6_addrcmp(union v6addr *a, union v6addr *b)
{
	int tmp;

	tmp = a->p1 - b->p1;
	if (!tmp) {
		tmp = a->p2 - b->p2;
		if (!tmp) {
			tmp = a->p3 - b->p3;
			if (!tmp)
				tmp = a->p4 - b->p4;
		}
	}

	return tmp;
}

// Only works with contiguous masks.
static inline int ipv6_addr_in_net(union v6addr *addr, union v6addr *net, union v6addr *mask)
{
	return ((addr->p1 & mask->p1) == net->p1)
		&& (!mask->p2
		    || (((addr->p2 & mask->p2) == net->p2)
			&& (!mask->p3
			    || (((addr->p3 & mask->p3) == net->p3)
				&& (!mask->p4 || ((addr->p4 & mask->p4) == net->p4))))));
}

#define GET_PREFIX(PREFIX)						\
	bpf_htonl(prefix <= 0 ? 0 : prefix < 32 ? ((1<<prefix) - 1) << (32-prefix)	\
			      : 0xFFFFFFFF)

static inline void ipv6_addr_clear_suffix(union v6addr *addr, int prefix)
{
	addr->p1 &= GET_PREFIX(prefix);
	prefix -= 32;
	addr->p2 &= GET_PREFIX(prefix);
	prefix -= 32;
	addr->p3 &= GET_PREFIX(prefix);
	prefix -= 32;
	addr->p4 &= GET_PREFIX(prefix);
	prefix -= 32;
}

static inline int ipv6_match_prefix_96(const union v6addr *addr, const union v6addr *prefix)
{
	int tmp;

	tmp = addr->p1 - prefix->p1;
	if (!tmp) {
		tmp = addr->p2 - prefix->p2;
		if (!tmp)
			tmp = addr->p3 - prefix->p3;
	}

	return !tmp;
}

static inline int ipv6_match_prefix_64(const union v6addr *addr, const union v6addr *prefix)
{
	int tmp;

	tmp = addr->p1 - prefix->p1;
	if (!tmp)
		tmp = addr->p2 - prefix->p2;

	return !tmp;
}

static inline int ipv6_dec_hoplimit(struct __sk_buff *skb, int off)
{
	__u8 hl;

	skb_load_bytes(skb, off + offsetof(struct ipv6hdr, hop_limit),
		       &hl, sizeof(hl));
	if (hl <= 1)
		return 1;
	hl--;
	if (skb_store_bytes(skb, off + offsetof(struct ipv6hdr, hop_limit),
			    &hl, sizeof(hl), BPF_F_RECOMPUTE_CSUM) < 0)
		return DROP_WRITE_ERROR;
	return 0;
}

static inline int ipv6_load_saddr(struct __sk_buff *skb, int off, union v6addr *dst)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, saddr), dst->addr,
			      sizeof(((struct ipv6hdr *)NULL)->saddr));
}

/* Assumes that caller fixes checksum csum_diff() and l4_csum_replace() */
static inline int ipv6_store_saddr(struct __sk_buff *skb, __u8 *addr, int off)
{
	return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, saddr), addr, 16, 0);
}

static inline int ipv6_load_daddr(struct __sk_buff *skb, int off, union v6addr *dst)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, daddr), dst->addr,
			      sizeof(((struct ipv6hdr *)NULL)->daddr));
}

/* Assumes that caller fixes checksum csum_diff() and l4_csum_replace() */
static inline int ipv6_store_daddr(struct __sk_buff *skb, __u8 *addr, int off)
{
	return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, daddr), addr, 16, 0);
}

static inline int ipv6_load_nexthdr(struct __sk_buff *skb, int off, __u8 *nexthdr)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, nexthdr), nexthdr,
			      sizeof(__u8));
}

/* Assumes that caller fixes checksum csum_diff() and l4_csum_replace() */
static inline int ipv6_store_nexthdr(struct __sk_buff *skb, __u8 *nexthdr, int off)
{
	return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, nexthdr), nexthdr,
			      sizeof(__u8), 0);
}

static inline int ipv6_load_paylen(struct __sk_buff *skb, int off, __be16 *len)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, payload_len),
			      len, sizeof(*len));
}

/* Assumes that caller fixes checksum csum_diff() and l4_csum_replace() */
static inline int ipv6_store_paylen(struct __sk_buff *skb, int off, __be16 *len)
{
	return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, payload_len),
			       len, sizeof(*len), 0);
}

static inline int ipv6_store_flowlabel(struct __sk_buff *skb, int off, __be32 label)
{
	__be32 old;

	/* use traffic class from packet */
	if (skb_load_bytes(skb, off, &old, 4) < 0)
		return DROP_INVALID;

	old &= IPV6_TCLASS_MASK;
	old = bpf_htonl(0x60000000) | label | old;

	if (skb_store_bytes(skb, off, &old, 4, BPF_F_RECOMPUTE_CSUM) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

static inline __be32 ipv6_pseudohdr_checksum(struct ipv6hdr *hdr,
                                             __u8 next_hdr,
					     __u16 payload_len, __be32 sum)
{
	__be32 len = bpf_htonl((__u32)payload_len);
	__be32 nexthdr = bpf_htonl((__u32)next_hdr);
	sum = csum_diff(NULL, 0, &hdr->saddr, sizeof(struct in6_addr), sum);
	sum = csum_diff(NULL, 0, &hdr->daddr, sizeof(struct in6_addr), sum);
	sum = csum_diff(NULL, 0, &len, sizeof(len), sum);
	sum = csum_diff(NULL, 0, &nexthdr, sizeof(nexthdr), sum);

	return sum;
}

/*
 * Ipv4 mapped address - 0:0:0:0:0:FFFF::/96
 */
static inline int ipv6_addr_is_mapped(union v6addr *addr)
{
	return addr->p1 == 0 && addr->p2 == 0 && addr->p3 == 0xFFFF0000;
}

static inline void ipv6_set_dscp(struct __sk_buff *skb, struct ipv6hdr *ip6, __u8 dscp)
{
	ip6->priority = dscp >> 2;
	ip6->flow_lbl[0] = (ip6->flow_lbl[0] & 0x3F) | (dscp << 6);
}
#endif /* __LIB_IPV6__ */
