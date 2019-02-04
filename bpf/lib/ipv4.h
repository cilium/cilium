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
#ifndef __LIB_IPV4__
#define __LIB_IPV4__

#include <linux/ip.h>

#include "dbg.h"

static inline int ipv4_load_daddr(struct __sk_buff *skb, int off, __u32 *dst)
{
	return skb_load_bytes(skb, off + offsetof(struct iphdr, daddr), dst, 4);
}

static inline int ipv4_dec_ttl(struct __sk_buff *skb, int off, struct iphdr *ip4)
{
	__u8 new_ttl, ttl = ip4->ttl;

	if (ttl <= 1)
		return 1;

	new_ttl = ttl - 1;
	/* l3_csum_replace() takes at min 2 bytes, zero extended. */
	l3_csum_replace(skb, off + offsetof(struct iphdr, check), ttl, new_ttl, 2);
	skb_store_bytes(skb, off + offsetof(struct iphdr, ttl), &new_ttl, sizeof(new_ttl), 0);

	return 0;
}

static inline int ipv4_hdrlen(struct iphdr *ip4)
{
	return ip4->ihl * 4;
}

static inline bool ipv4_is_fragment(struct iphdr *ip4)
{
	// The frag_off portion of the header consists of:
	//
	// +----+----+----+----------------------------------+
	// | RS | DF | MF | ...13 bits of fragment offset... |
	// +----+----+----+----------------------------------+
	//
	// If "More fragments" or the offset is nonzero, then this is an IP
	// fragment. The evil bit must be set to 0 (RFC791, RFC3514).
	return ip4->frag_off & bpf_htons(0xBFFF);
}

static inline void ipv4_set_dscp(struct __sk_buff *skb, struct iphdr *ip4, __u8 dscp)
{
       	__u8 old_tos = ip4->tos;
	__u8 new_tos = (old_tos & 0x03) | dscp << 2;
	ip4->tos = new_tos;
	// tos is in the higher bits of a U16 in the header, so it must be shifted accordingly.
	l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), old_tos << 8, new_tos << 8, 2);
}
#endif /* __LIB_IPV4__ */
