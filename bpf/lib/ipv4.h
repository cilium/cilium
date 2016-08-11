/*
 *  Copyright (C) 2016 Authors of Cilium
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

#define TTL_OFF(off) (off + offsetof(struct iphdr, ttl))

static inline int ipv4_dec_ttl(struct __sk_buff *skb, int off, struct iphdr *ip4)
{
	__u8 new_ttl, ttl = ip4->ttl;

	if (ttl <= 1)
		return 1;

	new_ttl = ttl - 1;
	l3_csum_replace(skb, TTL_OFF(off), ttl, new_ttl, 1);
	skb_store_bytes(skb, off + offsetof(struct iphdr, ttl), &ttl, sizeof(ttl), 0);

	return 0;
}

static inline int ipv4_hdrlen(struct iphdr *ip4)
{
	return ip4->ihl * 4;
}

#endif /* __LIB_IPV4__ */
