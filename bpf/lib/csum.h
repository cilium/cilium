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

#ifndef __LIB_CSUM_H_
#define __LIB_CSUM_H_

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>

#define TCP_CSUM_OFF (offsetof(struct tcphdr, check))
#define UDP_CSUM_OFF (offsetof(struct udphdr, check))

struct csum_offset
{
	__u16 offset;
	__u16 flags;
};

/**
 * Determins the L4 checksum field offset and required flags
 * @arg nexthdr	L3 nextheader field
 * @arg off	Pointer to uninitialied struct csum_offset struct
 *
 * Sets off.offset to offset from start of L4 header to L4 checksum field
 * and off.flags to the required flags, namely BPF_F_MARK_MANGLED_0 for UDP.
 * For unknown L4 protocols or L4 protocols which do not have a checksum
 * field, off is initialied to 0.
 */
static inline void csum_l4_offset_and_flags(__u8 nexthdr, struct csum_offset *off)
{
	switch (nexthdr) {
	case IPPROTO_TCP:
		off->offset = TCP_CSUM_OFF;
		break;

	case IPPROTO_UDP:
		off->offset = UDP_CSUM_OFF;
		off->flags = BPF_F_MARK_MANGLED_0;
		break;

	case IPPROTO_ICMPV6:
		off->offset = offsetof(struct icmp6hdr, icmp6_cksum);
		break;

	case IPPROTO_ICMP:
		break;
	}
}

/**
 * Helper to change L4 checksum
 * @arg skb	Packet
 * @arg l4_off	Offset to L4 header
 * @arg csum	Pointer to csum_offset as extracted by csum_l4_offset_and_flags()
 * @arg from	From value or 0 if to contains csum diff
 * @arg to	To value or a csum diff
 * @arg flags	Additional flags to be passed to l4_csum_replace()
 */
static inline int csum_l4_replace(struct __sk_buff *skb, int l4_off, struct csum_offset *csum,
				  __be32 from, __be32 to, int flags)
{
	return l4_csum_replace(skb, l4_off + csum->offset, from, to, flags | csum->flags);
}

#endif /* __LB_H_ */
