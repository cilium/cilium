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
#ifndef __LIB_L4_H_
#define __LIB_L4_H_

#include <linux/tcp.h>
#include <linux/udp.h>
#include "common.h"
#include "dbg.h"
#include "csum.h"

#define TCP_DPORT_OFF (offsetof(struct tcphdr, dest))
#define TCP_SPORT_OFF (offsetof(struct tcphdr, source))
#define UDP_DPORT_OFF (offsetof(struct udphdr, dest))
#define UDP_SPORT_OFF (offsetof(struct udphdr, source))


/**
 * Modify L4 port and correct checksum
 * @arg skb:      packet
 * @arg l4_off:   offset to L4 header
 * @arg off:      offset from L4 header to source or destination port
 * @arg csum_off: offset from L4 header to 16bit checksum field in L4 header
 * @arg port:     new port value
 * @arg old_port: old port value (for checksum correction)
 *
 * Overwrites a TCP or UDP port with new value and fixes up the checksum
 * in the L4 header and of skb->csum.
 *
 * NOTE: Calling this function will invalidate any pkt context offset
 * validation for direct packet access.
 *
 * Return 0 on success or a negative DROP_* reason
 */
static inline int l4_modify_port(struct __sk_buff *skb, int l4_off, int off,
				 struct csum_offset *csum_off, __u16 port, __u16 old_port)
{
	if (csum_l4_replace(skb, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
		return DROP_CSUM_L4;

        if (skb_store_bytes(skb, l4_off + off, &port, sizeof(port), 0) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

/**
 * Apply a port mapping for incoming packets
 * @arg skb:      packet
 * @arg l4_off:   offset to L4 header
 * @arg csum_off: offset to 16bit checksum field in L4 header
 * @arg map:      port mapping entry
 * @arg dport:    Current L4 destination port
 *
 * Checks if the packet needs to be port mapped and applies the mapping
 * if necessary.
 *
 * NOTE: Calling this function will invalidate any pkt context offset
 * validation for direct packet access.
 *
 * Return 0 on success or a negative DROP_* reason
 */
static inline int l4_port_map_in(struct __sk_buff *skb, int l4_off,
				 struct csum_offset *csum_off,
				 struct portmap *map, __u16 dport)
{
	cilium_trace(skb, DBG_PORT_MAP, ntohs(map->from), ntohs(map->to));

	if (likely(map->from != dport))
		return 0;

	/* Port offsets for UDP and TCP are the same */
	return l4_modify_port(skb, l4_off, TCP_DPORT_OFF, csum_off, map->to, dport);
}

/**
 * Apply a port mapping for outgoing packets
 * @arg skb:      packet
 * @arg l4_off:   offset to L4 header
 * @arg csum_off: offset to 16bit checksum field in L4 header
 * @arg map:      port mapping entry
 * @arg sport:    Current L4 source port
 *
 * Checks if the packet needs to be port mapped and applies the mapping
 * if necessary.
 *
 * NOTE: Calling this function will invalidate any pkt context offset
 * validation for direct packet access.
 *
 * Return 0 on success or a negative DROP_* reason
 */
static inline int l4_port_map_out(struct __sk_buff *skb, int l4_off,
				  struct csum_offset *csum_off,
				  struct portmap *map, __u16 sport)
{
	cilium_trace(skb, DBG_PORT_MAP, ntohs(map->to), ntohs(map->from));

	if (likely(map->to != sport))
		return 0;

	/* Port offsets for UDP and TCP are the same */
	return l4_modify_port(skb, l4_off, TCP_SPORT_OFF, csum_off, map->from, sport);
}

static inline int l4_load_port(struct __sk_buff *skb, int off, __u16 *port)
{
        return skb_load_bytes(skb, off, port, sizeof(__u16));
}

#endif
