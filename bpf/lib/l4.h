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
				 struct csum_offset *csum_off, __be16 port, __be16 old_port)
{
	if (csum_l4_replace(skb, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
		return DROP_CSUM_L4;

	if (skb_store_bytes(skb, l4_off + off, &port, sizeof(port), 0) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

static inline int l4_load_port(struct __sk_buff *skb, int off, __be16 *port)
{
        return skb_load_bytes(skb, off, port, sizeof(__be16));
}
#endif
