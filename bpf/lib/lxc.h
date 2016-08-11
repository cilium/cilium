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
#ifndef __LIB_LXC_H_
#define __LIB_LXC_H_

#include "common.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "dbg.h"

#ifndef DISABLE_SMAC_VERIFICATION
static inline int valid_src_mac(struct ethhdr *eth)
{
	union macaddr valid = LXC_MAC;

	return !eth_addrcmp(&valid, (union macaddr *) &eth->h_source);
}
#else
static inline int valid_src_mac(struct ethhdr *eth)
{
	return 1;
}
#endif

#ifndef DISABLE_SIP_VERIFICATION
static inline int valid_src_ip(struct ipv6hdr *ip6)
{
	union v6addr valid = LXC_IP;

	return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
}

static inline int valid_src_ipv4(struct iphdr *ip4)
{
#ifdef LXC_IPV4
	return ip4->saddr != LXC_IPV4;
#else
	/* Can't send IPv4 if no IPv4 address is configured */
	return 0;
#endif
}
#else
static inline int valid_src_ip(struct ipv6hdr *ip6)
{
	return 1;
}

static inline int valid_src_ipv4(struct iphdr *ip4)
{
	return 1;
}
#endif

#ifndef DISABLE_DMAC_VERIFICATION
static inline int valid_dst_mac(struct ethhdr *eth)
{
	union macaddr valid = NODE_MAC;

	return !eth_addrcmp(&valid, (union macaddr *) &eth->h_dest);
}
#else
static inline int valid_dst_mac(struct ethhdr *eth)
{
	return 1;
}
#endif

#endif
