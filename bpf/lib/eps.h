/*
 *  Copyright (C) 2017 Authors of Cilium
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
#ifndef __LIB_EPS_H_
#define __LIB_EPS_H_

#include <linux/ip.h>
#include <linux/ipv6.h>

#include "maps.h"

static __always_inline struct endpoint_info *
lookup_ip6_endpoint(struct ipv6hdr *ip6)
{
	struct endpoint_key key = {};

	key.ip6 = *((union v6addr *) &ip6->daddr);
	key.family = ENDPOINT_KEY_IPV6;

	return map_lookup_elem(&cilium_lxc, &key);
}

static __always_inline struct endpoint_info *
lookup_ip4_endpoint(struct iphdr *ip4)
{
	struct endpoint_key key = {};

	key.ip4 = ip4->daddr;
	key.family = ENDPOINT_KEY_IPV4;

	return map_lookup_elem(&cilium_lxc, &key);
}

#endif /* __LIB_EPS_H_ */
