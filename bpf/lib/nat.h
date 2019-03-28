/*
 *  Copyright (C) 2019 Authors of Cilium
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
#ifndef __LIB_NAT__
#define __LIB_NAT__

#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>

#include "common.h"
#include "drop.h"
#include "conntrack.h"
#include "conntrack_map.h"

#ifdef CONNTRACK
static __always_inline void ct_delete4(void *map, struct ipv4_ct_tuple *tuple,
				       struct __sk_buff *skb)
{
	int err;

	if ((err = map_delete_elem(map, tuple)) < 0)
		cilium_dbg(skb, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);
}

static __always_inline void ct_delete6(void *map, struct ipv6_ct_tuple *tuple,
				       struct __sk_buff *skb)
{
	int err;

	if ((err = map_delete_elem(map, tuple)) < 0)
		cilium_dbg(skb, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);
}
#else
static __always_inline void ct_delete4(void *map, struct ipv4_ct_tuple *tuple,
				       struct __sk_buff *skb)
{
}

static __always_inline void ct_delete6(void *map, struct ipv6_ct_tuple *tuple,
				       struct __sk_buff *skb)
{
}
#endif

#endif /* __LIB_NAT__ */
