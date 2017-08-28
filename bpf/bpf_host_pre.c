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
#include <node_config.h>
#include <netdev_config.h>

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/dbg.h"

static inline void __inline__ derive_identity(struct __sk_buff *skb, __u32 *secctx)
{
	/* When packet is coming from the host, it may contain the security
	 * identity, otherwise we fall back to HOST_ID. */
	if (skb->mark)
		*secctx = skb->mark;
	else
		*secctx = HOST_ID;
}

__section("to-netdev")
int to_netdev(struct __sk_buff *skb)
{
	__u32 secctx;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_HOST, skb->ifindex);

	derive_identity(skb, &secctx);
	skb->tc_index = secctx;

	/* Pass to other side of veth */
	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
