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

#ifndef __NAT_H_
#define __NAT_H_

#include "common.h"

#define MAGIC_NAT_MARK_FWD (0xA5B8 << 16)
#define MAGIC_NAT_MARK_HOST (0xFEFE << 16)

/**
 * Encode identity and revnat into skb->mark and skb->tc_classid for forward NAT
 */
static inline void __inline__ encode_nat_metadata(struct __sk_buff *skb, __u32 secctx, __u32 revnat)
{
	skb->mark = MAGIC_NAT_MARK_FWD | (revnat & 0xFFFF);
	skb->tc_classid = secctx & 0xFFF;
}

/**
 * Encode identity into skb->tc_classid for reverse NAT
 */
static inline void __inline__ encode_revnat_metadata(struct __sk_buff *skb, __u32 secctx)
{
	skb->tc_classid = secctx & 0xFFF;
}

/**
 * Decode identity and revnat from skb->mark
 */
static inline void __inline__ decode_nat_metadata(struct __sk_buff *skb, __u32 *secctx, __u16 *revnat)
{
	__u32 mark = *(volatile __u32 *) &skb->mark;
	__u32 index = *(volatile __u32 *) &skb->tc_index;

	if (secctx != NULL)
		*secctx = index & 0xFFFF;

	if (revnat != NULL)
		*revnat = mark & 0xFFFF;
}

/* Will lead to a compilation error if someoneis using redirect_nat_reverse without
 * providing NAT_OUT_MAC */
#ifdef NAT_OUT_MAC

/**
 * Redirect packet to NAT back in reverse direction
 */
static inline int __inline__ redirect_nat_reverse(struct __sk_buff *skb, __u8 *router_mac, __u32 secctx)
{
	union macaddr mac = NAT_OUT_MAC;

	if (eth_store_saddr(skb, router_mac, 0) < 0)
		return DROP_WRITE_ERROR;

	if (eth_store_daddr(skb, (__u8 *) &mac.addr, 0) < 0)
		return DROP_WRITE_ERROR;

	encode_revnat_metadata(skb, secctx);
	cilium_trace_capture(skb, DBG_CAPTURE_NAT_REV, NAT_OUT_IFINDEX);

	return redirect(NAT_OUT_IFINDEX, 0);
}
#endif

#endif /* __NAT_H_ */
