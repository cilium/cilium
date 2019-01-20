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
#ifndef __LIB_L3_H_
#define __LIB_L3_H_

#include "common.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eps.h"
#include "eth.h"
#include "dbg.h"
#include "l4.h"
#include "icmp6.h"
#include "csum.h"

static inline int __inline__ ipv6_l3(struct __sk_buff *skb, int l3_off,
				     __u8 *smac, __u8 *dmac, __u8 direction)
{
	int ret;

	ret = ipv6_dec_hoplimit(skb, l3_off);
	if (IS_ERR(ret))
		return ret;

	if (ret > 0) {
		/* Hoplimit was reached */
		return icmp6_send_time_exceeded(skb, l3_off, direction);
	}

	if (smac && eth_store_saddr(skb, smac, 0) < 0)
		return DROP_WRITE_ERROR;

	if (eth_store_daddr(skb, dmac, 0) < 0)
		return DROP_WRITE_ERROR;

	return TC_ACT_OK;
}

static inline int __inline__ ipv4_l3(struct __sk_buff *skb, int l3_off,
				     __u8 *smac, __u8 *dmac, struct iphdr *ip4)
{
	if (ipv4_dec_ttl(skb, l3_off, ip4)) {
		/* FIXME: Send ICMP TTL */
		return DROP_INVALID;
	}

	if (smac && eth_store_saddr(skb, smac, 0) < 0)
		return DROP_WRITE_ERROR;

	if (eth_store_daddr(skb, dmac, 0) < 0)
		return DROP_WRITE_ERROR;

	return TC_ACT_OK;
}

static inline int ipv6_local_delivery(struct __sk_buff *skb, int l3_off, int l4_off,
				      __u32 seclabel, struct ipv6hdr *ip6, __u8 nexthdr,
				      struct endpoint_info *ep, __u8 direction)
{
	int ret;

	cilium_dbg(skb, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);

	mac_t lxc_mac = ep->mac;
	mac_t router_mac = ep->node_mac;

	/* This will invalidate the size check */
	ret = ipv6_l3(skb, l3_off, (__u8 *) &router_mac, (__u8 *) &lxc_mac, direction);
	if (ret != TC_ACT_OK)
		return ret;

	cilium_dbg(skb, DBG_LXC_FOUND, ep->ifindex, 0);
	skb->cb[CB_SRC_LABEL] = seclabel;
	skb->cb[CB_IFINDEX] = ep->ifindex;

#if defined LXC_ID
	/*
	 * Special LXC case for updating egress forwarding metrics.
	 * Note that the packet could still be dropped but it would show up
	 * as an ingress drop counter in metrics.
	 */
	update_metrics(skb->len, direction, REASON_FORWARDED);
#endif
	tail_call(skb, &POLICY_CALL_MAP, ep->lxc_id);
	return DROP_MISSED_TAIL_CALL;
}

static inline int __inline__ ipv4_local_delivery(struct __sk_buff *skb, int l3_off, int l4_off,
						 __u32 seclabel, struct iphdr *ip4,
						 struct endpoint_info *ep, __u8 direction)
{
	int ret;

	cilium_dbg(skb, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);

	mac_t lxc_mac = ep->mac;
	mac_t router_mac = ep->node_mac;

	ret = ipv4_l3(skb, l3_off, (__u8 *) &router_mac, (__u8 *) &lxc_mac, ip4);
	if (ret != TC_ACT_OK)
		return ret;

	cilium_dbg(skb, DBG_LXC_FOUND, ep->ifindex, 0);
	skb->cb[CB_SRC_LABEL] = seclabel;
	skb->cb[CB_IFINDEX] = ep->ifindex;

#if defined LXC_ID
	/*
	 * Special LXC case for updating egress forwarding metrics.
	 * Note that the packet could still be dropped but it would show up
	 * as an ingress drop counter in metrics.
	 */
	update_metrics(skb->len, direction, REASON_FORWARDED);
#endif
	tail_call(skb, &POLICY_CALL_MAP, ep->lxc_id);
	return DROP_MISSED_TAIL_CALL;
}

#endif
