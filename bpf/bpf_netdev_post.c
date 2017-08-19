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
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/drop.h"
#include "lib/encap.h"

#ifdef ENCAP_IFINDEX
__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct endpoint_key key = {};
	__u32 secctx = skb->mark;

	switch (skb->protocol) {
	case bpf_htons(ETH_P_IPV6):
		if (1) {
			struct ipv6hdr *ip6 = data + ETH_HLEN;
			union v6addr *dst = (union v6addr *) &ip6->daddr;

			if (data + ETH_HLEN + sizeof(*ip6) > data_end)
				return DROP_INVALID;

			/* IPv6 lookup key: daddr/96 */
			key.ip6.p1 = dst->p1;
			key.ip6.p2 = dst->p2;
			key.ip6.p3 = dst->p3;
			key.ip6.p4 = 0;
			key.family = ENDPOINT_KEY_IPV6;
		}
		break;

#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (1) {
			struct iphdr *ip4 = data + ETH_HLEN;

			data = (void *) (long) skb->data;
			data_end = (void *) (long) skb->data_end;
			ip4 = data + ETH_HLEN;
			if (data + sizeof(*ip4) + ETH_HLEN > data_end)
				return DROP_INVALID;

			key.ip4 = ip4->daddr & IPV4_MASK;
			key.family = ENDPOINT_KEY_IPV4;

			if (secctx)
				secctx = (secctx & MD_ID_MASK) | MD_F_REVNAT;

			cilium_trace(skb, DBG_NETDEV_ENCAP4, key.ip4, secctx);
		}
		break;
#endif /* ENABLE_IPV4 */

		default:
			return TC_ACT_OK;
	}

	return encap_and_redirect(skb, &key, secctx);
}

#else /* ENCAP_IFINDEX */

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	return TC_ACT_OK;
}

#endif /* ENCAP_IFINDEX */

BPF_LICENSE("GPL");
