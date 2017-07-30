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

#define QUIET_CT

#ifndef CONNTRACK
#define CONNTRACK
#endif

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/l4.h"
#include "lib/lb.h"
#include "lib/conntrack.h"
#include "lib/proxy.h"

static inline int __inline__ ipv6_revnat(struct __sk_buff *skb)
{
	struct ipv6_ct_tuple tuple = {};
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	struct csum_offset csum_off = {};
	struct ct_state ct_state = {};
	int ret, l4_off;

	if (data + sizeof(struct ipv6hdr) + ETH_HLEN > data_end)
		return DROP_INVALID;

	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	tuple.nexthdr = ip6->nexthdr;

	l4_off = ETH_HLEN + ipv6_hdrlen(skb, ETH_HLEN, &tuple.nexthdr);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = reverse_proxy6(skb, l4_off, ip6, ip6->nexthdr);
	if (IS_ERR(ret))
		return ret;

	data = (void *) (long) skb->data;
	data_end = (void *) (long) skb->data_end;
	ip6 = data + ETH_HLEN;
	if (data + sizeof(*ip6) + ETH_HLEN > data_end)
		return DROP_INVALID;

	/* re-read the tuple as reverse proxy may have overwritten it */
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);

	ret = ct_lookup6(&CT_MAP6, &tuple, skb, l4_off, CT_EGRESS, &ct_state);
	if (unlikely(ret == CT_REPLY && ct_state.rev_nat_index)) {
		lb6_rev_nat(skb, l4_off, &csum_off,
			    ct_state.rev_nat_index, &tuple, 0);
	}

	return ret;
}

#ifdef ENABLE_IPV4
static inline int __inline__ ipv4_revnat(struct __sk_buff *skb)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct iphdr *ip4 = data + ETH_HLEN;
	struct ipv4_ct_tuple tuple = {};
	struct csum_offset csum_off = {};
	struct ct_state ct_state = {};
	int ret, l4_off;

	if (data + sizeof(*ip4) + ETH_HLEN > data_end)
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = reverse_proxy(skb, l4_off, ip4, &tuple);
	/* DIRECT PACKET READ INVALID */
	if (IS_ERR(ret))
		return ret;

	data = (void *) (long) skb->data;
	data_end = (void *) (long) skb->data_end;
	ip4 = data + ETH_HLEN;
	if (data + sizeof(*ip4) + ETH_HLEN > data_end)
		return DROP_INVALID;

	/* re-read the tuple as reverse proxy may have overwritten it */
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	ret = ct_lookup4(&CT_MAP4, &tuple, skb, l4_off, CT_EGRESS, &ct_state);
	if (unlikely(ret == CT_REPLY && ct_state.rev_nat_index)) {
		lb4_rev_nat(skb, ETH_HLEN, l4_off, &csum_off, &ct_state, &tuple,
			    REV_NAT_F_TUPLE_SADDR);
	}

	return ret;
}
#endif /* ENABLE_IPV4 */

__section("to-netdev")
int to_netdev(struct __sk_buff *skb)
{
	int ret = 0;

	switch (skb->protocol) {
	case bpf_htons(ETH_P_IPV6):
		ret = ipv6_revnat(skb);
		break;

#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = ipv4_revnat(skb);
		break;
#endif
	}

	/* Processing errors are reported in debugging mode but they never
	 * cause packets to be dropped. Dropping packets for invalid reasons
	 * could make the machine non-accessible and it is not safe to make
	 * an assumption when it is safe to drop a packet.
	 */
	if (IS_ERR(ret))
		cilium_trace(skb, DBG_ABORT_ERR, ret, 0);

	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
