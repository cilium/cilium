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

#ifndef CONNTRACK
#define CONNTRACK
#endif

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/l3.h"
#include "lib/l4.h"
#include "lib/eth.h"
#include "lib/encap.h"
#include "lib/dbg.h"
#include "lib/drop.h"
#include "lib/lb.h"
#include "lib/conntrack.h"
#include "lib/nat.h"

#ifdef ENABLE_IPV4
static inline int __inline__
handle_ipv4(struct __sk_buff *skb, __u32 secctx, __u16 revnat)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct iphdr *ip4 = data + ETH_HLEN;
	struct csum_offset csum_off = {};
	struct ipv4_ct_tuple tuple = {};
	int l4_off;

        data = (void *) (long) skb->data;
        data_end = (void *) (long) skb->data_end;
        ip4 = data + ETH_HLEN;
        if (data + sizeof(*ip4) + ETH_HLEN > data_end)
                return DROP_INVALID;

	l4_off = ct_extract_tuple4(&tuple, ip4, ETH_HLEN, CT_EGRESS);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	if (revnat) {
		/* Perform reverse NAT, this will also update the tuple to represent
		 * the post reverse translation state */
		lb4_rev_nat(skb, ETH_HLEN, l4_off, &csum_off, 0, &tuple, revnat, 0);

		data = (void *) (long) skb->data;
		data_end = (void *) (long) skb->data_end;
		ip4 = data + ETH_HLEN;
		if (data + sizeof(*ip4) + ETH_HLEN > data_end)
			return DROP_INVALID;
	}

	/* Check if destination is within our cluster prefix */
	if ((ip4->daddr & IPV4_CLUSTER_MASK) == IPV4_CLUSTER_RANGE) {
		struct endpoint_info *ep;

		cilium_trace(skb, DBG_NETDEV_IN_CLUSTER, secctx, 0);

		/* Lookup IPv4 address in list of local endpoints */
		if ((ep = lookup_ip4_endpoint(ip4)) != NULL) {
			/* Let through packets to the node-ip so they are
			 * processed by the local ip stack */
			if (ep->flags & ENDPOINT_F_HOST)
				return TC_ACT_OK;

			return ipv4_local_delivery(skb, ETH_HLEN, l4_off, secctx, ip4, ep);
#ifdef ENCAP_IFINDEX
		} else {
			/* IPv4 lookup key: daddr & IPV4_MASK */
			struct endpoint_key key = {};

			key.ip4 = ip4->daddr & IPV4_MASK;
			key.family = ENDPOINT_KEY_IPV4;

			cilium_trace(skb, DBG_NETDEV_ENCAP4, key.ip4, secctx);
			return encap_and_redirect(skb, &key, secctx);
#endif /* ENCAP_IFINDEX */
		}
	}

	/* The packet destination is outside of the cluster, pass it on, it
	 * will go through the veth pair and will be routed at ingress on the
	 * other side of the veth. */

	return TC_ACT_OK;
}
#endif

static inline int handle_ipv6(struct __sk_buff *skb, __u32 secctx, __u16 revnat)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	union v6addr *dst = (union v6addr *) &ip6->daddr;
	struct csum_offset csum_off = {};
	struct ipv6_ct_tuple tuple = {};
	union v6addr node_ip = {};
	struct endpoint_info *ep;
	int l4_off;

	if (data + ETH_HLEN + sizeof(*ip6) > data_end)
		return DROP_INVALID;

	l4_off = ct_extract_tuple6(skb, &tuple, ip6, ETH_HLEN, CT_EGRESS);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	if (revnat) {
		/* Perform reverse NAT, this will also update the tuple to represent
		 * the post reverse translation state */
		lb6_rev_nat(skb, l4_off, &csum_off, revnat, &tuple, 0);

		data = (void *) (long) skb->data;
		data_end = (void *) (long) skb->data_end;
		ip6 = data + ETH_HLEN;
		if (data + sizeof(*ip6) + ETH_HLEN > data_end)
			return DROP_INVALID;
	}

	dst = (union v6addr *) &ip6->daddr;
	BPF_V6(node_ip, ROUTER_IP);

	if (likely(ipv6_match_prefix_96(dst, &node_ip))) {
		/* Lookup IPv6 address in list of local endpoints */
		if ((ep = lookup_ip6_endpoint(ip6)) != NULL) {
			/* Let through packets to the node-ip so they are
			 * processed by the local ip stack */
			if (ep->flags & ENDPOINT_F_HOST)
				return TC_ACT_OK;

			return ipv6_local_delivery(skb, ETH_HLEN, l4_off, secctx, ip6, tuple.nexthdr, ep);
		} else {
#ifdef ENCAP_IFINDEX
			struct endpoint_key key = {};

			/* IPv6 lookup key: daddr/96 */
			dst = (union v6addr *) &ip6->daddr;
			key.ip6.p1 = dst->p1;
			key.ip6.p2 = dst->p2;
			key.ip6.p3 = dst->p3;
			key.ip6.p4 = 0;
			key.family = ENDPOINT_KEY_IPV6;

			return encap_and_redirect(skb, &key, secctx);
#endif
		}
	}

	/* The packet destination is outside of the cluster, pass it on, it
	 * will go through the veth pair and will be routed at ingress on the
	 * other side of the veth. */

	return TC_ACT_OK;
}

__section("to-netdev")
int from_netdev(struct __sk_buff *skb)
{
	__u32 secctx;
	__u16 revnat;

	decode_nat_metadata(skb, &secctx, &revnat);

	cilium_trace_capture(skb, DBG_CAPTURE_NAT_REV_OUT, revnat);

	switch (skb->protocol) {
	case bpf_htons(ETH_P_IPV6):
		return handle_ipv6(skb, secctx, revnat);

#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		return handle_ipv4(skb, secctx, revnat);
#endif /* ENABLE_IPV4 */
	}

	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
