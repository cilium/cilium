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

/**
 * Description: Standalone loadbalancer that can be attached to any
 *              net_device. Will perform a map lookup on the destination
 *              IP and optional destination port for every IPv4 and
 *              IPv6 packet recevied. If a matching entry is found, the
 *              destination address will be written to one of the
 *              configures slaves. Optionally the destination port can be
 *              mapped to a slave specific port as well. The packet is
 *              then passed back to the stack.
 *
 * Configuration:
 *  - LB_DISABLE_IPV4 - Ignore IPv4 packets
 *  - LB_DISABLE_IPV6 - Ignore IPv6 packets
 *  - LB_REDIRECT     - Redirect to an ifindex
 *  - LB_L4           - Enable L4 matching and mapping
 */

#define DISABLE_LOOPBACK_LB

#include <netdev_config.h>
#include <node_config.h>

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/l4.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/drop.h"
#include "lib/conntrack.h"
#include "lib/lb.h"

#ifndef LB_DISABLE_IPV6
__BPF_MAP(CT_MAP6_NSLB, BPF_MAP_TYPE_HASH, 0, sizeof(struct ipv6_ct_tuple),
	  sizeof(struct ct_entry), PIN_GLOBAL_NS, CT_MAP_LB_SIZE);

static inline int handle_ipv6(struct __sk_buff *skb)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct lb6_key key = {};
	struct lb6_service *svc;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	union v6addr *dst = (union v6addr *) &ip6->daddr;
	struct csum_offset csum_off = {};
	int l3_off, l4_off, ret;
	union v6addr new_dst;
	__u8 nexthdr;
	__u16 slave;
	struct ct_state ct_state_prexlate = {};
	struct ipv6_ct_tuple tuple = {};

	if (data + ETH_HLEN + sizeof(*ip6) > data_end)
		return DROP_INVALID;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_LB, skb->ingress_ifindex);

	nexthdr = ip6->nexthdr;
	tuple.nexthdr = nexthdr;
	ipv6_addr_copy(&tuple.addr, dst);
	l3_off = ETH_HLEN;
	l4_off = ETH_HLEN + ipv6_hdrlen(skb, ETH_HLEN, &nexthdr);

	ret = lb6_extract_key(skb, &tuple, l4_off, &key, &csum_off);
	if (IS_ERR(ret)) {
		/* Pass unknown L4 to stack */
		if (ret == DROP_UNKNOWN_L4)
			return TC_ACT_OK;
		else
			return ret;
	}

	/* Pass packets to the stack which should not be loadbalanced */
	if (lb6_skip(&CT_MAP6_NSLB, skb, &key, &tuple, &ct_state_prexlate, l4_off, 0))
		return TC_ACT_OK;

	slave = ct_state_prexlate.lb_slave_index;
	if (!(svc = lb6_lookup_slave(skb, &key, slave)))
		return DROP_NO_SERVICE;

	ipv6_addr_copy(&new_dst, &svc->target);
	if (svc->rev_nat_index)
		new_dst.p4 |= svc->rev_nat_index;

	ret = lb6_xlate(skb, &new_dst, nexthdr, l3_off, l4_off, &csum_off, &key, svc);
	if (IS_ERR(ret))
		return ret;

	return TC_ACT_REDIRECT;
}
#endif

#ifndef LB_DISABLE_IPV4
__BPF_MAP(CT_MAP4_NSLB, BPF_MAP_TYPE_HASH, 0, sizeof(struct ipv4_ct_tuple),
	  sizeof(struct ct_entry), PIN_GLOBAL_NS, CT_MAP_LB_SIZE);

static inline int handle_ipv4(struct __sk_buff *skb)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct lb4_key key = {};
	struct lb4_service *svc;
	struct iphdr *ip = data + ETH_HLEN;
	struct csum_offset csum_off = {};
	int l3_off, l4_off, ret;
	__be32 new_dst;
	__u8 nexthdr;
	__u16 slave;
	struct ct_state ct_state_prexlate = {};
	struct ipv4_ct_tuple tuple = {};

	if (data + ETH_HLEN + sizeof(*ip) > data_end)
		return DROP_INVALID;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_LB, skb->ingress_ifindex);

	nexthdr = ip->protocol;
	tuple.addr = ip->daddr;
	l3_off = ETH_HLEN;
	l4_off = ETH_HLEN + ipv4_hdrlen(ip);

	ret = lb4_extract_key(skb, &tuple, l4_off, &key, &csum_off);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNKNOWN_L4)
			/* Pass unknown L4 to stack */
			return TC_ACT_OK;
		else
			return ret;
	}

	/* Pass packets to the stack which should not be loadbalanced */
	if (lb4_skip(&CT_MAP4_NSLB, skb, &key, &tuple, &ct_state_prexlate, l4_off, 0))
		return TC_ACT_OK;

	slave = ct_state_prexlate.lb_slave_index;
	if (!(svc = lb4_lookup_slave(skb, &key, slave)))
		return DROP_NO_SERVICE;

	new_dst = svc->target;
	ret = lb4_xlate(skb, &new_dst, NULL, NULL, nexthdr, l3_off, l4_off, &csum_off, &key, svc);
	if (IS_ERR(ret))
		return ret;

	return TC_ACT_REDIRECT;
}
#endif

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	int ret;

	bpf_clear_cb(skb);

	switch (skb->protocol) {
#ifndef LB_DISABLE_IPV6
	case __constant_htons(ETH_P_IPV6):
		ret = handle_ipv6(skb);
		break;
#endif

#ifndef LB_DISABLE_IPV4
	case __constant_htons(ETH_P_IP):
		ret = handle_ipv4(skb);
		break;
#endif

	default:
		/* Pass unknown traffic to the stack */
		return TC_ACT_OK;
	}

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);

#ifdef LB_REDIRECT
	if (ret == TC_ACT_REDIRECT) {
		int ifindex = LB_REDIRECT;
#ifdef LB_DSTMAC
		union macaddr mac = LB_DSTMAC;

		if (eth_store_daddr(skb, (__u8 *) &mac.addr, 0) < 0)
			ret = DROP_WRITE_ERROR;
#endif
		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, ifindex);
		return redirect(ifindex, 0);
	}
#endif
	cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, 0);
	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
