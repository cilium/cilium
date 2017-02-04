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
#include <node_config.h>
#include <netdev_config.h>

/* These are configuartion options which have a default value in their
 * respective header files and must thus be defined beforehand:
 *
 * Pass unknown ICMPv6 NS to stack */
#define ACTION_UNKNOWN_ICMP6_NS TC_ACT_OK

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/policy.h"
#include "lib/drop.h"

static inline __u32 derive_sec_ctx(struct __sk_buff *skb, const union v6addr *node_ip,
				   struct ipv6hdr *ip6)
{
#ifdef FIXED_SRC_SECCTX
	return FIXED_SRC_SECCTX;
#else
	if (ipv6_match_prefix_64((union v6addr *) &ip6->saddr, node_ip)) {
		/* Read initial 4 bytes of header and then extract flowlabel */
		__u32 *tmp = (__u32 *) ip6;
		return ntohl(*tmp & IPV6_FLOWLABEL_MASK);
	}

	return WORLD_ID;
#endif
}

static inline int handle_ipv6(struct __sk_buff *skb)
{
	union v6addr node_ip = { . addr = ROUTER_IP };
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	union v6addr *dst = (union v6addr *) &ip6->daddr;
	int l4_off, l3_off = ETH_HLEN;
	__u8 nexthdr;
	__u32 flowlabel;

	if (data + l3_off + sizeof(*ip6) > data_end)
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	l4_off = l3_off + ipv6_hdrlen(skb, l3_off, &nexthdr);

#ifdef HANDLE_NS
	if (unlikely(nexthdr == IPPROTO_ICMPV6)) {
		int ret = icmp6_handle(skb, ETH_HLEN, ip6);
		if (IS_ERR(ret))
			return ret;
	}
#endif

	flowlabel = derive_sec_ctx(skb, &node_ip, ip6);

	if (likely(ipv6_match_prefix_96(dst, &node_ip)))
		return ipv6_local_delivery(skb, l3_off, l4_off, flowlabel, ip6, nexthdr);

	return TC_ACT_OK;
}

#ifdef ENABLE_IPV4
static inline __u32 derive_ipv4_sec_ctx(struct __sk_buff *skb, struct iphdr *ip4)
{
#ifdef FIXED_SRC_SECCTX
	return FIXED_SRC_SECCTX;
#else
	__u32 secctx = WORLD_ID;

	if ((ip4->saddr & IPV4_CLUSTER_MASK) == IPV4_CLUSTER_RANGE) {
		/* FIXME: Derive */
	}
	return secctx;
#endif
}

static inline int handle_ipv4(struct __sk_buff *skb)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct iphdr *ip4 = data + ETH_HLEN;

	if (data + sizeof(*ip4) + ETH_HLEN > data_end)
		return DROP_INVALID;

#ifdef ENABLE_IPV4
	/* Check if destination is within our cluster prefix */
	if ((ip4->daddr & IPV4_MASK) == IPV4_RANGE) {
		struct ipv4_ct_tuple tuple = {};
		__u32 secctx;
		int ret, l4_off;

		l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
		secctx = derive_ipv4_sec_ctx(skb, ip4);
		tuple.nexthdr = ip4->protocol;
		ret = ipv4_local_delivery(skb, ETH_HLEN, l4_off, secctx, ip4);
		if (ret != DROP_NO_LXC)
			return ret;
	}
#endif

	return TC_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4) int tail_handle_ipv4(struct __sk_buff *skb)
{
	int ret = handle_ipv4(skb);

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);

	return ret;
}

#endif

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	int ret;

	bpf_clear_cb(skb);

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_NETDEV, skb->ingress_ifindex);

	switch (skb->protocol) {
	case __constant_htons(ETH_P_IPV6):
		/* This is considered the fast path, no tail call */
		ret = handle_ipv6(skb);

		/* We should only be seeing an error here for packets which have
		 * been targetting an endpoint managed by us. */
		if (IS_ERR(ret))
			return send_drop_notify_error(skb, ret, TC_ACT_SHOT);
		break;

#ifdef ENABLE_IPV4
	case __constant_htons(ETH_P_IP):
		tail_call(skb, &cilium_calls, CILIUM_CALL_IPV4);
		/* We are not returning an error here to always allow traffic to
		 * the stack in case maps have become unavailable.
		 *
		 * Note: Since drop notification requires a tail call as well,
		 * this notification is unlikely to succeed. */
		return send_drop_notify_error(skb, DROP_MISSED_TAIL_CALL, TC_ACT_OK);
#endif

	default:
		/* Pass unknown traffic to the stack */
		ret = TC_ACT_OK;
	}

	return ret;
}

__BPF_MAP(POLICY_MAP, BPF_MAP_TYPE_HASH, 0, sizeof(__u32),
	  sizeof(struct policy_entry), PIN_GLOBAL_NS, 1024);

__section_tail(CILIUM_MAP_RES_POLICY, SECLABEL) int handle_policy(struct __sk_buff *skb)
{
	__u32 src_label = skb->cb[CB_SRC_LABEL];
	int ifindex = skb->cb[CB_IFINDEX];

	if (policy_can_access(&POLICY_MAP, skb, src_label) != TC_ACT_OK) {
		return send_drop_notify(skb, src_label, SECLABEL, 0,
					ifindex, TC_ACT_SHOT);
	} else {
		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, ifindex);

		/* ifindex 0 indicates passing down to the stack */
		if (ifindex == 0)
			return TC_ACT_OK;
		else
			return redirect(ifindex, 0);
	}
}

BPF_LICENSE("GPL");
