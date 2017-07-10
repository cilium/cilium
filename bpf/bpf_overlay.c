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
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/geneve.h"
#include "lib/drop.h"
#include "lib/policy.h"

static inline int handle_ipv6(struct __sk_buff *skb)
{
	void *data_end = (void *) (long) skb->data_end;
	void *data = (void *) (long) skb->data;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	struct bpf_tunnel_key key = {};
	struct endpoint_info *ep;
	int l4_off, l3_off = ETH_HLEN;

	if (data + sizeof(*ip6) + l3_off > data_end)
		return DROP_INVALID;

	if (unlikely(skb_get_tunnel_key(skb, &key, sizeof(key), 0) < 0))
		return DROP_NO_TUNNEL_KEY;

	cilium_trace(skb, DBG_DECAP, key.tunnel_id, key.tunnel_label);

#ifdef ENCAP_GENEVE
	if (1) {
		uint8_t buf[MAX_GENEVE_OPT_LEN] = {};
		struct geneveopt_val geneveopt_val = {};
		int ret;

		if (unlikely(skb_get_tunnel_opt(skb, buf, sizeof(buf)) < 0))
			return DROP_NO_TUNNEL_OPT;

		ret = parse_geneve_options(&geneveopt_val, buf);
		if (IS_ERR(ret))
			return ret;
	}
#endif

	/* Lookup IPv6 address in list of local endpoints */
	if ((ep = lookup_ip6_endpoint(ip6)) != NULL) {
		/* Let through packets to the node-ip so they are
		 * processed by the local ip stack */
		if (ep->flags & ENDPOINT_F_HOST)
			goto to_host;

		__u8 nexthdr = ip6->nexthdr;
		l4_off = l3_off + ipv6_hdrlen(skb, l3_off, &nexthdr);
		return ipv6_local_delivery(skb, l3_off, l4_off, key.tunnel_id, ip6, nexthdr, ep);
	} else {
		return DROP_NON_LOCAL;
	}

to_host:
#ifdef HOST_IFINDEX
	if (1) {
		union macaddr host_mac = HOST_IFINDEX_MAC;
		union macaddr router_mac = NODE_MAC;
		int ret;

		cilium_trace(skb, DBG_TO_HOST, is_policy_skip(skb), 0);

		ret = ipv6_l3(skb, ETH_HLEN, (__u8 *) &router_mac.addr, (__u8 *) &host_mac.addr);
		if (ret != TC_ACT_OK)
			return ret;

		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return redirect(HOST_IFINDEX, 0);
	}
#else
	return TC_ACT_OK;
#endif
}

#ifdef ENABLE_IPV4

static inline int handle_ipv4(struct __sk_buff *skb)
{
	void *data_end = (void *) (long) skb->data_end;
	void *data = (void *) (long) skb->data;
	struct iphdr *ip4 = data + ETH_HLEN;
	struct endpoint_info *ep;
	struct bpf_tunnel_key key = {};
	int l4_off;

	if (data + sizeof(*ip4) + ETH_HLEN > data_end)
		return DROP_INVALID;

	if (unlikely(skb_get_tunnel_key(skb, &key, sizeof(key), 0) < 0))
		return DROP_NO_TUNNEL_KEY;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	/* Lookup IPv4 address in list of local endpoints */
	if ((ep = lookup_ip4_endpoint(ip4)) != NULL) {
		/* Let through packets to the node-ip so they are
		 * processed by the local ip stack */
		if (ep->flags & ENDPOINT_F_HOST)
			goto to_host;

		return ipv4_local_delivery(skb, ETH_HLEN, l4_off, key.tunnel_id, ip4, ep);
	} else {
		return DROP_NON_LOCAL;
	}

to_host:
#ifdef HOST_IFINDEX
	if (1) {
		union macaddr host_mac = HOST_IFINDEX_MAC;
		union macaddr router_mac = NODE_MAC;
		int ret;

		cilium_trace(skb, DBG_TO_HOST, is_policy_skip(skb), 0);

		ret = ipv4_l3(skb, ETH_HLEN, (__u8 *) &router_mac.addr, (__u8 *) &host_mac.addr, ip4);
		if (ret != TC_ACT_OK)
			return ret;

		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return redirect(HOST_IFINDEX, 0);
	}
#else
	return TC_ACT_OK;
#endif
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4) int tail_handle_ipv4(struct __sk_buff *skb)
{
	int ret = handle_ipv4(skb);

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);

	return ret;
}

#endif

__section("from-overlay")
int from_overlay(struct __sk_buff *skb)
{
	int ret;

	bpf_clear_cb(skb);

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_OVERLAY, skb->ingress_ifindex);

	switch (skb->protocol) {
	case bpf_htons(ETH_P_IPV6):
		/* This is considered the fast path, no tail call */
		ret = handle_ipv6(skb);
		break;

	case bpf_htons(ETH_P_IP):
#ifdef ENABLE_IPV4
		ep_tail_call(skb, CILIUM_CALL_IPV4);
		ret = DROP_MISSED_TAIL_CALL;
#else
		ret = DROP_UNKNOWN_L3;
#endif
		break;

	default:
		/* Pass unknown traffic to the stack */
		ret = TC_ACT_OK;
	}

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);
	else
		return ret;
}

struct bpf_elf_map __section_maps POLICY_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct policy_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 1024,
};

__section_tail(CILIUM_MAP_RES_POLICY, SECLABEL) int handle_policy(struct __sk_buff *skb)
{
	__u32 src_label = skb->cb[CB_SRC_LABEL];
	int ifindex = skb->cb[CB_IFINDEX];

	if (policy_can_access(&POLICY_MAP, skb, src_label, 0, NULL) != TC_ACT_OK) {
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
