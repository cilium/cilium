/*
 *  Copyright (C) 2016-2019 Authors of Cilium
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
#ifndef __LIB_LXC_H_
#define __LIB_LXC_H_

#include "common.h"
#include "utils.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "dbg.h"
#include "trace.h"
#include "csum.h"
#include "l4.h"

#define TEMPLATE_LXC_ID 0xffff

#ifndef DISABLE_SIP_VERIFICATION
static inline int is_valid_lxc_src_ip(struct ipv6hdr *ip6)
{
#ifdef ENABLE_IPV6
	union v6addr valid = {};

	BPF_V6(valid, LXC_IP);

	return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
#else
	return 0;
#endif
}

static inline int is_valid_lxc_src_ipv4(struct iphdr *ip4)
{
#ifdef ENABLE_IPV4
	return ip4->saddr == LXC_IPV4;
#else
	/* Can't send IPv4 if no IPv4 address is configured */
	return 0;
#endif
}
#else
static inline int is_valid_lxc_src_ip(struct ipv6hdr *ip6)
{
	return 1;
}

static inline int is_valid_lxc_src_ipv4(struct iphdr *ip4)
{
	return 1;
}
#endif

static inline int __inline__
skb_redirect_to_proxy(struct __sk_buff *skb, __be16 proxy_port)
{
	skb->mark = MARK_MAGIC_TO_PROXY | proxy_port << 16;
	skb_change_type(skb, PACKET_HOST); // Required ingress packets from overlay
	cilium_dbg_capture(skb, DBG_CAPTURE_PROXY_POST, proxy_port);	
	return TC_ACT_OK;
}

/**
 * skb_redirect_to_proxy_hairpin redirects to the proxy by hairpining the
 * packet out the incoming interface
 */
static inline int __inline__
skb_redirect_to_proxy_hairpin(struct __sk_buff *skb, __be16 proxy_port)
{
	union macaddr host_mac = HOST_IFINDEX_MAC;
	union macaddr router_mac = NODE_MAC;
	void *data_end = (void *) (long) skb->data_end;
	void *data = (void *) (long) skb->data;
	struct iphdr *ip4;
	int ret;

	skb->cb[0] = MARK_MAGIC_TO_PROXY | (proxy_port << 16);

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	ret = ipv4_l3(skb, ETH_HLEN, (__u8 *) &router_mac, (__u8 *) &host_mac, ip4);
	if (IS_ERR(ret))
		return ret;

	cilium_dbg_capture(skb, DBG_CAPTURE_PROXY_POST, proxy_port);

	return redirect(HOST_IFINDEX, 0);
}

/**
 * tc_index_is_from_proxy - returns true if packet originates from ingress proxy
 */
static inline bool __inline__ tc_index_skip_proxy(struct __sk_buff *skb)
{
	volatile __u32 tc_index = skb->tc_index;
#ifdef DEBUG
	if (tc_index & TC_INDEX_F_SKIP_PROXY)
		cilium_dbg(skb, DBG_SKIP_PROXY, tc_index, 0);
#endif

	return tc_index & TC_INDEX_F_SKIP_PROXY;
}
#endif /* __LIB_LXC_H_ */
