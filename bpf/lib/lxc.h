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
#ifndef __LIB_LXC_H_
#define __LIB_LXC_H_

#include "common.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "dbg.h"
#include "csum.h"
#include "l4.h"

#ifndef DISABLE_SMAC_VERIFICATION
static inline int is_valid_lxc_src_mac(struct ethhdr *eth)
{
	union macaddr valid = LXC_MAC;

	return !eth_addrcmp(&valid, (union macaddr *) &eth->h_source);
}
#else
static inline int is_valid_lxc_src_mac(struct ethhdr *eth)
{
	return 1;
}
#endif

#ifndef DISABLE_SIP_VERIFICATION
static inline int is_valid_lxc_src_ip(struct ipv6hdr *ip6)
{
	union v6addr valid = {};

	BPF_V6(valid, LXC_IP);

	return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
}

static inline int is_valid_lxc_src_ipv4(struct iphdr *ip4)
{
#ifdef LXC_IPV4
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

#ifndef DISABLE_DMAC_VERIFICATION
static inline int is_valid_gw_dst_mac(struct ethhdr *eth)
{
	union macaddr valid = NODE_MAC;

	return !eth_addrcmp(&valid, (union macaddr *) &eth->h_dest);
}
#else
static inline int is_valid_gw_dst_mac(struct ethhdr *eth)
{
	return 1;
}
#endif

#ifdef LXC_IPV4
static inline int __inline__
ipv4_redirect_to_host_port(struct __sk_buff *skb, struct csum_offset *csum,
			  int l4_off, __u16 new_port, __u16 old_port, __be32 old_ip,
			  struct ipv4_ct_tuple *tuple, __u32 identity)
{
	__be32 host_ip = IPV4_GATEWAY;
	struct proxy4_tbl_key key = {
		.saddr = tuple->daddr,
		.sport = tuple->sport,
		.dport = new_port,
		.nexthdr = tuple->nexthdr,
	};
	struct proxy4_tbl_value value = {
		.orig_daddr = old_ip,
		.orig_dport = old_port,
		.lifetime = 360,
		.identity = identity,
	};

	cilium_trace_capture(skb, DBG_CAPTURE_PROXY_PRE, old_port);

	if (l4_modify_port(skb, l4_off, TCP_DPORT_OFF, csum,
			   new_port, old_port) < 0)
		return DROP_WRITE_ERROR;

	if (skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &host_ip, 4, 0) < 0)
		return DROP_WRITE_ERROR;

	if (l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), old_ip, host_ip, 4) < 0)
		return DROP_CSUM_L3;

	if (csum->offset &&
	    csum_l4_replace(skb, l4_off, csum, old_ip, host_ip, 4 | BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	cilium_trace_capture(skb, DBG_CAPTURE_PROXY_POST, new_port);

	cilium_trace3(skb, DBG_REV_PROXY_UPDATE,
		     key.sport << 16 | key.dport, key.saddr, key.nexthdr);
	if (map_update_elem(&cilium_proxy4, &key, &value, 0) < 0)
		return DROP_CT_CREATE_FAILED;

	return 0;
}
#endif /* LXC_IPV4 */

static inline int __inline__
ipv6_redirect_to_host_port(struct __sk_buff *skb, struct csum_offset *csum,
			  int l4_off, __u16 new_port, __u16 old_port,
			  union v6addr old_ip, struct ipv6_ct_tuple *tuple, union v6addr *host_ip,
			  __u32 identity)
{
	struct proxy6_tbl_key key = {
		.saddr = tuple->daddr,
		.sport = tuple->sport,
		.dport = new_port,
		.nexthdr = tuple->nexthdr,
	};
	struct proxy6_tbl_value value = {
		.orig_daddr = old_ip,
		.orig_dport = old_port,
		.lifetime = 360,
		.identity = identity,
	};

	if (l4_modify_port(skb, l4_off, TCP_DPORT_OFF, csum, new_port, old_port) < 0)
		return DROP_WRITE_ERROR;

	if (ipv6_store_daddr(skb, host_ip->addr, ETH_HLEN) > 0)
		return DROP_WRITE_ERROR;

	if (csum->offset) {
		__be32 sum = csum_diff(old_ip.addr, 16, host_ip->addr, 16, 0);

		if (csum_l4_replace(skb, l4_off, csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

	if (map_update_elem(&cilium_proxy6, &key, &value, 0) < 0)
		return DROP_CT_CREATE_FAILED;

	return 0;
}
#endif
