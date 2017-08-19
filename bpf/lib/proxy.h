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
#ifndef __LIB_PROXY_H_
#define __LIB_PROXY_H_

/*
 * NOTE: You *must* include "conntrack.h" before including this header
 */

#include "common.h"

struct bpf_elf_map __section_maps cilium_proxy4 = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct proxy4_tbl_key),
	.size_value	= sizeof(struct proxy4_tbl_value),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 8192,
};

struct bpf_elf_map __section_maps cilium_proxy6= {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct proxy6_tbl_key),
	.size_value	= sizeof(struct proxy6_tbl_value),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 8192,
};

static inline int __inline__
reverse_proxy(struct __sk_buff *skb, int l4_off, struct iphdr *ip4,
	      struct ipv4_ct_tuple *tuple)
{
	struct proxy4_tbl_value *val;
	struct proxy4_tbl_key key = {
		.saddr = ip4->daddr,
		.nexthdr = tuple->nexthdr,
	};
	__be32 new_saddr, old_saddr = ip4->saddr;
	__be16 new_sport, old_sport;
	struct csum_offset csum = {};

	switch (tuple->nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		/* load sport + dport in reverse order, sport=dport, dport=sport */
		if (skb_load_bytes(skb, l4_off, &key.dport, 4) < 0)
			return DROP_CT_INVALID_HDR;
		break;
	default:
		/* ignore */
		return 0;
	}

	csum_l4_offset_and_flags(tuple->nexthdr, &csum);

	cilium_trace3(skb, DBG_REV_PROXY_LOOKUP, key.sport << 16 | key.dport,
		      key.saddr, key.nexthdr);

	val = map_lookup_elem(&cilium_proxy4, &key);
	if (!val)
		return 0;

	new_saddr = val->orig_daddr;
	new_sport = val->orig_dport;
	old_sport = key.dport;

	cilium_trace(skb, DBG_REV_PROXY_FOUND, new_saddr, bpf_ntohs(new_sport));
	cilium_trace_capture(skb, DBG_CAPTURE_PROXY_PRE, 0);

	if (l4_modify_port(skb, l4_off, TCP_SPORT_OFF, &csum, new_sport, old_sport) < 0)
		return DROP_WRITE_ERROR;

	if (skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &new_saddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;

	if (l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), old_saddr, new_saddr, 4) < 0)
		return DROP_CSUM_L3;

	if (csum.offset &&
	    csum_l4_replace(skb, l4_off, &csum, old_saddr, new_saddr, 4 | BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	cilium_trace_capture(skb, DBG_CAPTURE_PROXY_POST, 0);

	return 0;
}

static inline int __inline__
reverse_proxy6(struct __sk_buff *skb, int l4_off, struct ipv6hdr *ip6, __u8 nh)
{
	struct proxy6_tbl_value *val;
	struct proxy6_tbl_key key = {
		.nexthdr = nh,
	};
	union v6addr new_saddr, old_saddr;
	struct csum_offset csum = {};
	__be16 new_sport, old_sport;
	int ret;

	switch (nh) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		/* load sport + dport in reverse order, sport=dport, dport=sport */
		if (skb_load_bytes(skb, l4_off, &key.dport, 4) < 0)
			return DROP_CT_INVALID_HDR;
		break;
	default:
		/* ignore */
		return 0;
	}

	ipv6_addr_copy(&key.saddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&old_saddr, (union v6addr *) &ip6->saddr);
	csum_l4_offset_and_flags(nh, &csum);

	val = map_lookup_elem(&cilium_proxy6, &key);
	if (!val)
		return 0;

	ipv6_addr_copy(&new_saddr, (union v6addr *)&val->orig_daddr);
	new_sport = val->orig_dport;
	old_sport = key.dport;

	ret = l4_modify_port(skb, l4_off, TCP_SPORT_OFF, &csum, new_sport, old_sport);
	if (ret < 0)
		return DROP_WRITE_ERROR;

	ret = ipv6_store_saddr(skb, new_saddr.addr, ETH_HLEN);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	if (csum.offset) {
		__be32 sum = csum_diff(old_saddr.addr, 16, new_saddr.addr, 16, 0);

		if (csum_l4_replace(skb, l4_off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

	return 0;
}

#endif /* __LIB_PROXY_H_ */
