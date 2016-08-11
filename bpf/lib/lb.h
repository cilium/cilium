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
#ifndef __LB_H_
#define __LB_H_

__BPF_MAP(cilium_lb_state, BPF_MAP_TYPE_HASH, CILIUM_MAP_LB_STATE, sizeof(__u16), sizeof(struct lb_value), PIN_GLOBAL_NS, CILIUM_LB_MAP_SIZE);

static inline int lb_dsr_dnat(struct __sk_buff *skb, __u16 state, struct ipv6_ct_tuple *tuple)
{
	struct lb_value *val;
	int off = ETH_HLEN + sizeof(struct ipv6hdr), ret;

	val = map_lookup_elem(&cilium_lb_state, &state);
	if (val != NULL) {
		union v6addr tmp = {}, sip;
		__u16 sport;
		int csum_off;
		__be32 sum;

		if (ipv6_load_saddr(skb, ETH_HLEN, &sip) < 0)
			return DROP_INVALID;

		csum_off = l4_checksum_offset(tuple->nexthdr);
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			/* Port offsets for UDP and TCP are the same */
			ret = l4_load_port(skb, off + TCP_SPORT_OFF, &sport);
			if (IS_ERR(ret))
				return ret;
			ret = l4_modify_port(skb, off + TCP_SPORT_OFF, csum_off,
					     htons(val->dport), sport);
			if (IS_ERR(ret))
				return ret;
			break;

		default:
			return DROP_UNKNOWN_L4;
		}

		tmp.p1 = val->vip.p1;
		tmp.p2 = val->vip.p2;
		tmp.p3 = val->vip.p3;
		tmp.p4 = val->vip.p4;
		ret = ipv6_store_saddr(skb, tmp.addr, ETH_HLEN);
		if (IS_ERR(ret))
			return DROP_WRITE_ERROR;

		sum = csum_diff(sip.addr, 16, tmp.addr, 16, 0);
		if (l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

	return 0;
}

#endif /* __LB_H_ */
