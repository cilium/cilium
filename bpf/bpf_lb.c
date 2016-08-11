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
#include <lb_config.h>
#include <netdev_config.h>

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/icmp6.h"
#include "lib/l4.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/drop.h"

__BPF_MAP(cilium_lb_services, BPF_MAP_TYPE_HASH, 0, sizeof(struct lb_key), sizeof(struct lb_value), PIN_GLOBAL_NS, CILIUM_LB_MAP_SIZE);

static inline __u32 lb_hash(struct ipv6hdr *ip6, __u16 sport, __u16 dport)
{
	return ip6->saddr.s6_addr32[0] ^ ip6->saddr.s6_addr32[1] ^
	       ip6->saddr.s6_addr32[2] ^ ip6->saddr.s6_addr32[3] ^
	       ip6->daddr.s6_addr32[0] ^ ip6->daddr.s6_addr32[1] ^
	       ip6->daddr.s6_addr32[2] ^ ip6->daddr.s6_addr32[3] ^
	       (__u32)sport ^ (__u32)dport;
}

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	__u8 server_prefix[] = SERVER_PREFIX;
	__u8 router_ip[] = ROUTER_IP;
	__u8 nexthdr;
	__u32 proto = skb->protocol, hash;
	__be32 sum;
	__u16 sport;
	int l4_off, csum_off, ret = TC_ACT_OK;
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct lb_key key = {};
	struct lb_value *val;
	union v6addr lb_ip;

	if (likely(proto == __constant_htons(ETH_P_IPV6))) {
		struct ipv6hdr *ip6 = data + ETH_HLEN;
		union v6addr *dst = (union v6addr *) &ip6->daddr;

		ipv6_addr_copy(&lb_ip, (union v6addr *)router_ip);

		if (data + ETH_HLEN + sizeof(*ip6) > data_end) {
			ret = DROP_INVALID;
			goto error;
		}

		ipv6_addr_copy(&key.vip, dst);

		if (ipv6_addrcmp(&key.vip, &lb_ip))
			return TC_ACT_OK;

		cilium_trace_capture(skb, DBG_CAPTURE_FROM_LB, skb->ingress_ifindex);
		nexthdr = ip6->nexthdr;
		l4_off = ETH_HLEN + ipv6_hdrlen(skb, ETH_HLEN, &nexthdr);

#ifdef HANDLE_NS
		if (unlikely(nexthdr == IPPROTO_ICMPV6)) {
			ret = icmp6_handle(skb, ETH_HLEN, ip6);
			if (IS_ERR(ret))
				goto error;

		}
#endif

		csum_off = l4_checksum_offset(nexthdr);
		if (unlikely(!csum_off))
			goto error;

		switch (nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			/* Port offsets for UDP and TCP are the same */
			ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, &key.dport);
			if (IS_ERR(ret))
				goto error;

			ret = l4_load_port(skb, l4_off + TCP_SPORT_OFF, &sport);
			if (IS_ERR(ret))
				goto error;
			break;
		/* FIXME: ICMPv6 */
		default:
			ret = DROP_UNKNOWN_L4;
			goto error;
		}

		hash = lb_hash(ip6, sport, key.dport);
		cilium_trace(skb, DBG_PKT_HASH, hash, 0);

		key.dport = ntohs(key.dport);
		//cilium_trace(skb, DBG_GENERIC, key.vip.p1, 0);
		//cilium_trace(skb, DBG_GENERIC, key.vip.p2, 0);
		//cilium_trace(skb, DBG_GENERIC, key.vip.p3, 0);
		//cilium_trace(skb, DBG_GENERIC, key.vip.p4, 0);
		//cilium_trace(skb, DBG_GENERIC, key.dport, 0);
		val = map_lookup_elem(&cilium_lb_services, &key);
		if (val != NULL && val->lxc_count) {
			union macaddr lb_mac = NODE_MAC;
			union macaddr lxc_mac = LXC_MAC;
			int i, which = hash % val->lxc_count;

#pragma unroll
			for (i = 0; i < MAX_LXC; i++) {
				if (i != which)
					continue;

				ipv6_addr_copy(&lb_ip,
					       (union v6addr *) &server_prefix);
				ipv6_set_node_id(&lb_ip, val->lxc[i].node_id);
				ipv6_set_state(&lb_ip, val->state);
				ipv6_set_lxc_id(&lb_ip, val->lxc[i].lxc_id);
				if (key.dport != val->lxc[i].port) {
					__u16 tmp = htons(val->lxc[i].port);
					//cilium_trace(skb, DBG_GENERIC, val->lxc[i].port, 0);
					switch (nexthdr) {
					case IPPROTO_TCP:
					case IPPROTO_UDP:
					/* Port offsets for UDP and TCP are the same */
						ret = l4_modify_port(skb, l4_off + TCP_DPORT_OFF,
								     csum_off, tmp,
								     htons(key.dport));
						if (IS_ERR(ret))
							goto error;
						break;
					/* FIXME: Handle ICMPv6 */
					/* default handled outside the loop */
					}
				}
			}

			ipv6_store_daddr(skb, lb_ip.addr, ETH_HLEN);

			/* fixup csums */
			sum = csum_diff(key.vip.addr, 16, lb_ip.addr, 16, 0);
			if (l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0) {
				ret = DROP_CSUM_L4;
				goto error;
			}

			eth_store_saddr(skb, lb_mac.addr, 0);
			eth_store_daddr(skb, lxc_mac.addr, 0);

			cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, LB_SERVER_IFINDEX);
			ret = redirect(LB_SERVER_IFINDEX, 0);
		} else {
			cilium_trace(skb, DBG_LB_SERVICES_LOOKUP_FAIL, key.vip.p4, key.dport);
		}
	}

	if (IS_ERR(ret)) {
error:
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);
	} else
		return ret;
}

BPF_LICENSE("GPL");
