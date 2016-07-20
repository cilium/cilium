#include <lb_config.h>
#include <netdev_config.h>

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/icmp6.h"
#include "lib/tcp.h"
#include "lib/udp.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/drop.h"

__BPF_MAP(cilium_lb1, BPF_MAP_TYPE_HASH, CILIUM_MAP_LB1, sizeof(struct lb_key), sizeof(struct lb_value), PIN_GLOBAL_NS, 32);

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
	__u8 lba[] = ROUTER_IP;
	__u32 proto = skb->protocol;
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	union v6addr lb_ip;
	struct lb_key key = {};
	__u16 sport;
	__u32 hash;
	struct lb_value *val;
	int off = ETH_HLEN + sizeof(struct ipv6hdr);
	int ret = TC_ACT_OK;

	memcpy(&lb_ip.addr, lba, sizeof(lba));

	if (likely(proto == __constant_htons(ETH_P_IPV6))) {
		struct ipv6hdr *ip6 = data + ETH_HLEN;
		union v6addr *dst = (union v6addr *) &ip6->daddr;

		cilium_trace_capture(skb, DBG_CAPTURE_FROM_NETDEV, skb->ingress_ifindex);

		if (data + ETH_HLEN + sizeof(*ip6) > data_end) {
			ret = DROP_INVALID;
			goto error;
		}

		memcpy(&key.vip, dst, sizeof(*dst));

		if (ipv6_addrcmp(&key.vip, &lb_ip))
			return TC_ACT_OK;

		if (unlikely(ip6->nexthdr == IPPROTO_ICMPV6)) {
			int ret = icmp6_handle(skb, ETH_HLEN, ip6);
			if (IS_ERR(ret))
				goto error;

		}

		switch (ip6->nexthdr) {
		case IPPROTO_TCP:
			tcp_load_dport(skb, off, &key.dport);
			tcp_load_sport(skb, off, &sport);
			break;
		case IPPROTO_UDP:
			udp_load_dport(skb, off, &key.dport);
			udp_load_sport(skb, off, &sport);
			break;
		default:
			ret = DROP_UNKNOWN_L4;
			goto error;
		}

		hash = lb_hash(ip6, sport, key.dport);
		//cilium_trace(skb, DBG_GENERIC, hash, 0);

		key.dport = ntohs(key.dport);
		//cilium_trace(skb, DBG_GENERIC, key.vip.p1, 0);
		//cilium_trace(skb, DBG_GENERIC, key.vip.p2, 0);
		//cilium_trace(skb, DBG_GENERIC, key.vip.p3, 0);
		//cilium_trace(skb, DBG_GENERIC, key.vip.p4, 0);
		//cilium_trace(skb, DBG_GENERIC, key.dport, 0);
		val = map_lookup_elem(&cilium_lb1, &key);
		if (val != NULL && val->lxc_count) {
			union macaddr lb_mac = SERVER_MAC;
			int i, which = hash % val->lxc_count;

#pragma unroll
			for (i = 0; i < MAX_LXC; i++) {
				if (i != which)
					continue;

				ipv6_set_node_id(&lb_ip, val->lxc[i].node_id);
				ipv6_set_state(&lb_ip, val->state);
				ipv6_set_lxc_id(&lb_ip, val->lxc[i].lxc_id);
				if (key.dport != val->lxc[i].port) {
					__u16 tmp = htons(val->lxc[i].port);
					cilium_trace(skb, DBG_GENERIC, val->lxc[i].port, 0);
					switch (ip6->nexthdr) {
					case IPPROTO_TCP:
						tcp_store_dport(skb, off, tmp);
						break;
					case IPPROTO_UDP:
						udp_store_dport(skb, off, tmp);
						break;
					default:
						ret = DROP_UNKNOWN_L4;
						goto error;
					}
				}
			}

			ipv6_store_daddr(skb, lb_ip.addr, ETH_HLEN);
			eth_store_saddr(skb, lb_mac.addr, 0);

			cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, SERVER_IFINDEX);
			ret = redirect(SERVER_IFINDEX, 0);
		} else {
			//cilium_trace(skb, DBG_GENERIC, 100, 0);
		}
	}

	if (IS_ERR(ret)) {
error:
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);
	} else
		return ret;
}

BPF_LICENSE("GPL");
