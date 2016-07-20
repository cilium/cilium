#ifndef __LB_H_
#define __LB_H_

__BPF_MAP(cilium_lb2, BPF_MAP_TYPE_HASH, CILIUM_MAP_LB2, sizeof(__u16), sizeof(struct lb_value), PIN_GLOBAL_NS, 32);

static inline int lb_dsr_dnat(struct __sk_buff *skb, __u16 state)
{
	struct lb_value *val;
	int off = ETH_HLEN + sizeof(struct ipv6hdr);

	val = map_lookup_elem(&cilium_lb2, &state);
	if (val != NULL) {
		__u8 nexthdr;
		union v6addr tmp = {};

		if (ipv6_load_nexthdr(skb, ETH_HLEN, &nexthdr) < 0)
			return DROP_INVALID;

		switch (nexthdr) {
		case IPPROTO_TCP:
			tcp_store_dport(skb, off, htons(val->dport));
			break;

		case IPPROTO_UDP:
			udp_store_dport(skb, off, htons(val->dport));
			break;

		default:
			return DROP_UNKNOWN_L4;
		}

		tmp.p1 = val->vip.p1;
		tmp.p2 = val->vip.p2;
		tmp.p3 = val->vip.p3;
		tmp.p4 = val->vip.p4;
		ipv6_store_daddr(skb, tmp.addr, ETH_HLEN);
	}

	return 0;
}

#endif /* __LB_H_ */
