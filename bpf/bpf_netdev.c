#include <node_config.h>

#include <iproute2/bpf_api.h>

#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/ipv6.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"

static inline int is_node_subnet(const union v6addr *dst)
{
	union v6addr node = { . addr = ROUTER_IP };
	int tmp;

	tmp = dst->p1 - node.p1;
	if (!tmp) {
		tmp = dst->p2 - node.p2;
		if (!tmp) {
			tmp = dst->p3 - node.p3;
			if (!tmp) {
				__u32 a = ntohl(dst->p4);
				__u32 b = ntohl(node.p4);
				tmp = (a & 0xFFFF0000) - (b & 0xFFFF0000);
			}
		}
	}

	return !tmp;
}

static inline int handle_icmp6_solicitation(struct __sk_buff *skb, int nh_off)
{
	union v6addr target = {}, router = { . addr = ROUTER_IP };

	if (skb_load_bytes(skb, nh_off + ICMP6_ND_TARGET_OFFSET, target.addr,
			   sizeof(((struct ipv6hdr *)NULL)->saddr)) < 0)
		return TC_ACT_SHOT;

	if (compare_ipv6_addr(&target, &router) == 0) {
		union macaddr router_mac = NODE_MAC;

		return send_icmp6_ndisc_adv(skb, nh_off, &router_mac);
	} else {
		/* Unknown target address, drop */
		return TC_ACT_SHOT;
	}
}

static inline int handle_icmp6(struct __sk_buff *skb, int nh_off)
{
	union v6addr dst = {};
	union v6addr router_ip = { .addr = ROUTER_IP };
	__u8 type = icmp6_load_type(skb, nh_off);
	int ret = TC_ACT_UNSPEC;

	printk("ICMPv6 packet skb %p len %d type %d\n", skb, skb->len, type);

	load_ipv6_daddr(skb, nh_off, &dst);

	switch(type) {
	case 135:
		ret = handle_icmp6_solicitation(skb, nh_off);
		break;
	case 128:
		if (!compare_ipv6_addr(&dst, &router_ip)) {
			ret = send_icmp6_echo_response(skb, nh_off);
			break;
		}
	case 129:
		ret = LXC_REDIRECT;
		break;
	default:
		break;
	}

	return ret;
}

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	int nh_off = ETH_HLEN, ret;

	if (likely(skb->protocol == __constant_htons(ETH_P_IPV6))) {
		union v6addr dst = {};
		__u8 nexthdr;

		nexthdr = load_byte(skb, nh_off + offsetof(struct ipv6hdr, nexthdr));
		if (unlikely(nexthdr == IPPROTO_ICMPV6)) {
			ret = handle_icmp6(skb, nh_off);
			if (ret != LXC_REDIRECT)
				return ret;
		}

		printk("IPv6 packet from netdev skb %p len %d\n", skb, skb->len);

		load_ipv6_daddr(skb, nh_off, &dst);

		if (is_node_subnet(&dst)) {
			printk("Targeted for a local container\n");

			/* FIXME: Derive correct seclabel */
			return do_l3(skb, nh_off, &dst, 0);
		}
	}

	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
