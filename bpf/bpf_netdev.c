#define NODE_MAC { .addr = { 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde } }

#include <node_config.h>

#include <iproute2/bpf_api.h>

#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/nat46.h"

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

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
#ifdef ENABLE_NAT46
	/* First try to do v46 nat */
	if (skb->protocol == __constant_htons(ETH_P_IP)) {
		union v6addr sp = NAT46_SRC_PREFIX;
		union v6addr dp = NAT46_DST_PREFIX;
		__u32 dst = 0;
		int ret;

		if (ipv4_load_daddr(skb, ETH_HLEN, &dst) < 0)
			return TC_ACT_SHOT;

		if ((dst & IPV4_MASK) != IPV4_RANGE)
			return TC_ACT_OK;

		ret = ipv4_to_ipv6(skb, 14, &sp, &dp);
		if (ret == -1) {
			printk("ipv4_to_ipv6 failed\n");
			return ret;
		}
		skb->tc_index = 1;
	}
#endif

	if (likely(skb->protocol == __constant_htons(ETH_P_IPV6))) {
		union v6addr dst = {};
		__u32 flowlabel = 0;
#ifdef HANDLE_NS
		__u8 nexthdr;

		nexthdr = load_byte(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr));
		if (unlikely(nexthdr == IPPROTO_ICMPV6)) {
			int ret = icmp6_handle(skb, ETH_HLEN);
			if (ret != LXC_REDIRECT)
				return ret;
		}
#endif
		printk("IPv6 packet from netdev skb %p len %d\n", skb, skb->len);

		load_ipv6_daddr(skb, ETH_HLEN, &dst);
		ipv6_load_flowlabel(skb, ETH_HLEN, &flowlabel);

		if (is_node_subnet(&dst)) {
			printk("Targeted for a local container, src label: %d\n",
				ntohl(flowlabel));

			return do_l3(skb, ETH_HLEN, &dst, ntohl(flowlabel));
		}
	}

	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
