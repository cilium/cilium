#include <node_config.h>
#include <lxc_config.h>

#include <iproute2/bpf_api.h>

#include <sys/socket.h>

#include <stdint.h>
#include <string.h>

#include "lib/common.h"
#include "lib/ipv6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/lxc.h"

static inline int is_node_subnet(const union v6addr *dst)
{
	union v6addr node = { . addr = ROUTER_IP };
	int tmp;

	tmp = dst->p1 - node.p1;
	if (!tmp) {
		tmp = dst->p2 - node.p2;
		if (!tmp) {
			tmp = dst->p3 - node.p3;
			if (!tmp)
				tmp = (dst->p4 & 0xFFFF0000) - (node.p4 & 0xFFFF0000);
		}
	}

	return !tmp;
}

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	int nh_off = ETH_HLEN;

	if (likely(skb->protocol == __constant_htons(ETH_P_IPV6))) {
		union v6addr dst = {};

		printk("IPv6 packet from netdev skb %p len %d\n", skb, skb->len);

		load_ipv6_daddr(skb, nh_off, &dst);

		if (is_node_subnet(&dst)) {
			printk("Targeted for a local container\n");

			return do_l3(skb, nh_off, &dst);
		}
	}

	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
