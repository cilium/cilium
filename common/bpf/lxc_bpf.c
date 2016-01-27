#include <node_config.h>
#include <lxc_config.h>

#include <iproute2/bpf_api.h>

#include <linux/icmpv6.h>
#include <sys/socket.h>

#include <stdint.h>
#include <string.h>

#include "lib/common.h"
#include "lib/ipv6.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/lxc.h"

static inline int __inline__ do_l3_from_lxc(struct __sk_buff *skb, int nh_off)
{
	union v6addr dst = {};
	__u32 node_id;

	printk("L3 from lxc: skb %p len %d\n", skb, skb->len);

	if (verify_src_mac(skb) || verify_src_ip(skb, nh_off) ||
	    verify_dst_mac(skb))
		return TC_ACT_SHOT;

	load_ipv6_daddr(skb, nh_off, &dst);
	node_id = derive_node_id(&dst);

	printk("node_id %x local %x\n", node_id, NODE_ID);

	if (node_id != NODE_ID) {
#ifdef ENCAP_IFINDEX
		return do_encapsulation(skb, node_id);
#else
		union macaddr router_mac = NODE_MAC;

		__do_l3(skb, nh_off, NULL, (__u8 *) &router_mac.addr);

		/* Pass down to stack */
		return TC_ACT_OK;
#endif
	} else {
		return do_l3(skb, nh_off, &dst);
	}
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

__section("from-container")
int handle_ingress(struct __sk_buff *skb)
{
	int ret = LXC_REDIRECT, nh_off = ETH_HLEN;
	__u8 nexthdr;

	if (likely(skb->protocol == __constant_htons(ETH_P_IPV6))) {
		nexthdr = load_byte(skb, nh_off + offsetof(struct ipv6hdr, nexthdr));
		if (unlikely(nexthdr == IPPROTO_ICMPV6))
			ret = handle_icmp6(skb, nh_off);

		if (likely(ret == LXC_REDIRECT))
			return do_l3_from_lxc(skb, nh_off);
		else
			return ret;
	}

	return TC_ACT_UNSPEC;
}

BPF_LICENSE("GPL");
