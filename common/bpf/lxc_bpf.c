#include <iproute2/bpf_api.h>

#include <linux/icmpv6.h>
#include <sys/socket.h>

#include <stdint.h>
#include <string.h>

#include "common.h"

#include "lib/ipv6.h"
#include "lib/eth.h"
#include "lib/dbg.h"

#include <lxc_config.h>

__BPF_MAP(cilium_lxc, BPF_MAP_TYPE_HASH, 0, sizeof(__u16), sizeof(struct lxc_info), PIN_GLOBAL_NS, 1024);

#ifndef DISABLE_SMAC_VERIFICATION
static inline int verify_src_mac(struct __sk_buff *skb)
{
	union macaddr src = {}, valid = LXC_MAC;
	load_eth_saddr(skb, src.addr, 0);
	return compare_eth_addr(&src, &valid);
}
#else
static inline int verify_src_mac(struct __sk_buff *skb)
{
	return 0;
}
#endif

#ifndef DISABLE_SIP_VERIFICATION
static inline int verify_src_ip(struct __sk_buff *skb, int off)
{
	union v6addr src = {}, valid = LXC_IP;
	load_ipv6_saddr(skb, off, &src);
	return compare_ipv6_addr(&src, &valid);
}
#else
static inline int verify_src_ip(struct __sk_buff *skb, int off)
{
	return 0;
}
#endif

static inline int verify_dst_mac(struct __sk_buff *skb)
{
	union macaddr dst = {}, valid = ROUTER_MAC;
	int ret;

	load_eth_daddr(skb, dst.addr, 0);
	ret = compare_eth_addr(&dst, &valid);

	if (unlikely(ret))
		printk("skb %p: invalid dst MAC\n", skb);

	return ret;
}

static inline void debug_trace_packet(struct __sk_buff *skb)
{
	printk("skb %p len %d\n", skb, skb->len);
}

static inline int do_redirect6(struct __sk_buff *skb, int nh_off)
{
	__u16 lxc_id;
	union v6addr dst = {};
	int node_id, *ifindex;

	debug_trace_packet(skb);

	if (verify_src_mac(skb) || verify_src_ip(skb, nh_off) ||
	    verify_dst_mac(skb))
		return -1;

	load_ipv6_daddr(skb, nh_off, &dst);
	lxc_id = derive_lxc_id(&dst);
	node_id = derive_node_id(&dst);

	printk("lxc-id: %x node-id: %x\n", lxc_id, node_id);

	if (node_id != NODE_ID) {
		/* FIXME: Handle encapsulation case */
	} else {
		struct lxc_info *dst_lxc;

		dst_lxc = map_lookup_elem(&cilium_lxc, &lxc_id);
		if (dst_lxc) {
			__u64 tmp_mac = dst_lxc->mac;
			store_eth_daddr(skb, (__u8 *) &tmp_mac, 0);

			if (decrement_ipv6_hoplimit(skb, nh_off)) {
				/* FIXME: Handle hoplimit == 0 */
			}

			printk("Found destination container locally\n");

			return redirect(dst_lxc->ifindex, 0);
		}
	}

	return -1;
}

static inline int handle_icmp6(struct __sk_buff *skb, int nh_off)
{
	__u8 type;
	struct icmp6hdr icmp6hdr;
	union macaddr smac = {};
	union macaddr router_mac = ROUTER_MAC;
	__u8 opts[2] = { 2, 1 };

	type = load_byte(skb, ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_type));

	printk("ICMPv6 packet skb %p len %d type %d\n", skb, skb->len, type);

	if (type == 135) {
		union v6addr sip = {};
		__u8 router_ip[] = ROUTER_IP;

		/* skb->daddr = skb->saddr */
		load_ipv6_saddr(skb, nh_off, &sip);
		store_ipv6_daddr(skb, sip.addr, ETH_HLEN);
		/* skb->saddr = router address, verifier rejects when initialized statically */
		store_ipv6_saddr(skb, router_ip, ETH_HLEN);

		/* fill icmp6hdr */
		icmp6hdr.icmp6_type = 136;
		icmp6hdr.icmp6_code = 0;
		icmp6hdr.icmp6_dataun.un_data32[0] = 0;
		icmp6hdr.icmp6_router = 1;
		icmp6hdr.icmp6_solicited = 1;
		icmp6hdr.icmp6_override = 0;
		/* FIXME compute icmp6 checksum */
		icmp6hdr.icmp6_cksum = 0;
		skb_store_bytes(skb, ETH_HLEN + sizeof(struct ipv6hdr), &icmp6hdr, sizeof(icmp6hdr), 0);
		// ND_OPT_TARGET_LL_ADDR
		skb_store_bytes(skb, ETH_HLEN + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) + sizeof(struct in6_addr), opts, sizeof(opts), 0);
		skb_store_bytes(skb, ETH_HLEN + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) + sizeof(struct in6_addr) + 2, &router_mac, 6, 0);

		/* dmac = smac, smac = router mac */
		load_eth_saddr(skb, smac.addr, 0);
		store_eth_daddr(skb, smac.addr, 0);
		store_eth_saddr(skb, router_mac.addr, 0);

		printk("Redirect skb to Ifindex %d\n", skb->ifindex);

		return redirect(skb->ifindex, 0);

	}

	return -1;
}
__section("from-container")
int handle_ingress(struct __sk_buff *skb)
{
	int ret = 0, nh_off = ETH_HLEN;
	__u8 nexthdr;

	if (likely(skb->protocol == __constant_htons(ETH_P_IPV6))) {
		nexthdr = load_byte(skb, nh_off + offsetof(struct ipv6hdr, nexthdr));
		if (nexthdr == IPPROTO_ICMPV6)
			ret = handle_icmp6(skb, nh_off);
		else
			ret = do_redirect6(skb, nh_off);
	}
	return ret;
}
BPF_LICENSE("GPL");
