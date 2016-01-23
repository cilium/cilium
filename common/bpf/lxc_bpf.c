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

#ifndef BPF_F_PSEUDO_HDR
# define BPF_F_PSEUDO_HDR                (1ULL << 4)
#endif

#define LXC_REDIRECT -2

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
		printk("Destination on remote node\n");
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

static inline int handle_icmp6_solicitation(struct __sk_buff *skb, int nh_off)
{
	struct icmp6hdr icmp6hdr = {}, icmp6hdr_old = {};
	union macaddr smac = {};
	union macaddr router_mac = ROUTER_MAC;
	__u8 opts[8] = { 2, 1, 0, 0, 0, 0, 0, 0 };
	__u8 opts_old[8] = {};
	const int csum_off = nh_off + sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_cksum);
	union v6addr sip = {}, dip = {};
	__u8 router_ip[] = ROUTER_IP;
	__be32 sum = 0;

	/* skb->daddr = skb->saddr */
	load_ipv6_saddr(skb, nh_off, &sip);
	load_ipv6_daddr(skb, nh_off, &dip);

	store_ipv6_saddr(skb, router_ip, nh_off);
	store_ipv6_daddr(skb, sip.addr, nh_off);

	/* fixup checksums */
	sum = csum_diff(sip.addr, 16, router_ip, 16, 0);
	l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR);
	sum = csum_diff(dip.addr, 16, sip.addr, 16, 0);
	l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR);

	if (skb_load_bytes(skb, nh_off + sizeof(struct ipv6hdr), &icmp6hdr_old, sizeof(icmp6hdr_old)) < 0)
	return -1;

	/* fill icmp6hdr */
	icmp6hdr.icmp6_type = 136;
	icmp6hdr.icmp6_code = 0;
	icmp6hdr.icmp6_dataun.un_data32[0] = 0;
	icmp6hdr.icmp6_router = 1;
	icmp6hdr.icmp6_solicited = 1;
	icmp6hdr.icmp6_override = 0;
	icmp6hdr.icmp6_cksum = icmp6hdr_old.icmp6_cksum;
	skb_store_bytes(skb, nh_off + sizeof(struct ipv6hdr), &icmp6hdr, sizeof(icmp6hdr), 0);

	/* fixup checksums */
	sum = csum_diff(&icmp6hdr_old, sizeof(icmp6hdr_old),
		&icmp6hdr, sizeof(icmp6hdr), 0);
	l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR);

	if (skb_load_bytes(skb, nh_off + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) + sizeof(struct in6_addr), opts_old, sizeof(opts_old)) < 0)
	return -1;

	opts[2] = router_mac.addr[0];
	opts[3] = router_mac.addr[1];
	opts[4] = router_mac.addr[2];
	opts[5] = router_mac.addr[3];
	opts[6] = router_mac.addr[4];
	opts[7] = router_mac.addr[5];

	// ND_OPT_TARGET_LL_ADDR
	skb_store_bytes(skb, nh_off + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) + sizeof(struct in6_addr), opts, sizeof(opts), 0);

	/* fixup checksum */
	sum = csum_diff(opts_old, sizeof(opts_old), opts, sizeof(opts),
			0);
	l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR);

	/* dmac = smac, smac = router mac */
	load_eth_saddr(skb, smac.addr, 0);
	store_eth_daddr(skb, smac.addr, 0);
	store_eth_saddr(skb, router_mac.addr, 0);

	printk("Redirect skb to Ifindex %d\n", skb->ifindex);

	return redirect(skb->ifindex, 0);
}

static inline int handle_icmp6(struct __sk_buff *skb, int nh_off)
{
	int ret = -1;
	__u8 type = load_byte(skb, nh_off + sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_type));

	printk("ICMPv6 packet skb %p len %d type %d\n", skb, skb->len, type);

	switch(type) {
	case 135:
		ret = handle_icmp6_solicitation(skb, nh_off);
		break;
	case 128:
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
		if (nexthdr == IPPROTO_ICMPV6)
			ret = handle_icmp6(skb, nh_off);
		if (ret == LXC_REDIRECT)
			ret = do_redirect6(skb, nh_off);
	}
	return ret;
}
BPF_LICENSE("GPL");
