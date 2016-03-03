#ifndef __LIB_NAT46__
#define __LIB_NAT46__

#include <linux/ip.h>
#include <linux/icmp.h>
#include "common.h"
#include "ipv6.h"
#include "eth.h"
#include "dbg.h"

#define IPV6_SRC_PREFIX 0xbeef0000
#define IPV6_DST_PREFIX 0xdead0000

static inline int get_csum_offset(__u8 protocol)
{
	int csum_off;

	switch (protocol) {
	case IPPROTO_TCP:
		csum_off = TCP_CSUM_OFF;
		break;
	case IPPROTO_UDP:
		csum_off = UDP_CSUM_OFF;
		break;
	case IPPROTO_ICMP:
		csum_off = (offsetof(struct icmphdr, checksum));
		break;
	case IPPROTO_ICMPV6:
		csum_off = (offsetof(struct icmp6hdr, icmp6_cksum));
		break;
	default:
		return -1;
	}

	return csum_off;
}

static inline int ipv4_to_ipv6(struct __sk_buff *skb, int nh_off)
{
	struct ipv6hdr v6 = {};
	struct iphdr v4 = {};
	int csum_off;
	int pushoff;
	__be32 csum = 0;
	__be16 v4hdr_len;
	__be16 protocol = htons(ETH_P_IPV6);
	__u64 csum_flags = BPF_F_PSEUDO_HDR;
	
	if (skb_load_bytes(skb, nh_off, &v4, sizeof(v4)) < 0)
		return -1;

	/* build v6 header */
	v6.version = 0x6;
	v6.saddr.in6_u.u6_addr32[0] = IPV6_SRC_PREFIX;
	v6.daddr.in6_u.u6_addr32[0] = IPV6_DST_PREFIX;
	v6.saddr.in6_u.u6_addr32[3] = v4.saddr;
	v6.daddr.in6_u.u6_addr32[3] = v4.daddr;
	v6.nexthdr = v4.protocol;
	v6.hop_limit = v4.ttl;
	v4hdr_len = (v4.ihl << 2);
	v6.payload_len = htons(ntohs(v4.tot_len) - v4hdr_len);

	pushoff = sizeof(struct ipv6hdr) - v4hdr_len;

	if (pushoff != 0 && skb_modify(skb, nh_off, pushoff, htons(ETH_P_IPV6),
				       BPF_F_HDR_OUTER_NET) < 0) {
		printk("v46 NAT: skb_modify failed\n");
		return -1;
	}

	skb_store_bytes(skb, nh_off, &v6, sizeof(v6), 0);
	skb_store_bytes(skb, nh_off - 2, &protocol, 2, 0);

	/* 
	 * get checksum from inner header tcp / udp / icmp
	 * undo ipv4 pseudohdr checksum and
	 * add  ipv6 pseudohdr checksum
	 */
	csum_off = get_csum_offset(v4.protocol);
	if (csum_off < 0)
		return -1;
	else
		csum_off += sizeof(struct ipv6hdr);

	csum = csum_diff(&v4.saddr, 4, NULL, 0, csum);
	csum = csum_diff(&v4.daddr, 4, NULL, 0, csum);
	csum = csum_diff(NULL, 0, &v6.saddr, 16, csum);
	csum = csum_diff(NULL, 0, &v6.daddr, 16, csum);
	if (v4.protocol == IPPROTO_UDP)
		csum_flags |= BPF_F_MARK_MANGLED_0;
	l4_csum_replace(skb, nh_off + csum_off, 0, csum, csum_flags);

	printk("v46 NAT: nh_off %d, pushoff %d, csum_off %d\n",
	       nh_off, pushoff, csum_off);

	return 0;
}

static inline int ipv6_to_ipv4(struct __sk_buff *skb, int nh_off)
{
	struct ipv6hdr v6 = {};
	struct iphdr v4 = {};
	int pushoff = -20;
	int csum_off;
	__u8 mac[14] = {};
	__be32 csum = 0;
	__be16 protocol = htons(ETH_P_IP);
	__u64 csum_flags = BPF_F_PSEUDO_HDR;

	if (skb_load_bytes(skb, 0, mac, sizeof(mac)) < 0)
		return -1;
	if (skb_load_bytes(skb, nh_off, &v6, sizeof(v6)) < 0)
		return -1;

	/* build v4 header */
	v4.ihl = 0x5;
	v4.version = 0x4;
	v4.saddr = v6.saddr.in6_u.u6_addr32[3];
	v4.daddr = v6.daddr.in6_u.u6_addr32[3];
	v4.protocol = v6.nexthdr;
	v4.ttl = v6.hop_limit;
	v4.tot_len = htons(ntohs(v6.payload_len) + sizeof(v4));
	csum_off = offsetof(struct iphdr, check);
	csum = csum_diff(NULL, 0, &v4, sizeof(v4), csum);

	if (skb_modify(skb, nh_off, pushoff, htons(ETH_P_IP),
		       BPF_F_HDR_OUTER_NET) < 0) {
		printk("v46 NAT: skb_modify failed\n");
		return -1;
	}

	skb_store_bytes(skb, nh_off, &v4, sizeof(v4), 0);
	skb_store_bytes(skb, nh_off - 2, &protocol, 2, 0);
	l4_csum_replace(skb, nh_off + csum_off, 0, csum, 0);

	/* 
	 * get checksum from inner header tcp / udp / icmp
	 * undo ipv6 pseudohdr checksum and
	 * add  ipv4 pseudohdr checksum
	 */
	csum_off = get_csum_offset(v4.protocol);
	if (csum_off < 0)
		return -1;
	else
		csum_off += sizeof(struct iphdr);

	csum = 0;
	csum = csum_diff(&v6.saddr, 16, NULL, 0, csum);
	csum = csum_diff(&v6.daddr, 16, NULL, 0, csum);
	csum = csum_diff(NULL, 0, &v4.saddr, 4, csum);
	csum = csum_diff(NULL, 0, &v4.daddr, 4, csum);
	if (v4.protocol == IPPROTO_UDP)
		csum_flags |= BPF_F_MARK_MANGLED_0;
	l4_csum_replace(skb, nh_off + csum_off, 0, csum, csum_flags);

	printk("v64 NAT: nh_off %d, pushoff %d, csum_off %d\n",
	       nh_off, pushoff, csum_off);

	return 0;
}

static inline int ip_nat_wrapper(struct __sk_buff *skb, int nh_off)
{
	__u64 proto = load_half(skb, 12);
	int ret = -1;

	if (proto == ETH_P_IP) {
		ret = ipv4_to_ipv6(skb, nh_off);
	}

	if (proto == ETH_P_IPV6) {
		ret = ipv6_to_ipv4(skb, nh_off);
	}

	return ret;
}
#endif /* __LIB_NAT46__ */
