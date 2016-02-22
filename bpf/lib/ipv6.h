#ifndef __LIB_IPV6__
#define __LIB_IPV6__

#include <linux/ipv6.h>

#include "dbg.h"

static inline int compare_ipv6_addr(const union v6addr *a,
				    const union v6addr *b)
{
	int tmp;

	tmp = a->p1 - b->p1;
	if (!tmp) {
		tmp = a->p2 - b->p2;
		if (!tmp) {
			tmp = a->p3 - b->p3;
			if (!tmp)
				tmp = a->p4 - b->p4;
		}
	}

	return tmp;
}

static inline int decrement_ipv6_hoplimit(struct __sk_buff *skb, int off)
{
	__u8 hoplimit, new_hl;

	hoplimit = load_byte(skb, off + offsetof(struct ipv6hdr, hop_limit));
	if (hoplimit <= 1) {
		printk("Hoplimit reached 0\n");
		return 1;
	}

	new_hl = hoplimit - 1;
	skb_store_bytes(skb, off + offsetof(struct ipv6hdr, hop_limit),
			&new_hl, sizeof(new_hl), 0);

	printk("Decremented hoplimit\n");
	return 0;
}

static inline int load_ipv6_saddr(struct __sk_buff *skb, int off, union v6addr *dst)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, saddr), dst->addr,
			      sizeof(((struct ipv6hdr *)NULL)->saddr));
}

static inline int store_ipv6_saddr(struct __sk_buff *skb, __u8 *addr, int off)
{
	return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, saddr), addr, 16, 0);
}

static inline int load_ipv6_daddr(struct __sk_buff *skb, int off, union v6addr *dst)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, daddr), dst->addr,
			      sizeof(((struct ipv6hdr *)NULL)->daddr));
}

static inline int store_ipv6_daddr(struct __sk_buff *skb, __u8 *addr, int off)
{
	return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, daddr), addr, 16, 0);
}

static inline int ipv6_load_nexthdr(struct __sk_buff *skb, int off, __u8 *nexthdr)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, nexthdr), nexthdr,
			      sizeof(__u8));
}

static inline int load_ipv6_paylen(struct __sk_buff *skb, int off, __be16 *len)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, payload_len),
			      len, sizeof(*len));
}

static inline int store_ipv6_paylen(struct __sk_buff *skb, int off, __be16 *len)
{
	return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, payload_len),
			       len, sizeof(*len), 0);
}

static inline __u16 derive_lxc_id(const union v6addr *addr)
{
	return ntohl(addr->p4) & 0xFFFF;
}

static inline __u32 derive_node_id(const union v6addr *addr)
{
	return (ntohl(addr->p3) & 0xFFFF) << 16 | (ntohl(addr->p4) >> 16);
}

static inline __be32 ipv6_pseudohdr_checksum(struct ipv6hdr *hdr,
					     __u16 payload_len, __be32 sum)
{
	__u32 len = htonl((__u32)payload_len);
	__u32 nexthdr = htonl((__u32)hdr->nexthdr);
	sum = csum_diff(NULL, 0, &hdr->saddr, sizeof(struct in6_addr), sum);
	sum = csum_diff(NULL, 0, &hdr->daddr, sizeof(struct in6_addr), sum);
	sum = csum_diff(NULL, 0, &len, sizeof(len), sum);
	sum = csum_diff(NULL, 0, &nexthdr, sizeof(nexthdr), sum);

	return sum;
}
#endif /* __LIB_IPV6__ */
