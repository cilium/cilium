#ifndef __LIB_IPV6__
#define __LIB_IPV6__

#include <linux/ipv6.h>

#include "dbg.h"
#define IPV6_FLOWINFO_MASK              htonl(0x0FFFFFFF)
#define IPV6_FLOWLABEL_MASK             htonl(0x000FFFFF)
#define IPV6_FLOWLABEL_STATELESS_FLAG   htonl(0x00080000)

#define IPV6_TCLASS_MASK (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK)
#define IPV6_TCLASS_SHIFT       20

static inline void ipv6_addr_copy(union v6addr *dst, union v6addr *src)
{
	dst->p1 = src->p1;
	dst->p2 = src->p2;
	dst->p3 = src->p3;
	dst->p4 = src->p4;
}

static inline int ipv6_addrcmp(union v6addr *a, union v6addr *b)
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

static inline int ipv6_match_subnet_96(union v6addr *addr, union v6addr *prefix)
{
	int tmp;

	tmp = addr->p1 - prefix->p1;
	if (!tmp) {
		tmp = addr->p2 - prefix->p2;
		if (!tmp) {
			__u32 a = ntohl(addr->p3);
			__u32 b = ntohl(prefix->p3);
			tmp = (a & 0xFFFF0000) - (b & 0xFFFF0000);
		}
	}

	return !tmp;
}

static inline int ipv6_dec_hoplimit(struct __sk_buff *skb, int off)
{
	__u8 hoplimit, new_hl;

	hoplimit = load_byte(skb, off + offsetof(struct ipv6hdr, hop_limit));
	if (hoplimit <= 1) {
		return 1;
	}

	new_hl = hoplimit - 1;
	if (skb_store_bytes(skb, off + offsetof(struct ipv6hdr, hop_limit),
			    &new_hl, sizeof(new_hl), BPF_F_RECOMPUTE_CSUM) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

static inline int ipv6_load_saddr(struct __sk_buff *skb, int off, union v6addr *dst)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, saddr), dst->addr,
			      sizeof(((struct ipv6hdr *)NULL)->saddr));
}

/* Assumes that caller fixes checksum csum_diff() and l4_csum_replace() */
static inline int ipv6_store_saddr(struct __sk_buff *skb, __u8 *addr, int off)
{
	return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, saddr), addr, 16, 0);
}

static inline int ipv6_load_daddr(struct __sk_buff *skb, int off, union v6addr *dst)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, daddr), dst->addr,
			      sizeof(((struct ipv6hdr *)NULL)->daddr));
}

/* Assumes that caller fixes checksum csum_diff() and l4_csum_replace() */
static inline int ipv6_store_daddr(struct __sk_buff *skb, __u8 *addr, int off)
{
	return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, daddr), addr, 16, 0);
}

static inline int ipv6_load_nexthdr(struct __sk_buff *skb, int off, __u8 *nexthdr)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, nexthdr), nexthdr,
			      sizeof(__u8));
}

/* Assumes that caller fixes checksum csum_diff() and l4_csum_replace() */
static inline int ipv6_store_nexthdr(struct __sk_buff *skb, __u8 *nexthdr, int off)
{
	return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, nexthdr), nexthdr,
			      sizeof(__u8), 0);
}

static inline int ipv6_load_paylen(struct __sk_buff *skb, int off, __be16 *len)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, payload_len),
			      len, sizeof(*len));
}

/* Assumes that caller fixes checksum csum_diff() and l4_csum_replace() */
static inline int ipv6_store_paylen(struct __sk_buff *skb, int off, __be16 *len)
{
	return skb_store_bytes(skb, off + offsetof(struct ipv6hdr, payload_len),
			       len, sizeof(*len), 0);
}

static inline int ipv6_store_flowlabel(struct __sk_buff *skb, int off, __be32 label)
{
	__u32 old;

	/* use traffic class from packet */
	if (skb_load_bytes(skb, off, &old, 4) < 0)
		return DROP_INVALID;

	old &= IPV6_TCLASS_MASK;
	old = htonl(0x60000000) | label | old;

	if (skb_store_bytes(skb, off, &old, 4, BPF_F_RECOMPUTE_CSUM) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

static inline __u16 derive_lxc_id(union v6addr *addr)
{
	return ntohl(addr->p4) & 0xFFFF;
}

static inline __u32 ipv6_derive_node_id(union v6addr *addr)
{
	return (ntohl(addr->p3) & 0xFFFF) << 16 | (ntohl(addr->p4) >> 16);
}

static inline __be32 ipv6_pseudohdr_checksum(struct ipv6hdr *hdr,
                                             __u8 next_hdr,
					     __u16 payload_len, __be32 sum)
{
	__u32 len = htonl((__u32)payload_len);
	__u32 nexthdr = htonl((__u32)next_hdr);
	sum = csum_diff(NULL, 0, &hdr->saddr, sizeof(struct in6_addr), sum);
	sum = csum_diff(NULL, 0, &hdr->daddr, sizeof(struct in6_addr), sum);
	sum = csum_diff(NULL, 0, &len, sizeof(len), sum);
	sum = csum_diff(NULL, 0, &nexthdr, sizeof(nexthdr), sum);

	return sum;
}
#endif /* __LIB_IPV6__ */
