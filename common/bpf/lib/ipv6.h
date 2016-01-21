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

static inline int load_ipv6_daddr(struct __sk_buff *skb, int off, union v6addr *dst)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, saddr), dst->addr,
			      sizeof(((struct ipv6hdr *)NULL)->saddr));
}

static inline __u16 derive_lxc_id(const union v6addr *addr)
{
	return addr->p4 & 0xFFFF;
}

static inline int derive_node_id(const union v6addr *addr)
{
	return (addr->p3 & 0xFFFF) << 16 | (addr->p4 >> 16);
}

#endif /* __LIB_IPV6__ */
