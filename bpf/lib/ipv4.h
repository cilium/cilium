#ifndef __LIB_IPV4__
#define __LIB_IPV4__

#include <linux/ip.h>

#include "dbg.h"

static inline int ipv4_load_daddr(struct __sk_buff *skb, int off, __u32 *dst)
{
	return skb_load_bytes(skb, off + offsetof(struct iphdr, daddr), dst, 4);
}

#define TTL_OFF(off) (off + offsetof(struct iphdr, ttl))

static inline int ipv4_dec_ttl(struct __sk_buff *skb, int off, struct iphdr *ip4)
{
	__u8 new_ttl, ttl = ip4->ttl;

	if (ttl <= 1)
		return 1;

	new_ttl = ttl - 1;
	l3_csum_replace(skb, TTL_OFF(off), ttl, new_ttl, 1);
	skb_store_bytes(skb, off + offsetof(struct iphdr, ttl), &ttl, sizeof(ttl), 0);

	return 0;
}

static inline int ipv4_hdrlen(struct iphdr *ip4)
{
	return ip4->ihl * 4;
}

#endif /* __LIB_IPV4__ */
