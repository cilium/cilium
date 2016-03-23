#ifndef __LIB_IPV4__
#define __LIB_IPV4__

#include <linux/ip.h>

#include "dbg.h"

static inline int ipv4_load_daddr(struct __sk_buff *skb, int off, __u32 *dst)
{
	return skb_load_bytes(skb, off + offsetof(struct iphdr, daddr), dst, 4);
}

#endif /* __LIB_IPV4__ */
