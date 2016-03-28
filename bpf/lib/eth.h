#ifndef __LIB_ETH__
#define __LIB_ETH__

#include <linux/if_ether.h>

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

union macaddr {
	struct {
		__u32 p1;
		__u16 p2;
	};
	__u8 addr[6];
};

static inline int compare_eth_addr(const union macaddr *a,
				   const union macaddr *b)
{
	int tmp;

	tmp = a->p1 - b->p1;
	if (!tmp)
		tmp = a->p2 - b->p2;

	return tmp;
}

static inline int is_eth_bcast(const union macaddr *a)
{
	union macaddr bcast;

	bcast.p1 = 0xffffffff;
	bcast.p2 = 0xffff;

	if (!compare_eth_addr(a, &bcast))
		return 1;
	else
		return 0;
}

static inline int load_eth_saddr(struct __sk_buff *skb, __u8 *mac, int off)
{
	return skb_load_bytes(skb, off + ETH_ALEN, mac, ETH_ALEN);
}

static inline int store_eth_saddr(struct __sk_buff *skb, __u8 *mac, int off)
{
	return skb_store_bytes(skb, off + ETH_ALEN, mac, ETH_ALEN, 1);
}

static inline int load_eth_daddr(struct __sk_buff *skb, __u8 *mac, int off)
{
	return skb_load_bytes(skb, off, mac, ETH_ALEN);
}

static inline int store_eth_daddr(struct __sk_buff *skb, __u8 *mac, int off)
{
	return skb_store_bytes(skb, off, mac, ETH_ALEN, 1);
}

#endif /* __LIB_ETH__ */
