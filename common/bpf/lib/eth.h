#include <linux/if_ether.h>

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

union macaddr {
	struct {
		__u32 p1;
		__u16 p2;
	};
	__u8 addr[6];
};

static inline int compare_eth_addr(union macaddr *a, union macaddr *b)
{
	int tmp;

	tmp = a->p1 - b->p1;
	if (!tmp)
		tmp = a->p2 - b->p2;

	return tmp;
}

static inline void load_eth_saddr(struct __sk_buff *skb, union macaddr *dst, int off)
{
	/* FIXME: use skb_load_bytes() instead */
	dst->p1 = ntohl(load_word(skb, off + 6));
	dst->p2 = ntohs(load_half(skb, off + 6 + sizeof(dst->p1)));
}

static inline void store_eth_saddr(struct __sk_buff *skb, char *mac, int off)
{
        skb_store_bytes(skb, off + 6, mac, 6, 1);
}

static inline void load_eth_daddr(struct __sk_buff *skb, union macaddr *dst, int off)
{
	/* FIXME: use skb_load_bytes() instead */
	dst->p1 = ntohl(load_word(skb, off));
	dst->p2 = ntohs(load_half(skb, off + sizeof(dst->p1)));
}

static inline void store_eth_daddr(struct __sk_buff *skb, char *mac, int off)
{
        skb_store_bytes(skb, off, mac, 6, 1);
}
