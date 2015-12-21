#include "bpf_api.h"

#include <asm/types.h>
#include <linux/if_ether.h>

#if 0
# tc filter add dev wlp2s0b1 parent 8001: bpf da obj examples/bpf/list/bpf_l2.o
# tc filter show dev wlp2s0b1 parent 8001:
filter protocol all pref 49152 bpf 
filter protocol all pref 49152 bpf handle 0x1 bpf_l2.o:[classifier] direct-action 
#endif

/* use skb_load_bytes() instead */
union maddr {
	struct {
		__u32 p1;
		__u16 p2;
	};
	__u8 addr[6];
} __attribute__ ((packed));

static inline void load_mac(struct __sk_buff *skb, union maddr *dst, int off)
{
	dst->p1 = ntohl(load_word(skb, off));
	dst->p2 = ntohs(load_half(skb, off + sizeof(dst->p1)));
	/* todo: skb_load_bytes() */
}

static inline void store_mac(struct __sk_buff *skb, union maddr *dst, int off)
{
	/* Note: sizeof(*dst) won't work as compiler still aligns it to 8bytes. */
	skb_store_bytes(skb, off, dst, ETH_ALEN, 0);
}

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	union maddr src, dst;
//	char fmt[] = "%x:%x:%x\n";

	load_mac(skb, &dst, 0);
	load_mac(skb, &src, ETH_ALEN);

//	trace_printk(fmt, sizeof(fmt), src.addr[3], src.addr[4], src.addr[5]);

	store_mac(skb, &src, 0);
	store_mac(skb, &dst, ETH_ALEN);

	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
