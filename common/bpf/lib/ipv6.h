#include <linux/ipv6.h>

static inline int decrement_ipv6_hoplimit(struct __sk_buff *skb, int off)
{
	__u8 hoplimit, new_hl;

	hoplimit = load_byte(skb, off + offsetof(struct ipv6hdr, hop_limit));
	if (hoplimit <= 1) {
#ifdef DEBUG
		char fmt[] = "Hoplimit reached 0\n";
		trace_printk(fmt, sizeof(fmt));
#endif
		return 1;
	}

	new_hl = hoplimit - 1;
	skb_store_bytes(skb, off + offsetof(struct ipv6hdr, hop_limit),
			&new_hl, sizeof(new_hl), 0);
#ifdef DEBUG
	char fmt[] = "Decremented hoplimit\n";
	trace_printk(fmt, sizeof(fmt));
#endif

	return 0;
}
