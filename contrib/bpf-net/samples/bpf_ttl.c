#include "bpf_api.h"

#include <asm/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#if 0
# tc filter add dev wlp2s0b1 parent 8001: bpf da obj examples/bpf/list/bpf_ttl.o
# tc filter show dev wlp2s0b1 parent 8001:
filter protocol all pref 49152 bpf 
filter protocol all pref 49152 bpf handle 0x1 bpf_ttl.o:[classifier] direct-action 
#endif

static inline void ttl_handle_ipv4(struct __sk_buff *skb, int nh_off)
{
	__u8 ttl_old, ttl_new = 46;

	ttl_old = load_byte(skb, nh_off + offsetof(struct iphdr, ttl));
	if (ttl_old == 64) {
		l3_csum_replace(skb, nh_off + offsetof(struct iphdr, check),
				ttl_old, ttl_new, sizeof(__u16));
		skb_store_bytes(skb, nh_off + offsetof(struct iphdr, ttl),
				&ttl_new, sizeof(ttl_new), 0);
	}
}

static inline void ttl_handle_ipv6(struct __sk_buff *skb, int nh_off)
{
	__u8 hl_old, hl_new = 46;

	hl_old = load_byte(skb, nh_off + offsetof(struct ipv6hdr, hop_limit));
	if (hl_old == 64) {
		skb_store_bytes(skb, nh_off + offsetof(struct ipv6hdr, hop_limit),
				&hl_new, sizeof(hl_new), 0);
	}
}

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	int nh_off = ETH_HLEN;

	/* Handle vlan in nh_off. */
	if (likely(skb->protocol == htons(ETH_P_IP)))
		ttl_handle_ipv4(skb, nh_off);
	else if (skb->protocol == htons(ETH_P_IPV6))
		ttl_handle_ipv6(skb, nh_off);

	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
