#include "bpf_api.h"

#include <asm/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#if 0
# tc filter add dev wlp2s0b1 parent 8001: bpf da obj examples/bpf/list/bpf_l3.o
# tc filter show dev wlp2s0b1 parent 8001:
filter protocol all pref 49152 bpf 
filter protocol all pref 49152 bpf handle 0x1 bpf_l3.o:[classifier] direct-action 
#endif

static inline void addr_handle_ipv4(struct __sk_buff *skb, int nh_off)
{
	__u32 src_old, src_new = htonl(0xabcdabef);

	src_old = htonl(load_word(skb, nh_off + offsetof(struct iphdr, saddr)));
	l3_csum_replace(skb, nh_off + offsetof(struct iphdr, check), src_old,
			src_new, sizeof(__u32));
	skb_store_bytes(skb, nh_off + offsetof(struct iphdr, saddr), &src_new,
			sizeof(src_new), 0);
}

/* use skb_load_bytes() instead */
union v6addr {
	struct {
		__u32 p1;
		__u32 p2;
		__u32 p3;
		__u32 p4;
	};
	__u8 addr[16];
};

static inline void addr_handle_ipv6(struct __sk_buff *skb, int nh_off)
{
	/* such initializer doesn't work (verifier rejected). */
//	union v6addr src_old, src_new = { .p1 = htonl(0xab), .p2 = htonl(0xcd), .p3 = htonl(0xab), .p4 = htonl(0xef) };
	union v6addr src_old, src_new;
//	char fmt[] = "%x:%x:%x\n";

	src_old.p1 = ntohl(load_word(skb, nh_off + offsetof(struct ipv6hdr, saddr) + sizeof(__u32) * 0));
	src_old.p2 = ntohl(load_word(skb, nh_off + offsetof(struct ipv6hdr, saddr) + sizeof(__u32) * 1));
	src_old.p3 = ntohl(load_word(skb, nh_off + offsetof(struct ipv6hdr, saddr) + sizeof(__u32) * 2));
	src_old.p4 = ntohl(load_word(skb, nh_off + offsetof(struct ipv6hdr, saddr) + sizeof(__u32) * 3));

//	trace_printk(fmt, sizeof(fmt), src_old.addr[13], src_old.addr[14], src_old.addr[15]);

	src_new.p1 = htonl(0xab);
	src_new.p2 = htonl(0xcd);
	src_new.p3 = htonl(0xab);
	src_new.p4 = htonl(0xef);

	skb_store_bytes(skb, nh_off + offsetof(struct ipv6hdr, saddr), &src_new, 16, 0);
}

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	int nh_off = ETH_HLEN;

	/* Handle vlan in nh_off. */
	if (likely(skb->protocol == htons(ETH_P_IP)))
		addr_handle_ipv4(skb, nh_off);
	else if (skb->protocol == htons(ETH_P_IPV6))
		addr_handle_ipv6(skb, nh_off);

	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
