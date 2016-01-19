#include <iproute2/bpf_api.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <stdint.h>
#include "common.h"
#include "lib/ipv6.h"

#define ETH_HLEN 14

__BPF_MAP(cilium_lxc, BPF_MAP_TYPE_HASH, 0, sizeof(__u16), sizeof(struct lxc_info), PIN_GLOBAL_NS, 1024);

static inline void set_dst_mac(struct __sk_buff *skb, char *mac)
{
        skb_store_bytes(skb, 0, mac, 6, 1);
}

static inline int do_redirect6(struct __sk_buff *skb, int nh_off)
{
	struct lxc_info *dst_lxc;
	__u16 lxc_id;
	union v6addr dst;
        int *ifindex;
        char fmt[] = "skb %p len %d\n";
        char fmt2[] = "%x %x\n";

	/* FIXME: Validate source MAC and source IP */

	/* FIXME: Validate destination node ID and perform encap */

	load_ipv6_daddr(skb, nh_off, &dst);

	trace_printk(fmt, sizeof(fmt), skb, skb->len);
	trace_printk(fmt2, sizeof(fmt2), dst.p3, dst.p4);

	if (decrement_ipv6_hoplimit(skb, nh_off)) {
		/* FIXME: Handle hoplimit == 0 */
	}

	lxc_id = dst.p4 & 0xFFFF;

	dst_lxc = map_lookup_elem(&cilium_lxc, &lxc_id);
	if (dst_lxc) {
		__u64 tmp_mac = dst_lxc->mac;
		set_dst_mac(skb, (char *) &tmp_mac);

		char fmt[] = "Found destination container locally\n";
		trace_printk(fmt, sizeof(fmt));

		redirect(dst_lxc->ifindex, 0);
	}

	return -1;
}

__section("from-container")
int handle_ingress(struct __sk_buff *skb)
{
	int ret = 0, nh_off = ETH_HLEN;

	if (likely(skb->protocol == __constant_htons(ETH_P_IPV6)))
		ret = do_redirect6(skb, nh_off);

	return ret;
}
BPF_LICENSE("GPL");
