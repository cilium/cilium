#include <iproute2/bpf_api.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include "common.h"
#include "lib/ipv6.h"
#include "lib/eth.h"
#include <lxc_config.h>

__BPF_MAP(cilium_lxc, BPF_MAP_TYPE_HASH, 0, sizeof(__u16), sizeof(struct lxc_info), PIN_GLOBAL_NS, 1024);

#ifndef DISABLE_SMAC_VERIFICATION
static inline int verify_src_mac(struct __sk_buff *skb)
{
	union macaddr src, valid = LXC_MAC;
	load_eth_saddr(skb, &src, 0);
	return compare_eth_addr(&src, &valid);
}
#else
static inline int verify_src_mac(struct __sk_buff *skb)
{
	return 0;
}
#endif

static inline int do_redirect6(struct __sk_buff *skb, int nh_off)
{
	struct lxc_info *dst_lxc;
	__u16 lxc_id;
	union v6addr dst;
        int *ifindex;
        char fmt[] = "skb %p len %d\n";
        char fmt2[] = "%x %x\n";

	if (verify_src_mac(skb))
		return -1;

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
		store_eth_daddr(skb, (char *) &tmp_mac, 0);

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
