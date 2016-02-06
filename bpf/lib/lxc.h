#ifndef __LIB_LXC_H_
#define __LIB_LXC_H_

#include "common.h"
#include "ipv6.h"
#include "eth.h"
#include "dbg.h"

#ifndef DISABLE_SMAC_VERIFICATION
static inline int verify_src_mac(struct __sk_buff *skb)
{
	union macaddr src = {}, valid = LXC_MAC;
	int ret;

	load_eth_saddr(skb, src.addr, 0);
	ret = compare_eth_addr(&src, &valid);
	if (unlikely(ret))
		printk("Invalid source MAC address, dropping...\n");

	return ret;
}
#else
static inline int verify_src_mac(struct __sk_buff *skb)
{
	return 0;
}
#endif

#ifndef DISABLE_SIP_VERIFICATION
static inline int verify_src_ip(struct __sk_buff *skb, int off)
{
	union v6addr src = {}, valid = LXC_IP;
	int ret;

	load_ipv6_saddr(skb, off, &src);
	ret = compare_ipv6_addr(&src, &valid);
	if (unlikely(ret))
		printk("Invalid source IP address, dropping...\n");

	return ret;
}
#else
static inline int verify_src_ip(struct __sk_buff *skb, int off)
{
	return 0;
}
#endif

static inline int verify_dst_mac(struct __sk_buff *skb)
{
	union macaddr dst = {}, valid = NODE_MAC;
	int ret;

	load_eth_daddr(skb, dst.addr, 0);
	ret = compare_eth_addr(&dst, &valid);
	if (unlikely(ret))
		printk("Invalid destination MAC address, dropping...\n");

	return ret;
}

#endif
