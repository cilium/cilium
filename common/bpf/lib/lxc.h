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
	load_eth_saddr(skb, src.addr, 0);
	return compare_eth_addr(&src, &valid);
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
	load_ipv6_saddr(skb, off, &src);
	return compare_ipv6_addr(&src, &valid);
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
		printk("skb %p: invalid dst MAC\n", skb);

	return ret;
}

#endif
