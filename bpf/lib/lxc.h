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

	eth_load_saddr(skb, src.addr, 0);
	ret = eth_addrcmp(&src, &valid);
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
static inline int verify_src_ip(struct ipv6_ct_tuple *tuple)
{
	union v6addr valid = LXC_IP;
	int ret;

	ret = ipv6_addrcmp(&tuple->src, &valid);
	if (unlikely(ret))
		printk("Invalid source IP address, dropping...\n");

	return ret;
}
#else
static inline int verify_src_ip(struct ipv6_ct_tuple *tuple)
{
	return 0;
}
#endif

static inline int verify_dst_mac(struct __sk_buff *skb)
{
	union macaddr dst = {}, valid = NODE_MAC;
	int ret;

	eth_load_daddr(skb, dst.addr, 0);
	ret = eth_addrcmp(&dst, &valid);
	if (unlikely(ret))
		printk("Invalid destination MAC address, dropping...\n");

	return ret;
}

#endif
