#ifndef __LIB_LXC_H_
#define __LIB_LXC_H_

#include "common.h"
#include "ipv6.h"
#include "eth.h"
#include "dbg.h"

#ifndef DISABLE_SMAC_VERIFICATION
static inline int invalid_src_mac(struct __sk_buff *skb)
{
	union macaddr src, valid = LXC_MAC;
	int ret;

	ret = eth_load_saddr(skb, src.addr, 0);
	if (likely(ret == 0))
		return eth_addrcmp(&src, &valid);
	else
		return ret;
}
#else
static inline int invalid_src_mac(struct __sk_buff *skb)
{
	return 0;
}
#endif

#ifndef DISABLE_SIP_VERIFICATION
static inline int invalid_src_ip(struct __sk_buff *skb, int off)
{
	union v6addr src, valid = LXC_IP;
	int ret;

	ret = ipv6_load_saddr(skb, off, &src);
	if (likely(ret == 0))
		return ipv6_addrcmp(&src, &valid);
	else
		return ret;
}
#else
static inline int invalid_src_ip(struct __sk_buff *skb, int off)
{
	return 0;
}
#endif

#ifndef DISABLE_DMAC_VERIFICATION
static inline int invalid_dst_mac(struct __sk_buff *skb)
{
	union macaddr dst, valid = NODE_MAC;
	int ret;

	ret = eth_load_daddr(skb, dst.addr, 0);
	if (likely(ret == 0))
		return eth_addrcmp(&dst, &valid);
	else
		return ret;
}
#else
static inline int invalid_dst_mac(struct __sk_buff *skb)
{
	return 0;
}
#endif

#endif
