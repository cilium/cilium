#ifndef __LIB_LXC_H_
#define __LIB_LXC_H_

#include "common.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "dbg.h"

#ifndef DISABLE_SMAC_VERIFICATION
static inline int valid_src_mac(struct ethhdr *eth)
{
	union macaddr valid = LXC_MAC;

	return !eth_addrcmp(&valid, (union macaddr *) &eth->h_source);
}
#else
static inline int valid_src_mac(struct ethhdr *eth)
{
	return 1;
}
#endif

#ifndef DISABLE_SIP_VERIFICATION
static inline int valid_src_ip(struct ipv6hdr *ip6)
{
	union v6addr valid = LXC_IP;

	return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
}

static inline int valid_src_ipv4(struct iphdr *ip4)
{
#ifdef LXC_IPV4
	return ip4->saddr != LXC_IPV4;
#else
	/* Can't send IPv4 if no IPv4 address is configured */
	return 0;
#endif
}
#else
static inline int valid_src_ip(struct ipv6hdr *ip6)
{
	return 1;
}

static inline int valid_src_ipv4(struct iphdr *ip4)
{
	return 1;
}
#endif

#ifndef DISABLE_DMAC_VERIFICATION
static inline int valid_dst_mac(struct ethhdr *eth)
{
	union macaddr valid = NODE_MAC;

	return !eth_addrcmp(&valid, (union macaddr *) &eth->h_dest);
}
#else
static inline int valid_dst_mac(struct ethhdr *eth)
{
	return 1;
}
#endif

#endif
