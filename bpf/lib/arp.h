#ifndef __LIB_ARP__
#define __LIB_ARP__

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include "eth.h"
#include "dbg.h"

#define ENABLE_ARP_RESPONDER
#define CILIUM_MAP_PROTO_ARP 0

/*
 * check if an arp request is for ar_tip
 */
static inline int arp_check(struct __sk_buff *skb, __be32 ar_tip, union macaddr *responder_mac)
{
	union macaddr dmac = {};
	__be32 tip = 0;
	__be16 arpop = 0;

	if (likely(skb->protocol != __constant_htons(ETH_P_ARP)))
		return 0;

	load_eth_daddr(skb, dmac.addr, 0);
	/* Get ARP op code */
	if (skb_load_bytes(skb, 20, &arpop, sizeof(arpop)) < 0)
		return -1;
	/* Get ARP Target IP */
	if (skb_load_bytes(skb, 38, &tip, sizeof(tip)) < 0)
		return -1;

	if ((arpop != __constant_htons(ARPOP_REQUEST)) || (tip != ar_tip) ||
	    (!is_eth_bcast(&dmac) && compare_eth_addr(&dmac, responder_mac))) {
		printk("arp target mismatch for %x, (target %x op %d)\n",
			ar_tip, tip, ntohs(arpop));
		return 0;
	}

	printk("arp target match for %x ifindex %d\n", tip, skb->ifindex);
	return 1;
}

#endif /* __LIB_ARP__ */
