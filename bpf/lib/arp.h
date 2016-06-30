#ifndef __LIB_ARP__
#define __LIB_ARP__

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include "eth.h"
#include "dbg.h"

/*
 * check if an arp request is for ar_tip
 */
static inline int arp_check(struct __sk_buff *skb, __be32 ar_tip, union macaddr *responder_mac)
{
	union macaddr dmac;
	__be32 tip;
	__be16 arpop;

	eth_load_daddr(skb, dmac.addr, 0);
	/* Get ARP op code */
	if (skb_load_bytes(skb, 20, &arpop, sizeof(arpop)) < 0)
		return 0;
	/* Get ARP Target IP */
	if (skb_load_bytes(skb, 38, &tip, sizeof(tip)) < 0)
		return 0;

	if ((arpop != __constant_htons(ARPOP_REQUEST)) || (tip != ar_tip) ||
	    (!eth_is_bcast(&dmac) && eth_addrcmp(&dmac, responder_mac))) {
#ifdef DEBUG_ARP
		printk("arp target mismatch for %x, (target %x op %d)\n",
			ar_tip, tip, ntohs(arpop));
#endif
		return 0;
	}

#ifdef DEBUG_ARP
	printk("arp target match for %x ifindex %d\n", tip, skb->ifindex);
#endif
	return 1;
}

static inline int arp_prepare_response(struct __sk_buff *skb, __be32 ip,
				       union macaddr *mac)
{
	__be16 arpop = __constant_htons(ARPOP_REPLY);
	union macaddr smac = {};
	__be32 sip;

	if (eth_load_saddr(skb, smac.addr, 0) < 0 ||
	    skb_load_bytes(skb, 28, &sip, sizeof(sip)) < 0)
		return DROP_INVALID;

	if (eth_store_saddr(skb, mac->addr, 0) < 0 ||
	    eth_store_daddr(skb, smac.addr, 0) < 0 ||
	    skb_store_bytes(skb, 20, &arpop, sizeof(arpop), 0) < 0 ||
	    skb_store_bytes(skb, 22, mac, 6, 0) < 0 ||
	    skb_store_bytes(skb, 28, &ip, 4, 0) < 0 ||
	    skb_store_bytes(skb, 32, &smac, sizeof(smac), 0) < 0 ||
	    skb_store_bytes(skb, 38, &sip, sizeof(sip), 0) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

#endif /* __LIB_ARP__ */
