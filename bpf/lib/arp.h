#ifndef __LIB_ARP__
#define __LIB_ARP__

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include "eth.h"
#include "dbg.h"

struct arp_eth {
	unsigned char		ar_sha[ETH_ALEN];
	unsigned char		ar_sip[4];
	unsigned char		ar_tha[ETH_ALEN];
	unsigned char		ar_tip[4];
};

/*
 * check if an arp request is for ar_tip
 */
static inline int arp_check(struct ethhdr *eth, struct arphdr *arp, void *data,
			    void *data_end, __be32 ar_tip, union macaddr *responder_mac)
{
	union macaddr *dmac = (union macaddr *) &eth->h_dest;
	struct arp_eth *arp_eth = data + sizeof(*eth) + sizeof(*arp);

	if (arp->ar_op != __constant_htons(ARPOP_REQUEST) ||
	    arp->ar_hrd != __constant_htons(ARPHRD_ETHER) ||
	    (!eth_is_bcast(dmac) && eth_addrcmp(dmac, responder_mac)))
		return 0;

	/* Check if packet contains ethernet specific arp header */
	if (data + sizeof(*arp) + ETH_HLEN + 20 > data_end)
		return 0;

	if (*(__be32 *) &arp_eth->ar_tip != ar_tip)
		return 0;

	return 1;
}

static inline int arp_prepare_response(struct __sk_buff *skb, __be32 ip, union macaddr *mac)
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
