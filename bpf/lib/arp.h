/*
 *  Copyright (C) 2016-2019 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __LIB_ARP__
#define __LIB_ARP__

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include "eth.h"
#include "dbg.h"
#include "drop.h"

struct arp_eth {
	unsigned char		ar_sha[ETH_ALEN];
	__be32                  ar_sip;
	unsigned char		ar_tha[ETH_ALEN];
	__be32                  ar_tip;
} __attribute__((packed));

/* Check if packet is ARP request for IP */
static inline int arp_check(struct ethhdr *eth, struct arphdr *arp,
			    struct arp_eth *arp_eth, union macaddr *mac)
{
	union macaddr *dmac = (union macaddr *) &eth->h_dest;

	return arp->ar_op  == bpf_htons(ARPOP_REQUEST) &&
	       arp->ar_hrd == bpf_htons(ARPHRD_ETHER) &&
	       (eth_is_bcast(dmac) || !eth_addrcmp(dmac, mac));
}

static inline int arp_prepare_response(struct __sk_buff *skb, struct ethhdr *eth,
				       struct arp_eth *arp_eth, __be32 ip,
				       union macaddr *mac)
{
	union macaddr smac = *(union macaddr *) &eth->h_source;
	__be32 sip = arp_eth->ar_sip;
	__be16 arpop = bpf_htons(ARPOP_REPLY);

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

static inline int arp_respond(struct __sk_buff *skb, union macaddr *mac, int direction)
{
	void *data_end = (void *) (long) skb->data_end;
	void *data = (void *) (long) skb->data;
	struct arphdr *arp = data + ETH_HLEN;
	struct ethhdr *eth = data;
	struct arp_eth *arp_eth;
	int ret;

	if (data + ETH_HLEN + sizeof(*arp) + sizeof(*arp_eth) > data_end)
		return TC_ACT_OK;

	arp_eth = data + ETH_HLEN + sizeof(*arp);

	if (arp_check(eth, arp, arp_eth, mac)) {
		__be32 target_ip = arp_eth->ar_tip;
		ret = arp_prepare_response(skb, eth, arp_eth, target_ip, mac);
		if (unlikely(ret != 0))
			goto error;

		cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, skb->ifindex);
		return redirect(skb->ifindex, direction);
	}

	/* Pass any unknown ARP requests to the Linux stack */
	return TC_ACT_OK;

error:
	return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, METRIC_EGRESS);
}

#endif /* __LIB_ARP__ */
