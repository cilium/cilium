/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

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
static __always_inline int arp_check(struct ethhdr *eth,
				     const struct arphdr *arp,
				     union macaddr *mac)
{
	union macaddr *dmac = (union macaddr *) &eth->h_dest;

	return arp->ar_op  == bpf_htons(ARPOP_REQUEST) &&
	       arp->ar_hrd == bpf_htons(ARPHRD_ETHER) &&
	       (eth_is_bcast(dmac) || !eth_addrcmp(dmac, mac));
}

static __always_inline int
arp_prepare_response(struct __ctx_buff *ctx, struct ethhdr *eth,
		     const struct arp_eth *arp_eth, __be32 ip,
		     union macaddr *mac)
{
	union macaddr smac = *(union macaddr *) &eth->h_source;
	__be32 sip = arp_eth->ar_sip;
	__be16 arpop = bpf_htons(ARPOP_REPLY);

	if (eth_store_saddr(ctx, mac->addr, 0) < 0 ||
	    eth_store_daddr(ctx, smac.addr, 0) < 0 ||
	    ctx_store_bytes(ctx, 20, &arpop, sizeof(arpop), 0) < 0 ||
	    ctx_store_bytes(ctx, 22, mac, 6, 0) < 0 ||
	    ctx_store_bytes(ctx, 28, &ip, 4, 0) < 0 ||
	    ctx_store_bytes(ctx, 32, &smac, sizeof(smac), 0) < 0 ||
	    ctx_store_bytes(ctx, 38, &sip, sizeof(sip), 0) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

static __always_inline int arp_respond(struct __ctx_buff *ctx, union macaddr *mac,
				       int direction)
{
	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void *) (long) ctx->data;
	struct arphdr *arp = data + ETH_HLEN;
	struct ethhdr *eth = data;
	struct arp_eth *arp_eth;
	int ret;

	if (data + ETH_HLEN + sizeof(*arp) + sizeof(*arp_eth) > data_end)
		return CTX_ACT_OK;

	arp_eth = data + ETH_HLEN + sizeof(*arp);
	if (arp_check(eth, arp, mac)) {
		__be32 target_ip = arp_eth->ar_tip;
		ret = arp_prepare_response(ctx, eth, arp_eth, target_ip, mac);
		if (unlikely(ret != 0))
			goto error;

		cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY,
				   ctx_get_ifindex(ctx));
		return ctx_redirect(ctx, ctx_get_ifindex(ctx), direction);
	}

	/* Pass any unknown ARP requests to the Linux stack */
	return CTX_ACT_OK;
error:
	return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
}

#endif /* __LIB_ARP__ */
