/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * ICMP Echo Reply Support for Virtual IPs
 *
 * This module provides functionality to respond to ICMP echo requests (ping)
 * sent to virtual service IPs (ClusterIP and LoadBalancer IPs) with ICMP echo
 * replies, making services appear "pingable" even when they don't have actual
 * ICMP services running.
 *
 * This feature is controlled by the ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY flag
 * and the bpf-lb-reply-icmp-echo-virtual-ips configuration option.
 */

#if !defined(__LIB_ICMP__) && defined(ENABLE_IPV4) && defined(ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY)
#define __LIB_ICMP__

#include <linux/icmp.h>
#include "common.h"
#include "eth.h"
#include "drop.h"

/**
 * icmp_send_echo_reply - Send ICMP echo reply
 * @ctx:	Packet context
 *
 * Converts an ICMP echo request packet to an echo reply by:
 * - Swapping source and destination MAC addresses
 * - Swapping source and destination IP addresses
 * - Converting ICMP type from ECHO to ECHOREPLY
 * - Updating checksums
 *
 * Returns:
 *   - 0 on success
 *   - Negative error code on failure
 */
static __always_inline
int icmp_send_echo_reply(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *ethhdr;
	struct iphdr *ip4;
	struct icmphdr *icmphdr;
	union macaddr smac = {};
	union macaddr dmac = {};
	__be32 saddr;
	__be32 daddr;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* Copy the incoming src and dest IPs and mac addresses to the stack.
	 * The pointers will not be valid after modifying the packet.
	 */
	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		return DROP_INVALID;

	if (eth_load_daddr(ctx, dmac.addr, 0) < 0)
		return DROP_INVALID;

	saddr = ip4->saddr;
	daddr = ip4->daddr;

	/* Load ICMP header and check bounds */
	icmphdr = (struct icmphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	if ((void *)(icmphdr + 1) > data_end)
		return DROP_INVALID;

	/* Only respond to ICMP echo requests */
	if (icmphdr->type != ICMP_ECHO)
		return DROP_INVALID;

	/* Rewrite ethernet header */
	ethhdr = (struct ethhdr *)data;
	if ((void *)(ethhdr + 1) > data_end)
		return DROP_INVALID;

	/* Swap src/dst MAC addresses */
	memcpy(ethhdr->h_dest, smac.addr, ETH_ALEN);
	memcpy(ethhdr->h_source, dmac.addr, ETH_ALEN);

	/* Calculate IP checksum delta for TTL change only (save old value first) */
	__be32 third_word_old = (__be32)(ip4->ttl << 24 | ip4->protocol << 16);  /* TTL|Protocol */
	
	/* Rewrite IP header - swap addresses and update TTL */
	ip4->saddr = daddr; /* Swap src/dst IP */
	ip4->daddr = saddr;
	ip4->ttl = IPDEFTTL;
	
	/* Calculate diff for TTL|Protocol word (only TTL actually changes) */
	__be32 third_word_new = (__be32)(ip4->ttl << 24 | ip4->protocol << 16);
	__wsum diff = csum_diff(&third_word_old, sizeof(third_word_old), &third_word_new, sizeof(third_word_new), 0);
	
	/* Apply the TTL diff to IP checksum */
	ret = l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
			      0, diff, 0);
	if (ret < 0)
		return ret;

	/* Revalidate data pointers after packet modifications */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* Recompute ICMP header pointer after packet modifications */
	icmphdr = (struct icmphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	if ((void *)(icmphdr + 1) > data_end)
		return DROP_INVALID;

	/* Calculate ICMP checksum delta for type change */
	__be32 icmp_old = (__be32)(icmphdr->type << 24 | icmphdr->code << 16);
	
	/* Convert ICMP echo request to echo reply */
	icmphdr->type = ICMP_ECHOREPLY;
	icmphdr->code = 0;
	
	__be32 icmp_new = (__be32)(icmphdr->type << 24 | icmphdr->code << 16);
	
	__wsum icmp_diff = csum_diff(&icmp_old, sizeof(icmp_old), &icmp_new, sizeof(icmp_new), 0);
	
	ret = l4_csum_replace(ctx, ETH_HLEN + sizeof(struct iphdr) +
			      offsetof(struct icmphdr, checksum),
			      0, icmp_diff, 0);
	if (ret < 0)
		return ret;

	return 0;
}

#endif /* __LIB_ICMP__ */
