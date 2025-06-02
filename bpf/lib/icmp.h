/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#if !defined(__LIB_ICMP__) && defined(ENABLE_IPV4)
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
	__u8 tos;
	__u8 icmp_type;
	__wsum csum;
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
	tos = ip4->tos;

	/* Load ICMP header and check bounds */
	icmphdr = (struct icmphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	if ((void *)(icmphdr + 1) > data_end)
		return DROP_INVALID;

	/* Only respond to ICMP echo requests */
	icmp_type = icmphdr->type;
	if (icmp_type != ICMP_ECHO)
		return DROP_INVALID;

	/* Rewrite ethernet header */
	ethhdr = (struct ethhdr *)data;
	if ((void *)(ethhdr + 1) > data_end)
		return DROP_INVALID;

	/* Swap src/dst MAC addresses */
	memcpy(ethhdr->h_dest, smac.addr, ETH_ALEN);
	memcpy(ethhdr->h_source, dmac.addr, ETH_ALEN);

	/* Rewrite IP header */
	ip4->saddr = daddr; /* Swap src/dst IP */
	ip4->daddr = saddr;
	ip4->tos = tos;
	ip4->ttl = IPDEFTTL;

	/* Update IP checksum */
	ret = l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
			      0, 0, 0);
	if (ret < 0)
		return ret;

	/* Revalidate data pointers after packet modifications */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* Recompute ICMP header pointer after packet modifications */
	icmphdr = (struct icmphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	if ((void *)(icmphdr + 1) > data_end)
		return DROP_INVALID;

	/* Convert ICMP echo request to echo reply */
	icmphdr->type = ICMP_ECHOREPLY;
	icmphdr->code = 0;

	/* Update ICMP checksum */
	csum = csum_diff(&icmphdr->type, 2, &((__u8[]){ICMP_ECHO, 0}), 2, 0);
	ret = l4_csum_replace(ctx, ETH_HLEN + sizeof(struct iphdr) +
			      offsetof(struct icmphdr, checksum),
			      0, csum, 0);
	if (ret < 0)
		return ret;

	return 0;
}

#endif /* __LIB_ICMP__ */