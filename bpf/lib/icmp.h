/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "bpf/compiler.h"
#include "icmp_wsum.h"
#include "csum.h"
#include "dbg.h"
#include "eth.h"
#include "overloadable.h"
#ifdef ENABLE_IPV4

#define ICMP_PACKET_MAX_SAMPLE_SIZE 8

static __always_inline
int generate_icmp4_reply(struct __ctx_buff *ctx, __u8 icmp_type, __u8 icmp_code,
			 __u32 icmp_data)
{
	__u64 full_len = ctx_full_len(ctx);
	__u64 new_len, sample_len;
	void *data, *data_end;
	struct ethhdr *ethhdr;
	struct iphdr *ip4;
	struct icmphdr *icmphdr;
	union macaddr smac = {};
	union macaddr dmac = {};
	__be32	saddr;
	__be32	daddr;
	__u8	tos;
	__wsum csum;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* copy the incoming src and dest IPs and mac addresses to the stack.
	 * the pointers will not be valid after adding headroom.
	 */

	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		return DROP_INVALID;

	if (eth_load_daddr(ctx, dmac.addr, 0) < 0)
		return DROP_INVALID;

	saddr = ip4->saddr;
	daddr = ip4->daddr;
	tos = ip4->tos;

	/* Trim down to sample size (IPv4 header + 8 bytes datagram) */
	if (full_len < sizeof(struct ethhdr))
		return DROP_INVALID;

	sample_len = ipv4_hdrlen(ip4) + ICMP_PACKET_MAX_SAMPLE_SIZE;
	new_len = sizeof(struct ethhdr) + sample_len;
	if (new_len > full_len) {
		new_len = full_len;
		sample_len = full_len - sizeof(struct ethhdr);
	}

	ctx_adjust_troom(ctx, (__s32)(new_len - full_len));

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	/* Calculate the checksum of the ICMP sample */
	csum = icmp_wsum_accumulate(data + sizeof(struct ethhdr), data_end, (int)sample_len);

	/* We need to insert a IPv4 and ICMP header before the original packet.
	 * Make that room.
	 */

	ret = ctx_adjust_hroom(ctx, sizeof(*ip4) + sizeof(*icmphdr),
			       BPF_ADJ_ROOM_MAC, ctx_adjust_hroom_flags());
	if (ret < 0)
		return DROP_INVALID;

	/* changing size invalidates pointers, so we need to re-fetch them. */
	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	/* Bound check all 3 headers at once. */
	ethhdr = data;
	ip4 = (void *)ethhdr + sizeof(*ethhdr);
	icmphdr = (void *)ip4 + sizeof(*ip4);
	if ((void *)icmphdr + sizeof(*icmphdr) > data_end)
		return DROP_INVALID;

	/* Write reversed eth header, ready for egress */
	memcpy(ethhdr->h_dest, smac.addr, sizeof(smac.addr));
	memcpy(ethhdr->h_source, dmac.addr, sizeof(dmac.addr));
	ethhdr->h_proto = bpf_htons(ETH_P_IP);

	/* Write reversed ip header, ready for egress */
	ip4->version = 4;
	ip4->ihl = sizeof(struct iphdr) >> 2;
	ip4->tos = tos;
	ip4->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct icmphdr) +
		       (__u16)sample_len);
	ip4->id = 0;
	ip4->frag_off = 0;
	ip4->ttl = IPDEFTTL;
	ip4->protocol = IPPROTO_ICMP;
	ip4->check = 0;
	ip4->daddr = saddr;
	ip4->saddr = daddr;
	ip4->check = csum_fold(csum_diff(ip4, 0, ip4, sizeof(struct iphdr), 0));

	/* Write reversed icmp header */
	icmphdr->type = icmp_type;
	icmphdr->code = icmp_code;
	icmphdr->checksum = 0;
	icmphdr->un.gateway = 0;

	if (icmp_type == ICMP_DEST_UNREACH && icmp_code == ICMP_FRAG_NEEDED)
		icmphdr->un.frag.mtu = (__be16)icmp_data;

	/* Add ICMP header checksum to sum of its body */
	csum += csum_diff(icmphdr, 0, icmphdr, sizeof(struct icmphdr), 0);
	icmphdr->checksum = csum_fold(csum);

	return 0;
}
#endif /* ENABLE_IPV4 */
