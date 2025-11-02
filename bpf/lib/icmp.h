/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "bpf/compiler.h"
#include "common.h"
#include "csum.h"
#include "dbg.h"
#include "eth.h"
#include "overloadable.h"

static __always_inline
__wsum icmp_wsum_accumulate(void *data_start, void *data_end, int sample_len)
{
	/* Unrolled loop to calculate the checksum of the ICMP sample
	 * Done manually because the compiler refuses with #pragma unroll
	 */
	__wsum wsum = 0;

	#define body(i) if ((i) > sample_len) \
		return wsum; \
	if (data_start + (i) + sizeof(__u16) > data_end) { \
		if (data_start + (i) + sizeof(__u8) <= data_end)\
			wsum += *(__u8 *)(data_start + (i)); \
		return wsum; \
	} \
	wsum += *(__u16 *)(data_start + (i));

	#define body4(i) body(i)\
		body(i + 2) \
		body(i + 4) \
		body(i + 6)

	#define body16(i) body4(i)\
		body4(i + 8) \
		body4(i + 16) \
		body4(i + 24)

	#define body128(i) body16(i)\
		body16(i + 32) \
		body16(i + 64) \
		body16(i + 96)

	body128(0)
	body128(256)
	body128(512)
	body128(768)
	body128(1024)

	return wsum;
}

#ifdef ENABLE_IPV4

#define ICMP_PACKET_MAX_SAMPLE_SIZE 64

static __always_inline
int generate_icmp4_reply(struct __ctx_buff *ctx, __u8 icmp_type, __u8 icmp_code)
{
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
	int sample_len;
	int ret;
	const int inner_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) +
		sizeof(struct icmphdr);

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

	/* Resize to ethernet header + 64 bytes or less */
	sample_len = (int)ctx_full_len(ctx);
	if (sample_len > ICMP_PACKET_MAX_SAMPLE_SIZE)
		sample_len = ICMP_PACKET_MAX_SAMPLE_SIZE;
	ctx_adjust_troom(ctx, (__s32)(sample_len + sizeof(struct ethhdr) - ctx_full_len(ctx)));

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	/* Calculate the checksum of the ICMP sample */
	csum = icmp_wsum_accumulate(data + sizeof(struct ethhdr), data_end, sample_len);

	/* We need to insert a IPv4 and ICMP header before the original packet.
	 * Make that room.
	 */

#if __ctx_is == __ctx_xdp
	ret = xdp_adjust_head(ctx, 0 - (int)(sizeof(struct iphdr) + sizeof(struct icmphdr)));
#else
	ret = skb_adjust_room(ctx, sizeof(struct iphdr) + sizeof(struct icmphdr),
			      BPF_ADJ_ROOM_MAC, 0);
#endif

	if (ret < 0)
		return DROP_INVALID;

	/* changing size invalidates pointers, so we need to re-fetch them. */
	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	/* Bound check all 3 headers at once. */
	if (data + inner_offset > data_end)
		return DROP_INVALID;

	/* Write reversed eth header, ready for egress */
	ethhdr = data;
	memcpy(ethhdr->h_dest, smac.addr, sizeof(smac.addr));
	memcpy(ethhdr->h_source, dmac.addr, sizeof(dmac.addr));
	ethhdr->h_proto = bpf_htons(ETH_P_IP);

	/* Write reversed ip header, ready for egress */
	ip4 = data + sizeof(struct ethhdr);
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
	icmphdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	icmphdr->type = icmp_type;
	icmphdr->code = icmp_code;
	icmphdr->checksum = 0;
	icmphdr->un.gateway = 0;

	/* Add ICMP header checksum to sum of its body */
	csum += csum_diff(icmphdr, 0, icmphdr, sizeof(struct icmphdr), 0);
	icmphdr->checksum = csum_fold(csum);

	return 0;
}
#endif /* ENABLE_IPV4 */
