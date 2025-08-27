/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "bpf/compiler.h"
#include "common.h"
#include "csum.h"
#include "dbg.h"
#include "drop.h"
#include "eth.h"
#include "ipv6.h"
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

#ifdef ENABLE_IPV6

#define ICMPV6_PACKET_MAX_SAMPLE_SIZE 1280

/* The IPv6 pseudo-header */
struct ipv6_pseudo_header_t {
	union {
		struct header {
			struct in6_addr src_ip;
			struct in6_addr dst_ip;
			__be32 top_level_length;
			__u8 zero[3];
			__u8 next_header;
		} __packed fields;
		__u16 words[20];
	};
};

static __always_inline
int generate_icmp6_reply(struct __ctx_buff *ctx, __u8 icmp_type, __u8 icmp_code)
{
	void *data, *data_end;
	struct ethhdr *ethhdr;
	struct ipv6hdr *ip6;
	struct icmp6hdr *icmphdr;
	struct ipv6_pseudo_header_t pseudo_header;
	union macaddr smac = {};
	union macaddr dmac = {};
	struct in6_addr saddr;
	struct in6_addr daddr;
	__wsum csum;
	__u64 sample_len;
	int i;
	int ret;
	const int inner_offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
		sizeof(struct icmp6hdr);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* copy the incoming src and dest IPs and mac addresses to the stack.
	 * the pointers will not be valid after adding headroom.
	 */

	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		return DROP_INVALID;

	if (eth_load_daddr(ctx, dmac.addr, 0) < 0)
		return DROP_INVALID;

	memcpy(&saddr, &ip6->saddr, sizeof(struct in6_addr));
	memcpy(&daddr, &ip6->daddr, sizeof(struct in6_addr));

	/* Resize to min MTU - IPv6 hdr + ICMPv6 hdr */
	sample_len = ctx_full_len(ctx);
	if (sample_len > (__u64)ICMPV6_PACKET_MAX_SAMPLE_SIZE)
		sample_len = ICMPV6_PACKET_MAX_SAMPLE_SIZE;
	ctx_adjust_troom(ctx, (__s32)(sample_len + sizeof(struct ethhdr) - ctx_full_len(ctx)));

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	/* Calculate the unfolded checksum of the ICMPv6 sample */
	csum = icmp_wsum_accumulate(data + sizeof(struct ethhdr), data_end, (int)sample_len);

	/* We need to insert a IPv6 and ICMPv6 header before the original packet.
	 * Make that room.
	 */

#if __ctx_is == __ctx_xdp
	ret = xdp_adjust_head(ctx, 0 - (int)(sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr)));
#else
	ret = skb_adjust_room(ctx, sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr),
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
	ethhdr->h_proto = bpf_htons(ETH_P_IPV6);

	/* Write reversed ip header, ready for egress */
	ip6 = data + sizeof(struct ethhdr);
	ip6->version = 6;
	ip6->priority = 0;
	ip6->flow_lbl[0] = 0;
	ip6->flow_lbl[1] = 0;
	ip6->flow_lbl[2] = 0;
	ip6->payload_len = bpf_htons(sizeof(struct icmp6hdr) + (__u16)sample_len);
	ip6->nexthdr = IPPROTO_ICMPV6;
	ip6->hop_limit = IPDEFTTL;
	memcpy(&ip6->daddr, &saddr, sizeof(struct in6_addr));
	memcpy(&ip6->saddr, &daddr, sizeof(struct in6_addr));

	/* Write reversed icmp header */
	icmphdr = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
	icmphdr->icmp6_type = icmp_type;
	icmphdr->icmp6_code = icmp_code;
	icmphdr->icmp6_cksum = 0;
	icmphdr->icmp6_dataun.un_data32[0] = 0;

	/* Add the ICMP header to the checksum (only type and code are non-zero) */
	csum += ((__u16)icmphdr->icmp6_code) << 8 | (__u16)icmphdr->icmp6_type;

	/* Fill pseudo header */
	memcpy(&pseudo_header.fields.src_ip, &ip6->saddr, sizeof(struct in6_addr));
	memcpy(&pseudo_header.fields.dst_ip, &ip6->daddr, sizeof(struct in6_addr));
	pseudo_header.fields.top_level_length = bpf_htonl(sizeof(struct icmp6hdr) +
					(__u32)sample_len);
	__bpf_memzero(pseudo_header.fields.zero, sizeof(pseudo_header.fields.zero));
	pseudo_header.fields.next_header = IPPROTO_ICMPV6;

	#pragma unroll
	for (i = 0; i < (int)(sizeof(pseudo_header.words) / sizeof(__u16)); i++)
		csum += pseudo_header.words[i];

	icmphdr->icmp6_cksum = csum_fold(csum);

	return 0;
}
#endif /* ENABLE_IPV6 */
