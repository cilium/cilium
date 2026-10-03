/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "common.h"
#include "csum.h"
#include "jhash.h"
#include "tunnel.h"

#define BPF_GENEVE_VERSION		0
#define BPF_GENEVE_DEFAULT_PORT		6081
#define BPF_GENEVE_OPT_MAX_LEN		252
#define BPF_GENEVE_OPT_MAX_COUNT	63

#define GENEVE_INNER_PROTO_ETH		1
#define GENEVE_INNER_PROTO_IP		2

#ifndef GENEVE_INNER_PROTOCOL
# define GENEVE_INNER_PROTOCOL		GENEVE_INNER_PROTO_ETH
#endif

#ifdef BPF_TEST
DECLARE_CONFIG(__u8, geneve_inner_protocol, "Geneve inner protocol (1=eth, 2=ip)")
#endif

static __always_inline __u8
bpf_geneve_inner_proto_mode(void)
{
#ifdef BPF_TEST
	__u8 mode = CONFIG(geneve_inner_protocol);

	if (mode == GENEVE_INNER_PROTO_ETH || mode == GENEVE_INNER_PROTO_IP)
		return mode;
#endif
	return GENEVE_INNER_PROTOCOL;
}

static __always_inline __u16
bpf_geneve_dport(void)
{
	__u16 dport = CONFIG(tunnel_port);

#ifdef TUNNEL_PORT
	if (!dport)
		dport = TUNNEL_PORT;
#endif
#if __ctx_is == __ctx_skb || defined(ENABLE_BPF_GENEVE)
	if (!dport)
		dport = BPF_GENEVE_DEFAULT_PORT;
#endif
	return dport;
}

/* Outer Geneve encapsulation headers for IPv4 underlay */
struct geneve_encaphdr4 {
	struct iphdr ip;
	struct udphdr udp;
	struct genevehdr geneve;
} __packed;

/* Outer Geneve encapsulation headers for IPv6 underlay */
struct geneve_encaphdr6 {
	struct ipv6hdr ip6;
	struct udphdr udp;
	struct genevehdr geneve;
} __packed;

static __always_inline __u16
bpf_geneve_encaphdr4_len(__u8 opt_len_words)
{
	return (__u16)(sizeof(struct geneve_encaphdr4) + ((__u16)opt_len_words << 2));
}

static __always_inline __u16
bpf_geneve_encaphdr6_len(__u8 opt_len_words)
{
	return (__u16)(sizeof(struct geneve_encaphdr6) + ((__u16)opt_len_words << 2));
}

static __always_inline void
bpf_geneve_hdr_init(struct genevehdr *geneve, __be16 proto,
		    __u32 vni, __u8 opt_len_words)
{
	__u32 *w = (__u32 *)geneve;
	WRITE_ONCE(w[0], 0);
	WRITE_ONCE(w[1], 0);
	geneve->ver = BPF_GENEVE_VERSION;
	geneve->opt_len = opt_len_words;
	WRITE_ONCE(geneve->protocol_type, proto);
	WRITE_ONCE(geneve->vni[0], (__u8)((vni >> 16) & 0xFF));
	WRITE_ONCE(geneve->vni[1], (__u8)((vni >> 8) & 0xFF));
	WRITE_ONCE(geneve->vni[2], (__u8)(vni & 0xFF));
}

static __always_inline __u32
bpf_geneve_hdr_vni(const struct genevehdr *geneve)
{
	return ((__u32)geneve->vni[0] << 16) |
	       ((__u32)geneve->vni[1] << 8) |
	       ((__u32)geneve->vni[2]);
}

static __always_inline __u32
bpf_geneve_hash_inner_v6(const struct __ctx_buff *ctx, const struct ipv6hdr *inner_ip6)
{
	__u32 hash = 0;

	if (inner_ip6 && ctx) {
		const void *data_end = ctx_data_end(ctx);
		__u32 flow = ((__u32)(inner_ip6->flow_lbl[0] & 0x0F) << 16) |
			     ((__u32)inner_ip6->flow_lbl[1] << 8) |
			     (__u32)inner_ip6->flow_lbl[2];
		__u32 addr_hash = jhash_2words(
			((const union v6addr *)&inner_ip6->saddr)->p4 ^
			((const union v6addr *)&inner_ip6->saddr)->p3,
			((const union v6addr *)&inner_ip6->daddr)->p4 ^
			((const union v6addr *)&inner_ip6->daddr)->p3,
			flow ^ inner_ip6->nexthdr);

		if ((const void *)inner_ip6 + sizeof(struct ipv6hdr) + 4 <= data_end) {
			__be32 ports = *(__be32 *)((const void *)inner_ip6 + sizeof(struct ipv6hdr));

			hash = jhash_2words(addr_hash, (__u32)ports, inner_ip6->nexthdr);
		} else {
			hash = addr_hash;
		}
	}
	return hash;
}

/* Calculate UDP source port based on flow hash for ECMP hashing (RFC 8926 Section 3.3).
 * Source port is masked to range [32768, 65535].
 */
static __always_inline __u16
bpf_geneve_calc_sport(const struct __ctx_buff *ctx, const struct iphdr *inner_ip4,
		      const struct ipv6hdr *inner_ip6, __u32 saddr, __u32 daddr)
{
	__u32 hash = 0;

#if __ctx_is == __ctx_skb
	if (ctx)
		hash = ctx->hash;
#endif

	if (!hash && inner_ip4 && ctx) {
		const void *data_end = ctx_data_end(ctx);

		if ((const void *)inner_ip4 + sizeof(struct iphdr) + 4 <= data_end) {
			__be32 ports = *(__be32 *)((const void *)inner_ip4 + sizeof(struct iphdr));

			hash = jhash_3words(inner_ip4->saddr, inner_ip4->daddr, ports, inner_ip4->protocol);
		}
	}

	if (!hash && inner_ip6)
		hash = bpf_geneve_hash_inner_v6(ctx, inner_ip6);

	if (!hash)
		hash = jhash_2words(saddr, daddr, 0);

	return (__u16)((hash & 0x7FFF) | 0x8000);
}

static __always_inline __u16
bpf_geneve_calc_sport6(const struct __ctx_buff *ctx, const struct iphdr *inner_ip4,
		       const struct ipv6hdr *inner_ip6,
		       const union v6addr *saddr, const union v6addr *daddr)
{
	__u32 hash = 0;

#if __ctx_is == __ctx_skb
	if (ctx)
		hash = ctx->hash;
#endif

	if (!hash && inner_ip4 && ctx) {
		const void *data_end = ctx_data_end(ctx);

		if ((const void *)inner_ip4 + sizeof(struct iphdr) + 4 <= data_end) {
			__be32 ports = *(__be32 *)((const void *)inner_ip4 + sizeof(struct iphdr));

			hash = jhash_3words(inner_ip4->saddr, inner_ip4->daddr, ports, inner_ip4->protocol);
		}
	}

	if (!hash && inner_ip6)
		hash = bpf_geneve_hash_inner_v6(ctx, inner_ip6);

	if (!hash)
		hash = jhash_2words(saddr->p4, daddr->p4, 0);

	return (__u16)((hash & 0x7FFF) | 0x8000);
}

/* Validate Geneve options according to RFC 8926 across an arbitrary number of TLVs
 * (up to the RFC 8926 protocol maximum of 63 TLVs / 252 bytes).
 * Uses a non-unrolled bounded loop with explicit scalar constant bounds (offset <= 252)
 * so the BPF verifier proves memory safety in O(1) instruction space.
 */
static __always_inline bool
bpf_geneve_validate_opts(const void *opt_data, __u32 total_opt_len)
{
	const __u8 *base = opt_data;
	__u32 offset = 0;

	if (total_opt_len > BPF_GENEVE_OPT_MAX_LEN)
		return false;

	for (int i = 0; i < BPF_GENEVE_OPT_MAX_COUNT; i++) {
		const struct geneve_opt_hdr *hdr;
		__u32 opt_len;

		if (offset >= total_opt_len)
			break;

		if (offset > 252 || offset + sizeof(*hdr) > total_opt_len)
			return false;

		hdr = (const struct geneve_opt_hdr *)(base + offset);
		opt_len = sizeof(*hdr) + ((__u32)hdr->length << 2);
		if (offset + opt_len > total_opt_len || offset + opt_len > 256)
			return false;

		/* RFC 8926 Section 3.5.2: if a tunnel endpoint encounters a critical
		 * option (high bit of type is 1) that it does not understand,
		 * the packet MUST be dropped.
		 */
		if (hdr->type & GENEVE_OPT_TYPE_CRIT) {
			if (bpf_ntohs(hdr->opt_class) != DSR_GENEVE_OPT_CLASS)
				return false;
		}

		offset += opt_len;
	}

	return offset == total_opt_len;
}

#define BPF_GENEVE_META_MAGIC	0x474E564D /* 'GNVM' */

enum bpf_geneve_dir {
	BPF_GENEVE_DIR_INGRESS = 0,
	BPF_GENEVE_DIR_EGRESS  = 1,
};

/* Generic BPF Geneve metadata holding tunnel endpoint info and arbitrary RFC 8926
 * TLV options (up to the full 252-byte wire maximum). Stored in per-CPU map memory
 * (zero BPF stack footprint).
 */
struct bpf_geneve_metadata {
	__u32 magic;
	__u32 vni;
	__be16 inner_proto;
	__u8 family;
	__u8 opt_len;
	__u8 xdp_decapped;
	__u8 pad;
	__u16 inner_l3_off;
	union {
		struct {
			__be32 saddr;
			__be32 daddr;
		} ip4;
		struct {
			union v6addr saddr;
			union v6addr daddr;
		} ip6;
	};
	__u8 raw_opts[256];
} __aligned(8);

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct bpf_geneve_metadata);
	__uint(max_entries, 2);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_geneve_meta __section_maps_btf;

static __always_inline struct bpf_geneve_metadata *
bpf_geneve_get_meta_slot(enum bpf_geneve_dir dir)
{
	__u32 key = (__u32)dir;

	return map_lookup_elem(&cilium_geneve_meta, &key);
}

static __always_inline void
bpf_geneve_clear_ingress_meta(void)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_INGRESS);

	if (meta) {
		meta->magic = 0;
		meta->xdp_decapped = 0;
		meta->inner_l3_off = 0;
	}
}

/* Generic lookup of any RFC 8926 Geneve TLV option by (opt_class, opt_type)
 * across an arbitrary number of TLVs (up to 63 TLVs / 252 bytes).
 */
static __always_inline const struct geneve_opt_hdr *
bpf_geneve_find_opt(const struct bpf_geneve_metadata *meta,
		    __be16 opt_class, __u8 opt_type)
{
	const __u8 *curr;
	__u32 offset = 0;

	if (!meta || meta->magic != BPF_GENEVE_META_MAGIC)
		return NULL;

	curr = meta->raw_opts;
	for (int i = 0; i < BPF_GENEVE_OPT_MAX_COUNT; i++) {
		const struct geneve_opt_hdr *hdr;
		__u32 opt_len;

		if (offset >= meta->opt_len || offset > 252)
			break;

		hdr = (const struct geneve_opt_hdr *)(curr + offset);
		opt_len = sizeof(*hdr) + ((__u32)hdr->length << 2);
		if (offset + opt_len > meta->opt_len || offset + opt_len > 256)
			break;

		if (hdr->opt_class == opt_class && hdr->type == opt_type)
			return hdr;

		offset += opt_len;
	}

	return NULL;
}

/* Retrieve decapsulated Geneve metadata in XDP or TC (__sk_buff). */
static __always_inline struct bpf_geneve_metadata *
bpf_geneve_get_ingress_meta(const struct __ctx_buff *ctx __maybe_unused)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_INGRESS);

	if (!meta || meta->magic != BPF_GENEVE_META_MAGIC)
		return NULL;

#if __ctx_is == __ctx_skb
	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY ||
	    meta->xdp_decapped)
		return meta;
	return NULL;
#else
	return meta;
#endif
}

/* Load exact opt_bytes (4..252 bytes, always a multiple of 4) from packet into
 * per-CPU map buffer using power-of-two constant chunks.
 * Works on both XDP (struct xdp_md) and TC (struct __sk_buff).
 */
static __always_inline int
bpf_geneve_load_opts(const struct __ctx_buff *ctx, __u32 off, __u8 *dst, __u32 opt_bytes)
{
	__u32 pos = 0;

	if (opt_bytes & 128) {
		if (ctx_load_bytes(ctx, off + pos, dst + pos, 128) < 0)
			return -1;
		pos += 128;
	}
	if (opt_bytes & 64) {
		if (ctx_load_bytes(ctx, off + pos, dst + pos, 64) < 0)
			return -1;
		pos += 64;
	}
	if (opt_bytes & 32) {
		if (ctx_load_bytes(ctx, off + pos, dst + pos, 32) < 0)
			return -1;
		pos += 32;
	}
	if (opt_bytes & 16) {
		if (ctx_load_bytes(ctx, off + pos, dst + pos, 16) < 0)
			return -1;
		pos += 16;
	}
	if (opt_bytes & 8) {
		if (ctx_load_bytes(ctx, off + pos, dst + pos, 8) < 0)
			return -1;
		pos += 8;
	}
	if (opt_bytes & 4) {
		if (ctx_load_bytes(ctx, off + pos, dst + pos, 4) < 0)
			return -1;
	}
	return 0;
}

/* Store exact opt_bytes (4..252 bytes, always a multiple of 4) from per-CPU map
 * or stack buffer into packet using power-of-two constant chunks.
 * Works on both XDP (struct xdp_md) and TC (struct __sk_buff).
 */
static __always_inline int
bpf_geneve_store_opts(struct __ctx_buff *ctx, __u32 off, const void *src, __u32 opt_bytes)
{
	const __u8 *ptr = src;
	__u32 pos = 0;

	if (opt_bytes & 128) {
		if (ctx_store_bytes(ctx, off + pos, ptr + pos, 128, 0) < 0)
			return -1;
		pos += 128;
	}
	if (opt_bytes & 64) {
		if (ctx_store_bytes(ctx, off + pos, ptr + pos, 64, 0) < 0)
			return -1;
		pos += 64;
	}
	if (opt_bytes & 32) {
		if (ctx_store_bytes(ctx, off + pos, ptr + pos, 32, 0) < 0)
			return -1;
		pos += 32;
	}
	if (opt_bytes & 16) {
		if (ctx_store_bytes(ctx, off + pos, ptr + pos, 16, 0) < 0)
			return -1;
		pos += 16;
	}
	if (opt_bytes & 8) {
		if (ctx_store_bytes(ctx, off + pos, ptr + pos, 8, 0) < 0)
			return -1;
		pos += 8;
	}
	if (opt_bytes & 4) {
		if (ctx_store_bytes(ctx, off + pos, ptr + pos, 4, 0) < 0)
			return -1;
	}
	return 0;
}

static __always_inline __sum16 bpf_geneve_ipv4_csum(const struct iphdr *iph)
{
	const __u16 *words = (const __u16 *)iph;
	__u32 sum = 0;

#pragma unroll
	for (int i = 0; i < 10; i++)
		sum += words[i];

	return csum_fold(sum);
}

/* Inspect an encapsulated Geneve packet in-place (without decapsulating) and load
 * up to 252 bytes of wire TLVs into the destination buffer.
 */
static __always_inline int
bpf_geneve_load_wire_opts(const struct __ctx_buff *ctx, __u8 *dst, __u32 *total_len)
{
	const void *data = ctx_data(ctx);
	const void *data_end = ctx_data_end(ctx);
	const struct ethhdr *eth = data;
	__u32 l4_off = 0;

	if ((const void *)(eth + 1) > data_end)
		return -1;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		const struct iphdr *iph = (const void *)(eth + 1);

		if ((const void *)(iph + 1) > data_end)
			return -1;
		if (iph->protocol != IPPROTO_UDP || iph->ihl < 5)
			return -1;
		l4_off = ETH_HLEN + ((__u32)iph->ihl << 2);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		const struct ipv6hdr *ip6h = (const void *)(eth + 1);

		if ((const void *)(ip6h + 1) > data_end)
			return -1;
		if (ip6h->nexthdr != IPPROTO_UDP)
			return -1;
		l4_off = ETH_HLEN + sizeof(struct ipv6hdr);
	} else {
		return -1;
	}

	const struct udphdr *udph = data + l4_off;
	if ((const void *)(udph + 1) > data_end)
		return -1;
	if (udph->dest != bpf_htons(bpf_geneve_dport()))
		return -1;

	const struct genevehdr *geneve = (const void *)(udph + 1);
	if ((const void *)(geneve + 1) > data_end)
		return -1;

	__u32 opt_len = (__u32)geneve->opt_len << 2;
	if (opt_len == 0 || opt_len > BPF_GENEVE_OPT_MAX_LEN)
		return -1;

	__u32 opts_off = l4_off + sizeof(struct udphdr) + sizeof(struct genevehdr);
	if (bpf_geneve_load_opts(ctx, opts_off, dst, opt_len) < 0)
		return -1;

	*total_len = opt_len;
	return 0;
}

/* Shared helper to locate DSR Geneve option across ingress metadata, kernel
 * tunnel options, or in-place wire inspection (up to 63 TLVs / 252 bytes).
 */
static __always_inline const void *
bpf_geneve_find_dsr_opt(const struct __ctx_buff *ctx, __u32 min_opt_len)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_ingress_meta(ctx);
	const __u8 *raw_opts = NULL;
	__u32 total_len = 0;
	__u32 offset = 0;

	if (meta && meta->opt_len > 0) {
		raw_opts = meta->raw_opts;
		total_len = meta->opt_len;
	} else {
		struct bpf_geneve_metadata *slot = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_INGRESS);

		if (slot) {
#if __ctx_is == __ctx_skb
			int ret = ctx_get_tunnel_opt((struct __sk_buff *)ctx,
						     slot->raw_opts,
						     BPF_GENEVE_OPT_MAX_LEN);
			if (ret > 0) {
				raw_opts = slot->raw_opts;
				total_len = (__u32)ret;
			} else
#endif
			if (bpf_geneve_load_wire_opts(ctx, slot->raw_opts, &total_len) == 0)
				raw_opts = slot->raw_opts;
		}
	}

	if (!raw_opts || total_len == 0)
		return NULL;

	for (int i = 0; i < BPF_GENEVE_OPT_MAX_COUNT; i++) {
		const struct geneve_opt_hdr *hdr;
		__u32 opt_len;

		if (offset >= total_len || offset > 256 - min_opt_len)
			break;

		hdr = (const struct geneve_opt_hdr *)(raw_opts + offset);
		opt_len = sizeof(*hdr) + ((__u32)hdr->length << 2);
		if (offset + opt_len > total_len || offset + opt_len > 256)
			break;

		if (hdr->opt_class == bpf_htons(DSR_GENEVE_OPT_CLASS) &&
		    hdr->type == DSR_GENEVE_OPT_TYPE &&
		    opt_len >= min_opt_len)
			return raw_opts + offset;

		offset += opt_len;
	}

	return NULL;
}

static __always_inline int
bpf_geneve_extract_dsr_v4(const struct __ctx_buff *ctx, __be32 *addr, __be16 *port, bool *dsr)
{
	const struct geneve_dsr_opt4 *gopt =
		bpf_geneve_find_dsr_opt(ctx, sizeof(struct geneve_dsr_opt4));

	if (gopt) {
		*dsr = true;
		*port = gopt->port;
		*addr = gopt->addr;
	}
	return 0;
}

static __always_inline int
bpf_geneve_extract_dsr_v6(const struct __ctx_buff *ctx, union v6addr *addr, __be16 *port, bool *dsr)
{
	const struct geneve_dsr_opt6 *gopt =
		bpf_geneve_find_dsr_opt(ctx, sizeof(struct geneve_dsr_opt6));

	if (gopt) {
		*dsr = true;
		*port = gopt->port;
		ipv6_addr_copy_unaligned(addr, (union v6addr *)&gopt->addr);
	}
	return 0;
}

static __always_inline int
bpf_geneve_strip_outer_hdr(struct __ctx_buff *ctx, __u16 hdr_len, bool is_teb,
			   __be16 inner_proto, const struct ethhdr *outer_eth __maybe_unused,
			   const struct ethhdr *inner_eth __maybe_unused)
{
	void *data, *data_end;
	struct ethhdr *eth;

#if __ctx_is == __ctx_xdp
	if (is_teb) {
		if (xdp_adjust_head(ctx, (__s32)(ETH_HLEN + hdr_len)) < 0)
			return DROP_INVALID;
	} else {
		if (xdp_adjust_head(ctx, (__s32)hdr_len) < 0)
			return DROP_INVALID;
		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		if (data + ETH_HLEN > data_end)
			return DROP_INVALID;
		eth = data;
		*eth = *outer_eth;
		eth->h_proto = inner_proto;
	}
#else
	int ret;

	if (is_teb) {
		ret = ctx_adjust_hroom(ctx, -(__s32)(hdr_len + ETH_HLEN), BPF_ADJ_ROOM_MAC,
				       BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET);
		if (ret < 0)
			return ret;
		if (ctx_store_bytes(ctx, 0, inner_eth, ETH_HLEN, 0) < 0)
			return DROP_INVALID;
	} else {
		ret = ctx_adjust_hroom(ctx, -(__s32)hdr_len, BPF_ADJ_ROOM_MAC,
				       BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET);
		if (ret < 0)
			return ret;
		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		if (data + ETH_HLEN > data_end)
			return DROP_INVALID;
		eth = data;
		eth->h_proto = inner_proto;
	}

	{
		__u32 pull_len = ETH_HLEN + ((inner_proto == bpf_htons(ETH_P_IPV6)) ?
					     sizeof(struct ipv6hdr) : sizeof(struct iphdr));

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		if (data + pull_len > data_end) {
			if (ctx_pull_data(ctx, pull_len) < 0)
				return DROP_INVALID;
		}
	}
#endif
	return 0;
}

/* Native BPF GENEVE decapsulation for IPv4 underlay on both XDP and TC (__sk_buff). */
static __always_inline int
bpf_geneve_decap4(struct __ctx_buff *ctx, struct bpf_tunnel_key *key)
{
	struct geneve_encaphdr4 *hdr;
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	struct ethhdr *eth, outer_eth, inner_eth = {};
	__be16 wire_proto, inner_proto;
	__u16 hdr_len;
	bool is_teb;
	int ret;

	if (data + ETH_HLEN + sizeof(*hdr) > data_end) {
		if (ctx_pull_data(ctx, ETH_HLEN + sizeof(*hdr)) < 0)
			return DROP_INVALID;
		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		if (data + ETH_HLEN + sizeof(*hdr) > data_end)
			return DROP_INVALID;
	}

	eth = data;
	outer_eth = *eth;

	hdr = (struct geneve_encaphdr4 *)((void *)data + ETH_HLEN);
	if (hdr->ip.protocol != IPPROTO_UDP ||
	    hdr->udp.dest != bpf_htons(bpf_geneve_dport()) ||
	    hdr->geneve.ver != BPF_GENEVE_VERSION)
		return DROP_INVALID;

	hdr_len = bpf_geneve_encaphdr4_len(hdr->geneve.opt_len);
	wire_proto = hdr->geneve.protocol_type;
	is_teb = (wire_proto == bpf_htons(ETH_P_TEB));
	inner_proto = wire_proto;

	if (is_teb) {
		if (ctx_load_bytes(ctx, ETH_HLEN + hdr_len, &inner_eth, ETH_HLEN) < 0)
			return DROP_INVALID;
		inner_proto = inner_eth.h_proto;
	}

	if (key) {
		memset(key, 0, sizeof(*key));
		key->tunnel_id = bpf_geneve_hdr_vni(&hdr->geneve);
		key->remote_ipv4 = bpf_ntohl(hdr->ip.saddr);
		key->local_ipv4 = bpf_ntohl(hdr->ip.daddr);
		key->tunnel_ttl = (__u8)hdr->ip.ttl;
	}

	{
		struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_INGRESS);

		if (meta) {
			__u32 opt_bytes = (__u32)hdr->geneve.opt_len << 2;

			meta->magic = BPF_GENEVE_META_MAGIC;
			meta->vni = bpf_geneve_hdr_vni(&hdr->geneve);
			meta->inner_proto = inner_proto;
			meta->family = AF_INET;
			meta->ip4.saddr = hdr->ip.saddr;
			meta->ip4.daddr = hdr->ip.daddr;
			meta->opt_len = 0;
			meta->inner_l3_off = 0;
			meta->xdp_decapped = (__ctx_is == __ctx_xdp) ? 1 : 0;

			if (unlikely(opt_bytes > 0)) {
				if (opt_bytes > BPF_GENEVE_OPT_MAX_LEN ||
				    bpf_geneve_load_opts(ctx, ETH_HLEN + sizeof(*hdr),
							 meta->raw_opts, opt_bytes) < 0 ||
				    !bpf_geneve_validate_opts(meta->raw_opts, opt_bytes))
					return DROP_INVALID;
				meta->opt_len = (__u8)opt_bytes;
			}
		}
	}

	ret = bpf_geneve_strip_outer_hdr(ctx, hdr_len, is_teb, inner_proto, &outer_eth, &inner_eth);
	if (ret < 0)
		return ret;

#if __ctx_is == __ctx_skb && defined(BPF_TEST)
	if (key && ctx_set_tunnel_key(ctx, key, sizeof(*key), 0) < 0)
		return DROP_WRITE_ERROR;
#endif
	return 0;
}

/* Native BPF GENEVE decapsulation for IPv6 underlay on both XDP and TC (__sk_buff). */
static __always_inline int
bpf_geneve_decap6(struct __ctx_buff *ctx, struct bpf_tunnel_key *key)
{
	struct geneve_encaphdr6 *hdr;
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	struct ethhdr *eth, outer_eth, inner_eth = {};
	__be16 wire_proto, inner_proto;
	__u16 hdr_len;
	bool is_teb;
	int ret;

	if (data + ETH_HLEN + sizeof(*hdr) > data_end) {
		if (ctx_pull_data(ctx, ETH_HLEN + sizeof(*hdr)) < 0)
			return DROP_INVALID;
		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		if (data + ETH_HLEN + sizeof(*hdr) > data_end)
			return DROP_INVALID;
	}

	eth = data;
	outer_eth = *eth;

	hdr = (struct geneve_encaphdr6 *)((void *)data + ETH_HLEN);
	if (hdr->ip6.nexthdr != IPPROTO_UDP ||
	    hdr->udp.dest != bpf_htons(bpf_geneve_dport()) ||
	    hdr->geneve.ver != BPF_GENEVE_VERSION)
		return DROP_INVALID;

	hdr_len = bpf_geneve_encaphdr6_len(hdr->geneve.opt_len);
	wire_proto = hdr->geneve.protocol_type;
	is_teb = (wire_proto == bpf_htons(ETH_P_TEB));
	inner_proto = wire_proto;

	if (is_teb) {
		if (ctx_load_bytes(ctx, ETH_HLEN + hdr_len, &inner_eth, ETH_HLEN) < 0)
			return DROP_INVALID;
		inner_proto = inner_eth.h_proto;
	}

	if (key) {
		memset(key, 0, sizeof(*key));
		key->tunnel_id = bpf_geneve_hdr_vni(&hdr->geneve);
		key->remote_ipv6[0] = ((const union v6addr *)&hdr->ip6.saddr)->p1;
		key->remote_ipv6[1] = ((const union v6addr *)&hdr->ip6.saddr)->p2;
		key->remote_ipv6[2] = ((const union v6addr *)&hdr->ip6.saddr)->p3;
		key->remote_ipv6[3] = ((const union v6addr *)&hdr->ip6.saddr)->p4;
		key->tunnel_ttl = (__u8)hdr->ip6.hop_limit;
	}

	{
		struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_INGRESS);

		if (meta) {
			__u32 opt_bytes = (__u32)hdr->geneve.opt_len << 2;

			meta->magic = BPF_GENEVE_META_MAGIC;
			meta->vni = bpf_geneve_hdr_vni(&hdr->geneve);
			meta->inner_proto = inner_proto;
			meta->family = AF_INET6;
			meta->ip6.saddr = *(const union v6addr *)&hdr->ip6.saddr;
			meta->ip6.daddr = *(const union v6addr *)&hdr->ip6.daddr;
			meta->opt_len = 0;
			meta->inner_l3_off = 0;
			meta->xdp_decapped = (__ctx_is == __ctx_xdp) ? 1 : 0;

			if (unlikely(opt_bytes > 0)) {
				if (opt_bytes > BPF_GENEVE_OPT_MAX_LEN ||
				    bpf_geneve_load_opts(ctx, ETH_HLEN + sizeof(*hdr),
							 meta->raw_opts, opt_bytes) < 0 ||
				    !bpf_geneve_validate_opts(meta->raw_opts, opt_bytes))
					return DROP_INVALID;
				meta->opt_len = (__u8)opt_bytes;
			}
		}
	}

	ret = bpf_geneve_strip_outer_hdr(ctx, hdr_len, is_teb, inner_proto, &outer_eth, &inner_eth);
	if (ret < 0)
		return ret;

#if __ctx_is == __ctx_skb && defined(BPF_TEST)
	if (key && ctx_set_tunnel_key(ctx, key, sizeof(*key), BPF_F_TUNINFO_IPV6) < 0)
		return DROP_WRITE_ERROR;
#endif
	return 0;
}

/* Native BPF GENEVE encapsulation for IPv4 underlay on both XDP and TC (__sk_buff).
 * Supports both GENEVE_INNER_PROTO_IP (L3) and GENEVE_INNER_PROTO_ETH (L2 TEB),
 * and automatically merges any pending egress TLVs from cilium_geneve_meta.
 */
static __always_inline int
bpf_geneve_encap4_with_sport(struct __ctx_buff *ctx, __u32 saddr, __u32 daddr,
			     __u32 vni, __be16 proto, __be16 sport_be16,
			     const void *opt, __u32 opt_len)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);
	struct geneve_encaphdr4 *hdr;
	void *data, *data_end;
	struct iphdr *inner_ip4;
	struct ipv6hdr *inner_ip6;
	struct ethhdr *eth, inner_eth = {};
	__u32 extra_opt_len = 0, total_opt_len;
	__u8 opt_words;
	__u16 hdr_len, room_len, inner_len, sport, dport;
	__u8 inner_tos __maybe_unused = 0;
	__be16 udp_len, ip_tot_len, geneve_proto;
	bool is_eth_mode = (bpf_geneve_inner_proto_mode() == GENEVE_INNER_PROTO_ETH);
	__u64 flags;

	if (ctx_load_bytes(ctx, 0, &inner_eth, ETH_HLEN) < 0)
		return DROP_INVALID;
	if (!proto)
		proto = inner_eth.h_proto;

	if (meta && meta->magic == BPF_GENEVE_META_MAGIC && meta->opt_len > 0 && opt != meta->raw_opts)
		extra_opt_len = meta->opt_len;

	total_opt_len = opt_len + extra_opt_len;
	if (total_opt_len > BPF_GENEVE_OPT_MAX_LEN || (total_opt_len & 3) != 0)
		return DROP_INVALID;

	opt_words = (__u8)(total_opt_len >> 2);
	hdr_len = bpf_geneve_encaphdr4_len(opt_words);

	if (proto == bpf_htons(ETH_P_IP)) {
		if (!revalidate_data(ctx, &data, &data_end, &inner_ip4))
			return DROP_INVALID;
#if __ctx_is == __ctx_skb
		inner_len = bpf_ntohs(inner_ip4->tot_len);
		inner_tos = inner_ip4->tos;
#else
		inner_len = (__u16)(ctx_full_len(ctx) - ETH_HLEN);
#endif
		sport = sport_be16 ? bpf_ntohs(sport_be16) :
				     bpf_geneve_calc_sport(ctx, inner_ip4, NULL, saddr, daddr);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		if (!revalidate_data(ctx, &data, &data_end, &inner_ip6))
			return DROP_INVALID;
		inner_len = (__u16)(ctx_full_len(ctx) - ETH_HLEN);
#if __ctx_is == __ctx_skb
		inner_tos = (__u8)((inner_ip6->priority << 4) | (inner_ip6->flow_lbl[0] >> 4));
#endif
		sport = sport_be16 ? bpf_ntohs(sport_be16) :
				     bpf_geneve_calc_sport(ctx, NULL, inner_ip6, saddr, daddr);
	} else {
		inner_len = (__u16)(ctx_full_len(ctx) - ETH_HLEN);
		sport = sport_be16 ? bpf_ntohs(sport_be16) :
				     bpf_geneve_calc_sport(ctx, NULL, NULL, saddr, daddr);
	}

	if (is_eth_mode) {
		room_len = hdr_len + ETH_HLEN;
		udp_len = bpf_htons((__u16)(inner_len + ETH_HLEN + hdr_len - sizeof(struct iphdr)));
		geneve_proto = bpf_htons(ETH_P_TEB);
	} else {
		room_len = hdr_len;
		udp_len = bpf_htons((__u16)(inner_len + hdr_len - sizeof(struct iphdr)));
		geneve_proto = proto;
	}
	ip_tot_len = bpf_htons((__u16)(bpf_ntohs(udp_len) + sizeof(struct iphdr)));

#if __ctx_is == __ctx_skb
	flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET |
		BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
	if (is_eth_mode)
		flags |= BPF_F_ADJ_ROOM_ENCAP_L2(ETH_HLEN) |
			 BPF_F_ADJ_ROOM_ENCAP_L2_ETH;
#else
	flags = BPF_F_ADJ_ROOM_NO_CSUM_RESET;
#endif
	if (ctx_adjust_hroom(ctx, room_len, BPF_ADJ_ROOM_MAC, flags) < 0) {
#if __ctx_is == __ctx_skb
		flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET;
		if (ctx_adjust_hroom(ctx, room_len, BPF_ADJ_ROOM_MAC, flags) < 0)
			return DROP_INVALID;
#else
		return DROP_INVALID;
#endif
	}

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + sizeof(*hdr) > data_end)
		return DROP_INVALID;

	eth = data;
	*eth = inner_eth;
	eth->h_proto = bpf_htons(ETH_P_IP);

	dport = bpf_geneve_dport();

	hdr = (struct geneve_encaphdr4 *)((void *)data + ETH_HLEN);
	hdr->ip.version = IPVERSION;
	hdr->ip.ihl = (__u8)(sizeof(struct iphdr) >> 2);
#if __ctx_is == __ctx_skb
	hdr->ip.tos = inner_tos;
	hdr->ip.frag_off = bpf_htons(IP_DF);
#else
	hdr->ip.tos = 0;
	hdr->ip.frag_off = 0;
#endif
	hdr->ip.tot_len = ip_tot_len;
	hdr->ip.id = 0;
	hdr->ip.ttl = IPDEFTTL;
	hdr->ip.protocol = IPPROTO_UDP;
	hdr->ip.saddr = saddr;
	hdr->ip.daddr = daddr;
	hdr->ip.check = 0;
	hdr->ip.check = bpf_geneve_ipv4_csum(&hdr->ip);

	hdr->udp.source = bpf_htons(sport);
	hdr->udp.dest = bpf_htons(dport);
	hdr->udp.len = udp_len;
	hdr->udp.check = 0;

	bpf_geneve_hdr_init(&hdr->geneve, geneve_proto, vni, opt_words);

	if (opt && opt_len > 0) {
		if (bpf_geneve_store_opts(ctx, ETH_HLEN + sizeof(*hdr), opt, opt_len) < 0)
			return DROP_INVALID;
	}
	if (meta && extra_opt_len > 0) {
		if (bpf_geneve_store_opts(ctx, ETH_HLEN + sizeof(*hdr) + opt_len,
					  meta->raw_opts, extra_opt_len) < 0)
			return DROP_INVALID;
	}
	if (meta && meta->magic == BPF_GENEVE_META_MAGIC)
		meta->magic = 0;

	if (is_eth_mode) {
		if (ctx_store_bytes(ctx, ETH_HLEN + hdr_len, &inner_eth, ETH_HLEN, 0) < 0)
			return DROP_INVALID;
	}

	return 0;
}

static __always_inline int
bpf_geneve_encap4(struct __ctx_buff *ctx, __u32 saddr, __u32 daddr,
		  __u32 vni, __be16 proto, const void *opt, __u32 opt_len)
{
	return bpf_geneve_encap4_with_sport(ctx, saddr, daddr, vni, proto, 0, opt, opt_len);
}

/* Native BPF GENEVE encapsulation for IPv6 underlay on both XDP and TC (__sk_buff). */
static __always_inline int
bpf_geneve_encap6_with_sport(struct __ctx_buff *ctx, const union v6addr *saddr,
			     const union v6addr *daddr, __u32 vni, __be16 proto,
			     __be16 sport_be16, const void *opt, __u32 opt_len)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);
	struct geneve_encaphdr6 *hdr;
	void *data, *data_end;
	struct iphdr *inner_ip4;
	struct ipv6hdr *inner_ip6;
	struct ethhdr *eth, inner_eth = {};
	__u32 extra_opt_len = 0, total_opt_len;
	__u8 opt_words;
	__u16 hdr_len, room_len, inner_len, sport, dport;
	__u8 inner_tos __maybe_unused = 0;
	__be16 udp_len, geneve_proto;
	bool is_eth_mode = (bpf_geneve_inner_proto_mode() == GENEVE_INNER_PROTO_ETH);
	__u64 flags;

	if (ctx_load_bytes(ctx, 0, &inner_eth, ETH_HLEN) < 0)
		return DROP_INVALID;
	if (!proto)
		proto = inner_eth.h_proto;

	if (meta && meta->magic == BPF_GENEVE_META_MAGIC && meta->opt_len > 0 && opt != meta->raw_opts)
		extra_opt_len = meta->opt_len;

	total_opt_len = opt_len + extra_opt_len;
	if (total_opt_len > BPF_GENEVE_OPT_MAX_LEN || (total_opt_len & 3) != 0)
		return DROP_INVALID;

	opt_words = (__u8)(total_opt_len >> 2);
	hdr_len = bpf_geneve_encaphdr6_len(opt_words);

	if (proto == bpf_htons(ETH_P_IP)) {
		if (!revalidate_data(ctx, &data, &data_end, &inner_ip4))
			return DROP_INVALID;
		inner_len = bpf_ntohs(inner_ip4->tot_len);
#if __ctx_is == __ctx_skb
		inner_tos = inner_ip4->tos;
#endif
		sport = sport_be16 ? bpf_ntohs(sport_be16) :
				     bpf_geneve_calc_sport6(ctx, inner_ip4, NULL, saddr, daddr);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		if (!revalidate_data(ctx, &data, &data_end, &inner_ip6))
			return DROP_INVALID;
		inner_len = (__u16)(ctx_full_len(ctx) - ETH_HLEN);
#if __ctx_is == __ctx_skb
		inner_tos = (__u8)((inner_ip6->priority << 4) | (inner_ip6->flow_lbl[0] >> 4));
#endif
		sport = sport_be16 ? bpf_ntohs(sport_be16) :
				     bpf_geneve_calc_sport6(ctx, NULL, inner_ip6, saddr, daddr);
	} else {
		inner_len = (__u16)(ctx_full_len(ctx) - ETH_HLEN);
		sport = sport_be16 ? bpf_ntohs(sport_be16) :
				     bpf_geneve_calc_sport6(ctx, NULL, NULL, saddr, daddr);
	}

	if (is_eth_mode) {
		room_len = hdr_len + ETH_HLEN;
		udp_len = bpf_htons((__u16)(inner_len + ETH_HLEN + hdr_len - sizeof(struct ipv6hdr)));
		geneve_proto = bpf_htons(ETH_P_TEB);
	} else {
		room_len = hdr_len;
		udp_len = bpf_htons((__u16)(inner_len + hdr_len - sizeof(struct ipv6hdr)));
		geneve_proto = proto;
	}

#if __ctx_is == __ctx_skb
	flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET |
		BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
	if (is_eth_mode)
		flags |= BPF_F_ADJ_ROOM_ENCAP_L2(ETH_HLEN) |
			 BPF_F_ADJ_ROOM_ENCAP_L2_ETH;
#else
	flags = BPF_F_ADJ_ROOM_NO_CSUM_RESET;
#endif
	if (ctx_adjust_hroom(ctx, room_len, BPF_ADJ_ROOM_MAC, flags) < 0) {
#if __ctx_is == __ctx_skb
		flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET;
		if (ctx_adjust_hroom(ctx, room_len, BPF_ADJ_ROOM_MAC, flags) < 0)
			return DROP_INVALID;
#else
		return DROP_INVALID;
#endif
	}

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + sizeof(*hdr) > data_end)
		return DROP_INVALID;

	eth = data;
	*eth = inner_eth;
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	dport = bpf_geneve_dport();

	hdr = (struct geneve_encaphdr6 *)((void *)data + ETH_HLEN);
	hdr->ip6.version = 6;
#if __ctx_is == __ctx_skb
	hdr->ip6.priority = (__u8)(inner_tos >> 4);
	hdr->ip6.flow_lbl[0] = (__u8)((inner_tos & 0x0F) << 4);
#else
	hdr->ip6.priority = 0;
	hdr->ip6.flow_lbl[0] = 0;
#endif
	hdr->ip6.flow_lbl[1] = 0;
	hdr->ip6.flow_lbl[2] = 0;
	hdr->ip6.payload_len = udp_len;
	hdr->ip6.nexthdr = IPPROTO_UDP;
	hdr->ip6.hop_limit = IPDEFTTL;
	ipv6_addr_copy((union v6addr *)&hdr->ip6.saddr, saddr);
	ipv6_addr_copy((union v6addr *)&hdr->ip6.daddr, daddr);

	hdr->udp.source = bpf_htons(sport);
	hdr->udp.dest = bpf_htons(dport);
	hdr->udp.len = udp_len;
	hdr->udp.check = 0;

	bpf_geneve_hdr_init(&hdr->geneve, geneve_proto, vni, opt_words);

	if (opt && opt_len > 0) {
		if (bpf_geneve_store_opts(ctx, ETH_HLEN + sizeof(*hdr), opt, opt_len) < 0)
			return DROP_INVALID;
	}
	if (meta && extra_opt_len > 0) {
		if (bpf_geneve_store_opts(ctx, ETH_HLEN + sizeof(*hdr) + opt_len,
					  meta->raw_opts, extra_opt_len) < 0)
			return DROP_INVALID;
	}
	if (meta && meta->magic == BPF_GENEVE_META_MAGIC)
		meta->magic = 0;

	if (is_eth_mode) {
		if (ctx_store_bytes(ctx, ETH_HLEN + hdr_len, &inner_eth, ETH_HLEN, 0) < 0)
			return DROP_INVALID;
	}

	return 0;
}

static __always_inline int
bpf_geneve_encap6(struct __ctx_buff *ctx, const union v6addr *saddr,
		  const union v6addr *daddr, __u32 vni, __be16 proto,
		  const void *opt, __u32 opt_len)
{
	return bpf_geneve_encap6_with_sport(ctx, saddr, daddr, vni, proto, 0, opt, opt_len);
}

#if __ctx_is == __ctx_xdp
/* Insert opt_len bytes of new Geneve TLV options into an ALREADY-ENCAPSULATED
 * Geneve packet on XDP without double-encapsulating.
 */
static __always_inline int
bpf_geneve_xdp_insert_opt(struct xdp_md *ctx, const void *opt, __u32 opt_len)
{
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	struct ethhdr *eth = data;

	if (!opt || opt_len == 0 || opt_len > BPF_GENEVE_OPT_MAX_LEN || (opt_len & 3) != 0)
		return DROP_INVALID;

	if ((void *)(eth + 1) > data_end)
		return DROP_INVALID;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		__u8 hdr_buf[50] __aligned(2);
		struct iphdr *iph = (struct iphdr *)(hdr_buf + ETH_HLEN);
		struct udphdr *udph = (struct udphdr *)(hdr_buf + ETH_HLEN + sizeof(struct iphdr));
		struct genevehdr *g = (struct genevehdr *)(hdr_buf + 42);

		if (data + 50 > data_end || ctx_load_bytes(ctx, 0, hdr_buf, 50) < 0 ||
		    ((__u32)g->opt_len << 2) + opt_len > BPF_GENEVE_OPT_MAX_LEN)
			return DROP_INVALID;

		g->opt_len += (__u8)(opt_len >> 2);
		udph->len = bpf_htons((__u16)(bpf_ntohs(udph->len) + opt_len));
		iph->tot_len = bpf_htons((__u16)(bpf_ntohs(iph->tot_len) + opt_len));
		iph->check = 0;
		iph->check = bpf_geneve_ipv4_csum(iph);

		if (xdp_adjust_head(ctx, -(__s32)opt_len))
			return DROP_INVALID;
		if (ctx_store_bytes(ctx, 0, hdr_buf, 50, 0) < 0 ||
		    bpf_geneve_store_opts(ctx, 50, opt, opt_len) < 0)
			return DROP_WRITE_ERROR;
		return 0;
	}

	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		__u8 hdr_buf6[70] __aligned(2);
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(hdr_buf6 + ETH_HLEN);
		struct udphdr *udph = (struct udphdr *)(hdr_buf6 + ETH_HLEN + sizeof(struct ipv6hdr));
		struct genevehdr *g = (struct genevehdr *)(hdr_buf6 + 62);

		if (data + 70 > data_end || ctx_load_bytes(ctx, 0, hdr_buf6, 70) < 0 ||
		    ((__u32)g->opt_len << 2) + opt_len > BPF_GENEVE_OPT_MAX_LEN)
			return DROP_INVALID;

		g->opt_len += (__u8)(opt_len >> 2);
		udph->len = bpf_htons((__u16)(bpf_ntohs(udph->len) + opt_len));
		ip6h->payload_len = bpf_htons((__u16)(bpf_ntohs(ip6h->payload_len) + opt_len));

		if (xdp_adjust_head(ctx, -(__s32)opt_len))
			return DROP_INVALID;
		if (ctx_store_bytes(ctx, 0, hdr_buf6, 70, 0) < 0 ||
		    bpf_geneve_store_opts(ctx, 70, opt, opt_len) < 0)
			return DROP_WRITE_ERROR;
		return 0;
	}

	return DROP_INVALID;
}

/* Inspect an incoming XDP packet to detect if it is already Geneve-encapsulated,
 * locate its inner L3 offset and inner ethertype (skipping up to 63 TLVs and optional
 * inner Ethernet TEB header), and record inner_l3_off in cilium_geneve_meta.
 */
static __always_inline void
bpf_geneve_xdp_find_inner_l3(struct __ctx_buff *ctx, int *l3_off, __be16 *inner_proto)
{
	const void *data = ctx_data(ctx);
	const void *data_end = ctx_data_end(ctx);
	const struct ethhdr *eth = data;
	__u16 tunnel_port = bpf_geneve_dport();
	struct genevehdr geneve;
	struct udphdr udp;
	int l4_off = 0;

	*l3_off = ETH_HLEN;
	if ((const void *)(eth + 1) > data_end)
		goto out;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		const struct iphdr *ip4 = (const void *)(eth + 1);

		if ((const void *)(ip4 + 1) > data_end ||
		    ip4->protocol != IPPROTO_UDP || (ip4->ihl << 2) != sizeof(*ip4))
			goto out;
		l4_off = ETH_HLEN + sizeof(*ip4);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		const struct ipv6hdr *ip6 = (const void *)(eth + 1);

		if ((const void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_UDP)
			goto out;
		l4_off = ETH_HLEN + sizeof(*ip6);
	} else {
		goto out;
	}

	if (ctx_load_bytes(ctx, l4_off, &udp, sizeof(udp)) == 0 &&
	    udp.dest == bpf_htons(tunnel_port) && udp.check == 0 &&
	    ctx_load_bytes(ctx, l4_off + sizeof(struct udphdr), &geneve, sizeof(geneve)) == 0) {
		int next_off = l4_off + sizeof(struct udphdr) +
			       sizeof(struct genevehdr) + ((int)geneve.opt_len << 2);

		if (geneve.protocol_type == bpf_htons(ETH_P_TEB)) {
			__be16 eth_proto = 0;

			if (ctx_load_bytes(ctx, next_off + offsetof(struct ethhdr, h_proto),
					   &eth_proto, sizeof(eth_proto)) == 0 &&
			    (eth_proto == bpf_htons(ETH_P_IP) || eth_proto == bpf_htons(ETH_P_IPV6))) {
				*l3_off = next_off + ETH_HLEN;
				*inner_proto = eth_proto;
			}
		} else if (geneve.protocol_type == bpf_htons(ETH_P_IP) ||
			   geneve.protocol_type == bpf_htons(ETH_P_IPV6)) {
			*l3_off = next_off;
			*inner_proto = geneve.protocol_type;
		}
	}

out:
	{
		struct bpf_geneve_metadata *meta =
			bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_INGRESS);

		if (meta)
			meta->inner_l3_off = (*l3_off == ETH_HLEN) ? 0 : (__u16)*l3_off;
	}
}

/* Rewrite the outer IPv4/IPv6 header of an already-encapsulated Geneve packet in-place
 * on XDP (updating saddr to local routing IP and daddr to backend node tunnel endpoint)
 * and optionally insert DSR TLV option bytes.
 */
static __always_inline int
bpf_geneve_xdp_rewrite_outer_and_opt(struct __ctx_buff *ctx,
				     const union v6addr *dst_v6, __be32 dst_v4,
				     const void *opt, __u32 opt_len)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_INGRESS);
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);

	if (data + sizeof(struct ethhdr) > data_end)
		return DROP_INVALID;

	if (((struct ethhdr *)data)->h_proto == bpf_htons(ETH_P_IPV6)) {
		union v6addr src_ip6 = CONFIG(ipv6_direct_routing);

		if (!dst_v6 || data + ETH_HLEN + sizeof(struct ipv6hdr) > data_end)
			return DROP_INVALID;
		if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
				    src_ip6.addr, 16, 0) < 0 ||
		    ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
				    dst_v6->addr, 16, 0) < 0)
			return DROP_WRITE_ERROR;
	} else if (((struct ethhdr *)data)->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *outer_ip4 = data + ETH_HLEN;
		__be32 old_saddr, old_daddr, new_saddr, new_daddr;
		__wsum sum;

		if (!dst_v4 || (void *)(outer_ip4 + 1) > data_end)
			return DROP_INVALID;

		old_saddr = outer_ip4->saddr;
		old_daddr = outer_ip4->daddr;
		new_saddr = CONFIG(ipv4_direct_routing).be32;
		new_daddr = dst_v4;

		sum = csum_diff(&old_saddr, 4, &new_saddr, 4, 0);
		sum = csum_diff(&old_daddr, 4, &new_daddr, 4, sum);

		if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr),
				    &new_saddr, 4, 0) < 0 ||
		    ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr),
				    &new_daddr, 4, 0) < 0 ||
		    l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
				    0, sum, 0) < 0)
			return DROP_WRITE_ERROR;
	} else {
		return DROP_INVALID;
	}

	if (opt && opt_len > 0) {
		int ret = bpf_geneve_xdp_insert_opt(ctx, opt, opt_len);

		if (ret)
			return ret;
	}

	if (meta)
		meta->inner_l3_off = 0;
	return CTX_ACT_REDIRECT;
}
#endif /* __ctx_is == __ctx_xdp */

#if __ctx_is == __ctx_skb

#if defined(ENABLE_BPF_GENEVE) && !defined(SKIP_GENEVE_HANDLING)

#include "tailcall.h"
#include "drop.h"
#include "fib.h"
#include "trace.h"
#include "identity.h"

#if defined(ENABLE_NODEPORT) && (defined(IS_BPF_LXC) || defined(IS_BPF_HOST) || defined(IS_BPF_OVERLAY))
# ifdef ENABLE_IPV4
static __always_inline int
nodeport_rev_dnat_fwd_ipv4(struct __ctx_buff *ctx, bool *snat_done,
			   bool revdnat_only, struct trace_ctx *trace,
			   __s8 *ext_err);
# endif
# ifdef ENABLE_IPV6
static __always_inline int
nodeport_rev_dnat_fwd_ipv6(struct __ctx_buff *ctx, bool *snat_done,
			   bool revdnat_only, struct trace_ctx *trace,
			   __s8 *ext_err);
# endif
#endif

static __always_inline int
bpf_geneve_rev_dnat_fwd(struct __ctx_buff *ctx, __be16 *inner_proto)
{
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	struct ethhdr *eth = data;
	__be16 proto = bpf_htons(ETH_P_IP);
	bool snat_done __maybe_unused = false;
	struct trace_ctx trace __maybe_unused = {};
	__s8 ext_err __maybe_unused = 0;

	if ((void *)(eth + 1) <= data_end)
		proto = eth->h_proto;
	if (inner_proto)
		*inner_proto = proto;

#if defined(ENABLE_NODEPORT) && (defined(IS_BPF_LXC) || defined(IS_BPF_HOST) || defined(IS_BPF_OVERLAY))
# ifdef ENABLE_IPV4
	if (proto == bpf_htons(ETH_P_IP))
		return nodeport_rev_dnat_fwd_ipv4(ctx, &snat_done, true, &trace, &ext_err);
# endif
# ifdef ENABLE_IPV6
	if (proto == bpf_htons(ETH_P_IPV6))
		return nodeport_rev_dnat_fwd_ipv6(ctx, &snat_done, true, &trace, &ext_err);
# endif
#endif
	return CTX_ACT_OK;
}

#ifndef BPF_GENEVE_ROUTE_CACHE_TTL_NS
#define BPF_GENEVE_ROUTE_CACHE_TTL_NS (30ULL * 1000000000ULL)
#endif

struct geneve_route_entry {
	__u8 dmac[ETH_ALEN];
	__u8 pad1[2];
	__u8 smac[ETH_ALEN];
	__u8 pad2[2];
	__u32 ifindex;
	__be32 saddr;
	__u64 ts;
} __aligned(8);

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __be32);
	__type(value, struct geneve_route_entry);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_geneve_routes __section_maps_btf;

#ifdef ENABLE_IPV6
struct geneve_route6_entry {
	__u8 dmac[ETH_ALEN];
	__u8 pad1[2];
	__u8 smac[ETH_ALEN];
	__u8 pad2[2];
	__u32 ifindex;
	union v6addr saddr;
	__u64 ts;
} __aligned(8);

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, union v6addr);
	__type(value, struct geneve_route6_entry);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_geneve_routes6 __section_maps_btf;
#endif

static __always_inline void copy_mac_safe(__u8 *dst, const __u8 *src)
{
	const volatile __u16 *s = (const volatile __u16 *)src;
	volatile __u16 *d = (volatile __u16 *)dst;

	d[0] = s[0];
	d[1] = s[1];
	d[2] = s[2];
}

static __always_inline bool mac_is_zero_safe(const __u8 *mac)
{
	const volatile __u16 *m = (const volatile __u16 *)mac;

	return (m[0] | m[1] | m[2]) == 0;
}

#ifndef __DEVICE_MTU_CONFIG_DECLARED
#define __DEVICE_MTU_CONFIG_DECLARED
DECLARE_CONFIG(__u16, device_mtu, "MTU of the device the bpf program is attached to")
#endif

#include "icmp.h"
#ifdef ENABLE_IPV6
#include "icmp6.h"
#endif

/* Calculate the exact post-encapsulation outer L3 length and Geneve header
 * overhead (including optional inner Ethernet header in TEB mode and any
 * pending egress TLV options).
 */
static __always_inline int
bpf_geneve_check_mtu(struct __ctx_buff *ctx, __be16 inner_proto,
		     bool is_ipv6_outer, __u32 opt_len,
		     __u16 *outer_l3_len, __u16 *encap_overhead)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);
	bool is_eth_mode = (bpf_geneve_inner_proto_mode() == GENEVE_INNER_PROTO_ETH);
	__u32 extra_opt_len = 0, total_opt_len;
	__u16 hdr_len, inner_l3_len = 0;

	if (meta && meta->magic == BPF_GENEVE_META_MAGIC && meta->opt_len > 0)
		extra_opt_len = meta->opt_len;

	total_opt_len = opt_len + extra_opt_len;
	hdr_len = (is_ipv6_outer ? (__u16)sizeof(struct geneve_encaphdr6) :
				   (__u16)sizeof(struct geneve_encaphdr4)) +
		  (__u16)total_opt_len;
	*encap_overhead = is_eth_mode ? (hdr_len + ETH_HLEN) : hdr_len;

#if __ctx_is == __ctx_skb
	if (ctx->gso_segs > 1) {
		if (!ctx->gso_size)
			return 0;
		inner_l3_len = (__u16)(ctx->gso_size +
				       (inner_proto == bpf_htons(ETH_P_IPV6) ?
					sizeof(struct ipv6hdr) : sizeof(struct iphdr)) +
				       sizeof(struct tcphdr));
		*outer_l3_len = inner_l3_len + *encap_overhead;
		return 0;
	}
#endif

	if (inner_proto == bpf_htons(ETH_P_IP)) {
#ifdef ENABLE_IPV4
		void *data, *data_end;
		struct iphdr *ip4;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		inner_l3_len = bpf_ntohs(ip4->tot_len);
#else
		return DROP_INVALID;
#endif
	} else if (inner_proto == bpf_htons(ETH_P_IPV6)) {
#ifdef ENABLE_IPV6
		void *data, *data_end;
		struct ipv6hdr *ip6;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
		inner_l3_len = (__u16)(bpf_ntohs(ip6->payload_len) + sizeof(struct ipv6hdr));
#else
		return DROP_INVALID;
#endif
	} else {
		inner_l3_len = (__u16)(ctx_full_len(ctx) - ETH_HLEN);
	}

	*outer_l3_len = inner_l3_len + *encap_overhead;
	return 0;
}

/* Generate and send an RFC 1191 ICMPv4 Fragmentation Needed (Type 3, Code 4)
 * or RFC 8201 ICMPv6 Packet Too Big (Type 2, Code 0) reply with the reduced
 * tunnel Path MTU (underlay_mtu - encap_overhead) back to the sender.
 */
static __always_inline int
bpf_geneve_reply_icmp_too_big(struct __ctx_buff *ctx, __be16 inner_proto,
			      __u16 underlay_mtu, __u16 encap_overhead)
{
	__u16 inner_mtu;

	if (underlay_mtu <= encap_overhead)
		return send_drop_notify_error(ctx, 0, DROP_FRAG_NEEDED, METRIC_EGRESS);

	inner_mtu = underlay_mtu - encap_overhead;

	if (inner_proto == bpf_htons(ETH_P_IP)) {
#ifdef ENABLE_IPV4
		void *data, *data_end;
		struct iphdr *ip4;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return send_drop_notify_error(ctx, 0, DROP_INVALID, METRIC_EGRESS);

		/* RFC 1122 Section 3.2.2: Never send an ICMP error in response
		 * to another ICMP error message.
		 */
		if (ip4->protocol == IPPROTO_ICMP) {
			__u8 icmp_type = 0;

			if (icmp_load_type(ctx, ETH_HLEN + ipv4_hdrlen(ip4), &icmp_type) < 0 ||
			    (icmp_type != ICMP_ECHO && icmp_type != ICMP_ECHOREPLY))
				return send_drop_notify_error(ctx, 0, DROP_FRAG_NEEDED,
							      METRIC_EGRESS);
		}

		update_metrics(ctx_full_len(ctx), METRIC_EGRESS, (__u8)-DROP_FRAG_NEEDED);
		if (generate_icmp4_reply(ctx, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
					 bpf_htons(inner_mtu)))
			return send_drop_notify_error(ctx, 0, DROP_FRAG_NEEDED, METRIC_EGRESS);

		return redirect_self(ctx);
#endif
	} else if (inner_proto == bpf_htons(ETH_P_IPV6)) {
#ifdef ENABLE_IPV6
		void *data, *data_end;
		struct ipv6hdr *ip6;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return send_drop_notify_error(ctx, 0, DROP_INVALID, METRIC_EGRESS);

		/* RFC 4443 Section 2.4(e): Never send an ICMPv6 error in response
		 * to another ICMPv6 error message (types < 128).
		 */
		if (ip6->nexthdr == IPPROTO_ICMPV6) {
			__u8 icmp6_type = 0;

			if (ctx_load_bytes(ctx, ETH_HLEN + sizeof(struct ipv6hdr) +
					   offsetof(struct icmp6hdr, icmp6_type),
					   &icmp6_type, sizeof(icmp6_type)) < 0 ||
			    icmp6_type < 128)
				return send_drop_notify_error(ctx, 0, DROP_FRAG_NEEDED,
							      METRIC_EGRESS);
		}

		update_metrics(ctx_full_len(ctx), METRIC_EGRESS, (__u8)-DROP_FRAG_NEEDED);
		if (generate_icmp6_reply(ctx, ICMPV6_PKT_TOOBIG, 0,
					 bpf_htonl((__u32)inner_mtu)))
			return send_drop_notify_error(ctx, 0, DROP_FRAG_NEEDED, METRIC_EGRESS);

		return redirect_self(ctx);
#endif
	}

	return send_drop_notify_error(ctx, 0, DROP_FRAG_NEEDED, METRIC_EGRESS);
}

__declare_tail(CILIUM_CALL_GENEVE_ENCAP4)
int tail_geneve_encap4(struct __ctx_buff *ctx)
{
	struct bpf_fib_lookup_padded fib_params = {};
	struct geneve_route_entry *cached;
	__be16 inner_proto = bpf_htons(ETH_P_IP);
	__u16 outer_l3_len = 0, encap_overhead = 0;
	const void *opt = NULL;
	__u32 opt_len = 0;
	__s8 ext_err = 0;
	__be32 saddr = 0;
	__be32 daddr = 0;
	__u32 vni = 0;
	int ret, fib_result, oif;

	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);

	if (meta && meta->magic == BPF_GENEVE_META_MAGIC) {
		vni = meta->vni;
		daddr = meta->ip4.daddr;
		if (meta->opt_len > 0 && meta->opt_len <= BPF_GENEVE_OPT_MAX_LEN) {
			opt = meta->raw_opts;
			opt_len = meta->opt_len;
		}
		meta->magic = 0;
		meta->opt_len = 0;
	} else {
		struct bpf_tunnel_key key = {};

		ret = ctx_get_tunnel_key(ctx, &key, sizeof(key), 0);
		if (ret < 0)
			return send_drop_notify_error(ctx, 0, DROP_NO_TUNNEL_KEY, METRIC_EGRESS);

		daddr = bpf_htonl(key.remote_ipv4 ? key.remote_ipv4 : key.local_ipv4);
		vni = key.tunnel_id;
#ifdef BPF_TEST
		if (meta) {
			int opt_ret = skb_get_tunnel_opt(ctx, meta->raw_opts,
							 BPF_GENEVE_OPT_MAX_LEN);
			if (opt_ret > 0 && (__u32)opt_ret <= BPF_GENEVE_OPT_MAX_LEN) {
				opt = meta->raw_opts;
				opt_len = (__u32)opt_ret;
			}
		}
#endif
	}

	if (!validate_ethertype(ctx, &inner_proto))
		return send_drop_notify_error(ctx, 0, DROP_INVALID, METRIC_EGRESS);

	ret = bpf_geneve_check_mtu(ctx, inner_proto, false, opt_len,
				   &outer_l3_len, &encap_overhead);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, METRIC_EGRESS);

	if (CONFIG(device_mtu) > 0 && outer_l3_len > CONFIG(device_mtu))
		return bpf_geneve_reply_icmp_too_big(ctx, inner_proto,
						     CONFIG(device_mtu), encap_overhead);

	ret = bpf_geneve_rev_dnat_fwd(ctx, &inner_proto);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, METRIC_EGRESS);

	cached = map_lookup_elem(&cilium_geneve_routes, &daddr);
	if (cached &&
	    (cached->ts == 0 ||
	     (ktime_get_ns() - cached->ts) < BPF_GENEVE_ROUTE_CACHE_TTL_NS)) {
		struct geneve_route_entry r;
		void *data, *data_end;
		struct ethhdr *eth;

		r.saddr = cached->saddr;
		r.ifindex = cached->ifindex;
		copy_mac_safe(r.dmac, cached->dmac);
		copy_mac_safe(r.smac, cached->smac);

		ret = bpf_geneve_encap4(ctx, r.saddr, daddr, vni,
					inner_proto, opt, opt_len);
		if (ret < 0)
			return send_drop_notify_error(ctx, 0, ret, METRIC_EGRESS);

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		eth = data;
		if ((void *)(eth + 1) > data_end)
			return DROP_INVALID;

		copy_mac_safe(eth->h_dest, r.dmac);
		copy_mac_safe(eth->h_source, r.smac);

		return ctx_redirect(ctx, r.ifindex, 0);
	}

	fib_params.l.family = AF_INET;
	fib_params.l.ifindex = ctx_get_ifindex(ctx);
	fib_params.l.ipv4_src = 0;
	fib_params.l.ipv4_dst = daddr;
	fib_params.l.tot_len = outer_l3_len;

	fib_result = (int)fib_lookup(ctx, &fib_params.l, sizeof(fib_params.l), 0);
	if (fib_result != BPF_FIB_LKUP_RET_SUCCESS &&
	    fib_result != BPF_FIB_LKUP_RET_NO_NEIGH &&
	    fib_result != BPF_FIB_LKUP_RET_FRAG_NEEDED) {
		fib_params.l.tot_len = outer_l3_len;
		fib_result = fib_lookup_v4(ctx, &fib_params, 0, daddr, 0);
	}
	if (fib_result == BPF_FIB_LKUP_RET_FRAG_NEEDED)
		return bpf_geneve_reply_icmp_too_big(ctx, inner_proto,
						     fib_params.l.mtu_result,
						     encap_overhead);
	switch (fib_result) {
	case BPF_FIB_LKUP_RET_SUCCESS:
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		saddr = fib_params.l.ipv4_src;
		break;
	default:
		saddr = CONFIG(ipv4_direct_routing).be32;
		break;
	}
	if (!saddr)
		saddr = CONFIG(ipv4_direct_routing).be32;

	ret = bpf_geneve_encap4(ctx, saddr, daddr, vni,
				inner_proto, opt, opt_len);
	if (ret < 0)
		return send_drop_notify_error(ctx, 0, ret, METRIC_EGRESS);

	if (fib_result == BPF_FIB_LKUP_RET_SUCCESS && !mac_is_zero_safe(fib_params.l.dmac)) {
		struct geneve_route_entry entry = {};

		copy_mac_safe(entry.dmac, fib_params.l.dmac);
		copy_mac_safe(entry.smac, fib_params.l.smac);
		if (mac_is_zero_safe(entry.smac)) {
			const union macaddr *dev_smac = device_mac(fib_params.l.ifindex);
			if (dev_smac)
				copy_mac_safe(entry.smac, dev_smac->addr);
		}
		entry.ifindex = fib_params.l.ifindex;
		entry.saddr = saddr;
		entry.ts = ktime_get_ns();
		if (!mac_is_zero_safe(entry.dmac) && !mac_is_zero_safe(entry.smac)) {
			void *data = ctx_data(ctx);
			void *data_end = ctx_data_end(ctx);
			struct ethhdr *eth = data;

			map_update_elem(&cilium_geneve_routes, &daddr, &entry, BPF_ANY);
			if ((void *)(eth + 1) <= data_end) {
				copy_mac_safe(eth->h_dest, entry.dmac);
				copy_mac_safe(eth->h_source, entry.smac);
				return ctx_redirect(ctx, entry.ifindex, 0);
			}
		}
	}

	oif = fib_params.l.ifindex;
	return fib_do_redirect(ctx, false, &fib_params, false, fib_result, oif, &ext_err);
}

#if defined(ENABLE_IPV6)
__declare_tail(CILIUM_CALL_GENEVE_ENCAP6)
int tail_geneve_encap6(struct __ctx_buff *ctx)
{
	struct bpf_fib_lookup_padded fib_params = {};
	struct geneve_route6_entry *cached;
	__be16 inner_proto = bpf_htons(ETH_P_IP);
	__u16 outer_l3_len = 0, encap_overhead = 0;
	union v6addr saddr = {};
	union v6addr daddr = {};
	const void *opt = NULL;
	__u32 opt_len = 0;
	__u32 vni = 0;
	__s8 ext_err = 0;
	int ret, fib_result, oif;

	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);

	if (meta && meta->magic == BPF_GENEVE_META_MAGIC) {
		vni = meta->vni;
		daddr = meta->ip6.daddr;
		if (meta->opt_len > 0 && meta->opt_len <= BPF_GENEVE_OPT_MAX_LEN) {
			opt = meta->raw_opts;
			opt_len = meta->opt_len;
		}
		meta->magic = 0;
		meta->opt_len = 0;
	} else {
		struct bpf_tunnel_key key = {};

		ret = ctx_get_tunnel_key(ctx, &key, sizeof(key), BPF_F_TUNINFO_IPV6);
		if (ret < 0)
			return send_drop_notify_error(ctx, 0, DROP_NO_TUNNEL_KEY, METRIC_EGRESS);

		daddr.p1 = key.remote_ipv6[0] ? key.remote_ipv6[0] : key.local_ipv6[0];
		daddr.p2 = key.remote_ipv6[1] ? key.remote_ipv6[1] : key.local_ipv6[1];
		daddr.p3 = key.remote_ipv6[2] ? key.remote_ipv6[2] : key.local_ipv6[2];
		daddr.p4 = key.remote_ipv6[3] ? key.remote_ipv6[3] : key.local_ipv6[3];
		vni = key.tunnel_id;
#ifdef BPF_TEST
		if (meta) {
			int opt_ret = skb_get_tunnel_opt(ctx, meta->raw_opts,
							 BPF_GENEVE_OPT_MAX_LEN);
			if (opt_ret > 0 && (__u32)opt_ret <= BPF_GENEVE_OPT_MAX_LEN) {
				opt = meta->raw_opts;
				opt_len = (__u32)opt_ret;
			}
		}
#endif
	}

	if (!validate_ethertype(ctx, &inner_proto))
		return send_drop_notify_error(ctx, 0, DROP_INVALID, METRIC_EGRESS);

	ret = bpf_geneve_check_mtu(ctx, inner_proto, true, opt_len,
				   &outer_l3_len, &encap_overhead);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, METRIC_EGRESS);

	if (CONFIG(device_mtu) > 0 && outer_l3_len > CONFIG(device_mtu))
		return bpf_geneve_reply_icmp_too_big(ctx, inner_proto,
						     CONFIG(device_mtu), encap_overhead);

	ret = bpf_geneve_rev_dnat_fwd(ctx, &inner_proto);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, METRIC_EGRESS);

	cached = map_lookup_elem(&cilium_geneve_routes6, &daddr);
	if (cached &&
	    (cached->ts == 0 ||
	     (ktime_get_ns() - cached->ts) < BPF_GENEVE_ROUTE_CACHE_TTL_NS)) {
		struct geneve_route6_entry r;
		void *data, *data_end;
		struct ethhdr *eth;

		r.saddr = cached->saddr;
		r.ifindex = cached->ifindex;
		copy_mac_safe(r.dmac, cached->dmac);
		copy_mac_safe(r.smac, cached->smac);

		ret = bpf_geneve_encap6(ctx, &r.saddr, &daddr, vni,
					inner_proto, opt, opt_len);
		if (ret < 0)
			return send_drop_notify_error(ctx, 0, ret, METRIC_EGRESS);

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		eth = data;
		if ((void *)(eth + 1) > data_end)
			return DROP_INVALID;

		copy_mac_safe(eth->h_dest, r.dmac);
		copy_mac_safe(eth->h_source, r.smac);

		return ctx_redirect(ctx, r.ifindex, 0);
	}

	fib_params.l.tot_len = outer_l3_len;
	fib_result = fib_lookup_v6(ctx, &fib_params, (const struct in6_addr *)&saddr,
				   (const struct in6_addr *)&daddr, 0);
	if (fib_result == BPF_FIB_LKUP_RET_FRAG_NEEDED)
		return bpf_geneve_reply_icmp_too_big(ctx, inner_proto,
						     fib_params.l.mtu_result,
						     encap_overhead);
	switch (fib_result) {
	case BPF_FIB_LKUP_RET_SUCCESS:
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		ipv6_addr_copy(&saddr, (union v6addr *)&fib_params.l.ipv6_src);
		break;
	default:
		saddr = CONFIG(ipv6_direct_routing);
		break;
	}
	if (!saddr.p1 && !saddr.p2 && !saddr.p3 && !saddr.p4)
		saddr = CONFIG(ipv6_direct_routing);

	ret = bpf_geneve_encap6(ctx, &saddr, &daddr, vni,
				inner_proto, opt, opt_len);
	if (ret < 0)
		return send_drop_notify_error(ctx, 0, ret, METRIC_EGRESS);

	if (fib_result == BPF_FIB_LKUP_RET_SUCCESS && !mac_is_zero_safe(fib_params.l.dmac)) {
		struct geneve_route6_entry entry = {};

		copy_mac_safe(entry.dmac, fib_params.l.dmac);
		copy_mac_safe(entry.smac, fib_params.l.smac);
		if (mac_is_zero_safe(entry.smac)) {
			const union macaddr *dev_smac = device_mac(fib_params.l.ifindex);
			if (dev_smac)
				copy_mac_safe(entry.smac, dev_smac->addr);
		}
		entry.ifindex = fib_params.l.ifindex;
		entry.saddr = saddr;
		entry.ts = ktime_get_ns();
		if (!mac_is_zero_safe(entry.dmac) && !mac_is_zero_safe(entry.smac)) {
			void *data = ctx_data(ctx);
			void *data_end = ctx_data_end(ctx);
			struct ethhdr *eth = data;

			map_update_elem(&cilium_geneve_routes6, &daddr, &entry, BPF_ANY);
			if ((void *)(eth + 1) <= data_end) {
				copy_mac_safe(eth->h_dest, entry.dmac);
				copy_mac_safe(eth->h_source, entry.smac);
				return ctx_redirect(ctx, entry.ifindex, 0);
			}
		}
	}

	oif = fib_params.l.ifindex;
	return fib_do_redirect(ctx, false, &fib_params, false, fib_result, oif, &ext_err);
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_BPF_GENEVE
/* Global pinned ProgArray map created by Cilium's overlay loader
 * (/sys/fs/bpf/tc/globals/cilium_calls_bpf_overlay). Allows bpf_host (on eth0)
 * to jump directly into bpf_overlay's tail_handle_ipv4 / tail_handle_ipv6
 * after BPF Geneve decapsulation in ~15 ns without traversing virtual netdevs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, CILIUM_CALL_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__array(values, int ());
} cilium_calls_bpf_overlay __section_maps_btf;
#endif /* ENABLE_BPF_GENEVE */

#if __ctx_is == __ctx_skb
static __always_inline int
bpf_geneve_get_tunnel_opt(struct __ctx_buff *ctx, void *opt, __u32 size)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_INGRESS);

	if (meta && meta->magic == BPF_GENEVE_META_MAGIC && meta->opt_len > 0) {
		if (size > meta->opt_len || size > BPF_GENEVE_OPT_MAX_LEN)
			return -EINVAL;
		__bpf_memcpy_builtin(opt, meta->raw_opts, size);
		return meta->opt_len;
	}
	return skb_get_tunnel_opt(ctx, opt, size);
}

#undef ctx_get_tunnel_opt
#define ctx_get_tunnel_opt bpf_geneve_get_tunnel_opt
#endif

static __always_inline int
bpf_geneve_dispatch_to_overlay(struct __ctx_buff *ctx, __u32 tunnel_id)
{
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	struct ethhdr *eth;
	__u32 src_sec_identity;
	__be16 proto;
	__s8 ext_err = 0;
	int ret;

	if (data + ETH_HLEN > data_end)
		return send_drop_notify_error(ctx, UNKNOWN_ID, DROP_INVALID, METRIC_INGRESS);

	eth = data;
	proto = eth->h_proto;
	src_sec_identity = get_id_from_tunnel_id(tunnel_id, proto);

	if (src_sec_identity == HOST_ID)
		return send_drop_notify_error(ctx, src_sec_identity, DROP_INVALID_IDENTITY, METRIC_INGRESS);

	ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
	set_identity_mark(ctx, src_sec_identity, MARK_MAGIC_OVERLAY);

	send_trace_notify(ctx, TRACE_FROM_OVERLAY, src_sec_identity, UNKNOWN_ID,
			  TRACE_EP_ID_UNKNOWN, ctx->ingress_ifindex,
			  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN, proto);

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		tail_call_static(ctx, cilium_calls_bpf_overlay, CILIUM_CALL_IPV4_FROM_OVERLAY);
		ext_err = (__s8)CILIUM_CALL_IPV4_FROM_OVERLAY;
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		tail_call_static(ctx, cilium_calls_bpf_overlay, CILIUM_CALL_IPV6_FROM_OVERLAY);
		ext_err = (__s8)CILIUM_CALL_IPV6_FROM_OVERLAY;
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

	return send_drop_notify_error_with_exitcode_ext(ctx, src_sec_identity, ret, ext_err,
							CTX_ACT_OK, METRIC_INGRESS);
}

__declare_tail(CILIUM_CALL_GENEVE_DECAP4)
int tail_geneve_decap4(struct __ctx_buff *ctx)
{
	struct bpf_tunnel_key key = {};
	int ret = bpf_geneve_decap4(ctx, &key);

	if (ret < 0)
		return send_drop_notify_error(ctx, UNKNOWN_ID, ret, METRIC_INGRESS);
	return bpf_geneve_dispatch_to_overlay(ctx, key.tunnel_id);
}

#if defined(ENABLE_IPV6)
__declare_tail(CILIUM_CALL_GENEVE_DECAP6)
int tail_geneve_decap6(struct __ctx_buff *ctx)
{
	struct bpf_tunnel_key key = {};
	int ret = bpf_geneve_decap6(ctx, &key);

	if (ret < 0)
		return send_drop_notify_error(ctx, UNKNOWN_ID, ret, METRIC_INGRESS);
	return bpf_geneve_dispatch_to_overlay(ctx, key.tunnel_id);
}
#endif /* ENABLE_IPV6 */

#endif /* ENABLE_BPF_GENEVE && !SKIP_GENEVE_HANDLING */

#endif /* __ctx_is == __ctx_skb */
