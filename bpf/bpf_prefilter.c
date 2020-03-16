// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2017-2020 Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>
#include <filter_config.h>

#include <linux/if_ether.h>

#define SKIP_CALLS_MAP

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/eps.h"
#include "lib/events.h"

#ifndef HAVE_LPM_TRIE_MAP_TYPE
# undef CIDR4_LPM_PREFILTER
# undef CIDR6_LPM_PREFILTER
#endif

struct lpm_v4_key {
	struct bpf_lpm_trie_key lpm;
	__u8 addr[4];
};

struct lpm_v6_key {
	struct bpf_lpm_trie_key lpm;
	__u8 addr[16];
};

struct lpm_val {
	/* Just dummy for now. */
	__u8 flags;
};

#ifdef CIDR4_FILTER
struct bpf_elf_map __section_maps CIDR4_HMAP_NAME = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct lpm_v4_key),
	.size_value	= sizeof(struct lpm_val),
	.flags		= BPF_F_NO_PREALLOC,
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CIDR4_HMAP_ELEMS,
};

#ifdef CIDR4_LPM_PREFILTER
struct bpf_elf_map __section_maps CIDR4_LMAP_NAME = {
	.type		= BPF_MAP_TYPE_LPM_TRIE,
	.size_key	= sizeof(struct lpm_v4_key),
	.size_value	= sizeof(struct lpm_val),
	.flags		= BPF_F_NO_PREALLOC,
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CIDR4_LMAP_ELEMS,
};
#endif /* CIDR4_LPM_PREFILTER */
#endif /* CIDR4_FILTER */

#ifdef CIDR6_FILTER
struct bpf_elf_map __section_maps CIDR6_HMAP_NAME = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct lpm_v6_key),
	.size_value	= sizeof(struct lpm_val),
	.flags		= BPF_F_NO_PREALLOC,
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CIDR4_HMAP_ELEMS,
};

#ifdef CIDR6_LPM_PREFILTER
struct bpf_elf_map __section_maps CIDR6_LMAP_NAME = {
	.type		= BPF_MAP_TYPE_LPM_TRIE,
	.size_key	= sizeof(struct lpm_v6_key),
	.size_value	= sizeof(struct lpm_val),
	.flags		= BPF_F_NO_PREALLOC,
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CIDR4_LMAP_ELEMS,
};
#endif /* CIDR6_LPM_PREFILTER */
#endif /* CIDR6_FILTER */

static __always_inline int check_v4_endpoint(struct iphdr *ipv4_hdr)
{
	if (lookup_ip4_endpoint(ipv4_hdr))
		return CTX_ACT_OK;

	return CTX_ACT_DROP;
}

static __always_inline int check_v4(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct iphdr *ipv4_hdr = data + sizeof(struct ethhdr);
	struct lpm_v4_key pfx __maybe_unused;

	if (ctx_no_room(ipv4_hdr + 1, data_end))
		return CTX_ACT_DROP;

#ifdef CIDR4_FILTER
	__builtin_memcpy(pfx.lpm.data, &ipv4_hdr->saddr, sizeof(pfx.addr));
	pfx.lpm.prefixlen = 32;

#ifdef CIDR4_LPM_PREFILTER
	if (map_lookup_elem(&CIDR4_LMAP_NAME, &pfx))
		return CTX_ACT_DROP;
	else
#endif /* CIDR4_LPM_PREFILTER */
		return map_lookup_elem(&CIDR4_HMAP_NAME, &pfx) ?
		       CTX_ACT_DROP : check_v4_endpoint(ipv4_hdr);
#else
	return check_v4_endpoint(ipv4_hdr);
#endif /* CIDR4_FILTER */
}

static __always_inline int check_v6_endpoint(struct ipv6hdr *ipv6_hdr)
{
	if (lookup_ip6_endpoint(ipv6_hdr))
		return CTX_ACT_OK;

	return CTX_ACT_DROP;
}

static __always_inline int check_v6(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ipv6hdr *ipv6_hdr = data + sizeof(struct ethhdr);
	struct lpm_v6_key pfx __maybe_unused;

	if (ctx_no_room(ipv6_hdr + 1, data_end))
		return CTX_ACT_DROP;

#ifdef CIDR6_FILTER
	__builtin_memcpy(pfx.lpm.data, &ipv6_hdr->saddr, sizeof(pfx.addr));
	pfx.lpm.prefixlen = 128;

#ifdef CIDR6_LPM_PREFILTER
	if (map_lookup_elem(&CIDR6_LMAP_NAME, &pfx))
		return CTX_ACT_DROP;
	else
#endif /* CIDR6_LPM_PREFILTER */
		return map_lookup_elem(&CIDR6_HMAP_NAME, &pfx) ?
		       CTX_ACT_DROP : check_v6_endpoint(ipv6_hdr);
#else
	return check_v6_endpoint(ipv6_hdr);
#endif /* CIDR6_FILTER */
}

static __always_inline int check_filters(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ethhdr *eth = data;
	__u16 proto;

	if (ctx_no_room(eth + 1, data_end))
		return CTX_ACT_DROP;

	proto = eth->h_proto;
	if (proto == bpf_htons(ETH_P_IP))
		return check_v4(ctx);
	else if (proto == bpf_htons(ETH_P_IPV6))
		return check_v6(ctx);
	else
		/* Pass the rest to stack, we might later do more
		 * fine-grained filtering here.
		 */
		return CTX_ACT_OK;
}

__section("from-netdev")
int prefilter_start(struct __ctx_buff *ctx)
{
	return check_filters(ctx);
}

BPF_LICENSE("GPL");
