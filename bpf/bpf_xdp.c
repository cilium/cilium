/*
 *  Copyright (C) 2017 Authors of Cilium
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
#define SKIP_CALLS_MAP

#include <node_config.h>
#include <netdev_config.h>
#include <filter_config.h>

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/xdp.h"
#include "lib/eps.h"
#include "lib/events.h"

#ifndef HAVE_LPM_MAP_TYPE
# undef CIDR4_LPM_PREFILTER
# undef CIDR6_LPM_PREFILTER
#endif

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

static __always_inline int check_v4_endpoint(struct xdp_md *xdp,
					     struct iphdr *ipv4_hdr)
{
	if (lookup_ip4_endpoint(ipv4_hdr))
		return XDP_PASS;

	return XDP_DROP;
}

static __always_inline int check_v4(struct xdp_md *xdp)
{
	void *data_end = xdp_data_end(xdp);
	void *data = xdp_data(xdp);
	struct iphdr *ipv4_hdr = data + sizeof(struct ethhdr);
	struct lpm_v4_key pfx __maybe_unused;

	if (xdp_no_room(ipv4_hdr + 1, data_end))
		return XDP_DROP;

#ifdef CIDR4_FILTER
	__builtin_memcpy(pfx.lpm.data, &ipv4_hdr->saddr, sizeof(pfx.addr));
	pfx.lpm.prefixlen = 32;

#ifdef CIDR4_LPM_PREFILTER
	if (map_lookup_elem(&CIDR4_LMAP_NAME, &pfx))
		return XDP_DROP;
	else
#endif /* CIDR4_LPM_PREFILTER */
		return map_lookup_elem(&CIDR4_HMAP_NAME, &pfx) ?
		       XDP_DROP : check_v4_endpoint(xdp, ipv4_hdr);
#else
	return check_v4_endpoint(xdp, ipv4_hdr);
#endif /* CIDR4_FILTER */
}

static __always_inline int check_v6_endpoint(struct xdp_md *xdp,
					     struct ipv6hdr *ipv6_hdr)
{
	if (lookup_ip6_endpoint(ipv6_hdr))
		return XDP_PASS;

	return XDP_DROP;
}

static __always_inline int check_v6(struct xdp_md *xdp)
{
	void *data_end = xdp_data_end(xdp);
	void *data = xdp_data(xdp);
	struct ipv6hdr *ipv6_hdr = data + sizeof(struct ethhdr);
	struct lpm_v6_key pfx __maybe_unused;

	if (xdp_no_room(ipv6_hdr + 1, data_end))
		return XDP_DROP;

#ifdef CIDR6_FILTER
	__builtin_memcpy(pfx.lpm.data, &ipv6_hdr->saddr, sizeof(pfx.addr));
	pfx.lpm.prefixlen = 128;

#ifdef CIDR6_LPM_PREFILTER
	if (map_lookup_elem(&CIDR6_LMAP_NAME, &pfx))
		return XDP_DROP;
	else
#endif /* CIDR6_LPM_PREFILTER */
		return map_lookup_elem(&CIDR6_HMAP_NAME, &pfx) ?
		       XDP_DROP : check_v6_endpoint(xdp, ipv6_hdr);
#else
	return check_v6_endpoint(xdp, ipv6_hdr);
#endif /* CIDR6_FILTER */
}

static __always_inline int check_filters(struct xdp_md *xdp)
{
	void *data_end = xdp_data_end(xdp);
	void *data = xdp_data(xdp);
	struct ethhdr *eth = data;
	__u16 proto;

	if (xdp_no_room(eth + 1, data_end))
		return XDP_DROP;

	proto = eth->h_proto;
	if (proto == bpf_htons(ETH_P_IP))
		return check_v4(xdp);
	else if (proto == bpf_htons(ETH_P_IPV6))
		return check_v6(xdp);
	else
		/* Pass the rest to stack, we might later do more
		 * fine-grained filtering here.
		 */
		return XDP_PASS;
}

__section("from-netdev")
int xdp_start(struct xdp_md *xdp)
{
	return check_filters(xdp);
}

BPF_LICENSE("GPL");
