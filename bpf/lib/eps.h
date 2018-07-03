/*
 *  Copyright (C) 2017-2018 Authors of Cilium
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
#ifndef __LIB_EPS_H_
#define __LIB_EPS_H_

#include <linux/ip.h>
#include <linux/ipv6.h>

#include "maps.h"

static __always_inline struct endpoint_info *
lookup_ip6_endpoint(struct ipv6hdr *ip6)
{
	struct endpoint_key key = {};

	key.ip6 = *((union v6addr *) &ip6->daddr);
	key.family = ENDPOINT_KEY_IPV6;

	return map_lookup_elem(&cilium_lxc, &key);
}

static __always_inline struct endpoint_info *
lookup_ip4_endpoint(struct iphdr *ip4)
{
	struct endpoint_key key = {};

	key.ip4 = ip4->daddr;
	key.family = ENDPOINT_KEY_IPV4;

	return map_lookup_elem(&cilium_lxc, &key);
}

#if (defined POLICY_EGRESS || defined POLICY_INGRESS) && defined LXC_ID
/* IPCACHE_STATIC_PREFIX gets sizeof non-IP, non-prefix part of ipcache_key */
#define IPCACHE_STATIC_PREFIX							\
	(8 * (sizeof(struct ipcache_key) - sizeof(struct bpf_lpm_trie_key)	\
	      - sizeof(union v6addr)))
#define IPCACHE_PREFIX_LEN(PREFIX) (IPCACHE_STATIC_PREFIX + PREFIX)

static __always_inline struct remote_endpoint_info *
ipcache_lookup6(struct bpf_elf_map *map, union v6addr *addr, __u32 prefix)
{
	struct ipcache_key key = {
		.lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
		.family = ENDPOINT_KEY_IPV6,
		.ip6 = *addr,
	};
	ipv6_addr_clear_suffix(&key.ip6, prefix);
	return map_lookup_elem(map, &key);
}

static __always_inline struct remote_endpoint_info *
ipcache_lookup4(struct bpf_elf_map *map, __be32 addr, __u32 prefix)
{
	struct ipcache_key key = {
		.lpm_key = { IPCACHE_PREFIX_LEN(prefix) },
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = addr,
	};
	key.ip4 &= GET_PREFIX(prefix);
	return map_lookup_elem(map, &key);
}

#ifndef HAVE_LPM_MAP_TYPE
/* Define a function with the following NAME which iterates through PREFIXES
 * (a list of integers ordered from high to low representing prefix length),
 * performing a lookup in MAP using LOOKUP_FN to find a provided IP of type
 * IPTYPE. */
#define LPM_LOOKUP_FN(NAME, IPTYPE, PREFIXES, MAP, LOOKUP_FN)		\
static __always_inline struct remote_endpoint_info *NAME(IPTYPE addr) \
{									\
	int prefixes[] = { PREFIXES };					\
	const int size = (sizeof(prefixes) / sizeof(prefixes[0]));	\
	struct remote_endpoint_info *info;				\
	int i;								\
									\
_Pragma("unroll")							\
	for (i = 0; i < size; i++) {					\
		info = LOOKUP_FN(&MAP, addr, prefixes[i]);		\
		if (info != NULL)					\
			return info;					\
	}								\
									\
	return NULL;							\
}
LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, union v6addr *, IPCACHE6_PREFIXES,
	      cilium_ipcache, ipcache_lookup6)
LPM_LOOKUP_FN(lookup_ip4_remote_endpoint, __be32, IPCACHE4_PREFIXES,
	      cilium_ipcache, ipcache_lookup4)
#undef LPM_LOOKUP_FN
#else /* HAVE_LPM_MAP_TYPE */
#define V6_CACHE_KEY_LEN IPCACHE_PREFIX_LEN(sizeof(union v6addr)*8)
#define lookup_ip6_remote_endpoint(addr) \
	ipcache_lookup6(&cilium_ipcache, addr, V6_CACHE_KEY_LEN)
#define V4_CACHE_KEY_LEN IPCACHE_PREFIX_LEN(sizeof(__u32)*8)
#define lookup_ip4_remote_endpoint(addr) \
	ipcache_lookup4(&cilium_ipcache, addr, V4_CACHE_KEY_LEN)
#endif /* HAVE_LPM_MAP_TYPE */

#endif /* POLICY_EGRESS */

#endif /* __LIB_EPS_H_ */
