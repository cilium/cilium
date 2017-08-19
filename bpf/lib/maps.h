/*
 *  Copyright (C) 2016-2017 Authors of Cilium
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
#ifndef __LIB_MAPS_H_
#define __LIB_MAPS_H_

#include "common.h"
#include "ipv6.h"

#define CILIUM_MAP_POLICY	1
#define CILIUM_MAP_CALLS	2
#define CILIUM_MAP_RES_POLICY	3

struct bpf_elf_map __section_maps cilium_lxc = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct endpoint_key),
	.size_value	= sizeof(struct endpoint_info),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= ENDPOINTS_MAP_SIZE,
};

/* Global map to jump into policy enforcement of receiving endpoint */
struct bpf_elf_map __section_maps cilium_policy = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_POLICY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= POLICY_MAP_SIZE,
};

struct bpf_elf_map __section_maps cilium_reserved_policy = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_RES_POLICY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= RESERVED_POLICY_SIZE,
};

/* Private per EP map for internal tail calls */
struct bpf_elf_map __section_maps CALLS_MAP = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_CALLS,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_CALL_SIZE,
};

#ifdef ENCAP_IFINDEX

struct bpf_elf_map __section_maps tunnel_endpoint_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct endpoint_key),
	.size_value	= sizeof(struct endpoint_key),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= TUNNEL_ENDPOINT_MAP_SIZE,
};

#endif

#ifdef POLICY_ENFORCEMENT

#ifdef HAVE_LPM_MAP_TYPE

#ifndef LPM_MAP_SIZE
#define LPM_MAP_SIZE 1024
#endif

#ifndef LPM_MAP_VALUE_SIZE
#define LPM_MAP_VALUE_SIZE 1
#endif

struct bpf_lpm_trie_key6 {
	struct bpf_lpm_trie_key lpm_key;
	union v6addr lpm_addr;
};

static __always_inline int lpm6_map_lookup(struct bpf_elf_map *map, union v6addr *addr)
{
	struct bpf_lpm_trie_key6 key = { { 128 }, *addr };
	return map_lookup_elem(map, &key) != NULL;
}

#ifdef CIDR6_INGRESS_MAP
struct bpf_elf_map __section_maps CIDR6_INGRESS_MAP = {
	.type		= BPF_MAP_TYPE_LPM_TRIE,
	.size_key	= sizeof(struct bpf_lpm_trie_key6),
	.size_value	= LPM_MAP_VALUE_SIZE,
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= LPM_MAP_SIZE,
	.flags		= BPF_F_NO_PREALLOC,
};
#define lpm6_ingress_lookup(ADDR) lpm6_map_lookup(&CIDR6_INGRESS_MAP, ADDR)
#else
#define lpm6_ingress_lookup(ADDR) 0
#endif

#ifdef CIDR6_EGRESS_MAP
struct bpf_elf_map __section_maps CIDR6_EGRESS_MAP = {
	.type		= BPF_MAP_TYPE_LPM_TRIE,
	.size_key	= sizeof(struct bpf_lpm_trie_key6),
	.size_value	= LPM_MAP_VALUE_SIZE,
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= LPM_MAP_SIZE,
	.flags		= BPF_F_NO_PREALLOC,
};
#define lpm6_egress_lookup(ADDR) lpm6_map_lookup(&CIDR6_EGRESS_MAP, ADDR)
#else
#define lpm6_egress_lookup(ADDR) 0
#endif

struct bpf_lpm_trie_key4 {
	struct bpf_lpm_trie_key lpm_key;
	__be32 lpm_addr;
};

static __always_inline int lpm4_map_lookup(struct bpf_elf_map *map, __be32 addr)
{
	struct bpf_lpm_trie_key6 key = { { 32 }, addr };
	return map_lookup_elem(map, &key) != NULL;
}

#ifdef CIDR4_INGRESS_MAP
struct bpf_elf_map __section_maps CIDR4_INGRESS_MAP = {
	.type		= BPF_MAP_TYPE_LPM_TRIE,
	.size_key	= sizeof(struct bpf_lpm_trie_key4),
	.size_value	= LPM_MAP_VALUE_SIZE,
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= LPM_MAP_SIZE,
	.flags		= BPF_F_NO_PREALLOC,
};
#define lpm4_ingress_lookup(ADDR) lpm4_map_lookup(&CIDR4_INGRESS_MAP, ADDR)
#else
#define lpm4_ingress_lookup(ADDR) 0
#endif
#ifdef CIDR4_EGRESS_MAP
struct bpf_elf_map __section_maps CIDR4_EGRESS_MAP = {
	.type		= BPF_MAP_TYPE_LPM_TRIE,
	.size_key	= sizeof(struct bpf_lpm_trie_key4),
	.size_value	= LPM_MAP_VALUE_SIZE,
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= LPM_MAP_SIZE,
	.flags		= BPF_F_NO_PREALLOC,
};
#define lpm4_egress_lookup(ADDR) lpm4_map_lookup(&CIDR4_EGRESS_MAP, ADDR)
#else
#define lpm4_egress_lookup(ADDR) 0
#endif

#else /* HAVE_LPM_MAP_TYPE */
/* No LPM map, use an array instead. Since our policies are default
 * deny we can stop at the first match. */

struct cidr6_entry {
	union v6addr net, mask;
};

#ifdef CIDR6_INGRESS_MAPPINGS
static __always_inline int lpm6_ingress_lookup(union v6addr *addr)
{
	struct cidr6_entry map[] = { CIDR6_INGRESS_MAPPINGS };
	const int size = (sizeof(map) / sizeof(map[0]));
	int i;

#pragma unroll
	for (i = 0; i < size; i++)
		if (ipv6_addr_in_net(addr, &map[i].net, &map[i].mask))
			return 1;

	return 0;
}
#else
#define lpm6_ingress_lookup(ADDR) 0
#endif

#ifdef CIDR6_EGRESS_MAPPINGS
static __always_inline int lpm6_egress_lookup(union v6addr *addr)
{
	struct cidr6_entry map[] = { CIDR6_EGRESS_MAPPINGS };
	const int size = (sizeof(map) / sizeof(map[0]));
	int i;

#pragma unroll
	for (i = 0; i < size; i++)
		if (ipv6_addr_in_net(addr, &map[i].net, &map[i].mask))
			return 1;

	return 0;
}
#else
#define lpm6_egress_lookup(ADDR) 0
#endif

struct cidr4_entry {
	__be32 net, mask;
};

#ifdef CIDR4_INGRESS_MAPPINGS
static __always_inline int lpm4_ingress_lookup(__be32 addr)
{
	struct cidr4_entry map[] = { CIDR4_INGRESS_MAPPINGS };
	const int size = (sizeof(map) / sizeof(map[0]));
	int i;

#pragma unroll
	for (i = 0; i < size; i++)
		if ((addr & map[i].mask) == map[i].net)
			return 1;

	return 0;
}
#else
#define lpm4_ingress_lookup(ADDR) 0
#endif

#ifdef CIDR4_EGRESS_MAPPINGS
static __always_inline int lpm4_egress_lookup(__be32 addr)
{
	struct cidr4_entry map[] = { CIDR4_EGRESS_MAPPINGS };
	const int size = (sizeof(map) / sizeof(map[0]));
	int i;

#pragma unroll
	for (i = 0; i < size; i++) {
		if ((addr & map[i].mask) == map[i].net)
			return 1;
	}

	return 0;
}
#else
#define lpm4_egress_lookup(ADDR) 0
#endif

#endif  /* HAVE_LPM_MAP_TYPE */

#else /* POLICY_ENFORCEMENT */
#define lpm6_ingress_lookup(ADDR) 0
#define lpm6_egress_lookup(ADDR) 0
#define lpm4_ingress_lookup(ADDR) 0
#define lpm4_egress_lookup(ADDR) 0
#endif /* POLICY_ENFORCEMENT */

static __always_inline void ep_tail_call(struct __sk_buff *skb, uint32_t index)
{
	tail_call(skb, &CALLS_MAP, index);
}

#endif
