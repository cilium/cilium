/*
 *  Copyright (C) 2016-2018 Authors of Cilium
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

struct bpf_elf_map __section_maps cilium_lxc = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct endpoint_key),
	.size_value	= sizeof(struct endpoint_info),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= ENDPOINTS_MAP_SIZE,
};

struct bpf_elf_map __section_maps cilium_metrics = {
	.type		= BPF_MAP_TYPE_PERCPU_HASH,
	.size_key	= sizeof(struct metrics_key),
	.size_value	= sizeof(struct metrics_value),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= METRICS_MAP_SIZE,
};

/* Global map to jump into policy enforcement of receiving endpoint */
struct bpf_elf_map __section_maps cilium_policy = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_POLICY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= POLICY_PROG_MAP_SIZE,
};

/* Per-endpoint policy enforcement map */
#ifdef POLICY_MAP
struct bpf_elf_map __section_maps POLICY_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct policy_key),
	.size_value	= sizeof(struct policy_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= POLICY_MAP_SIZE,
};
#endif

struct bpf_elf_map __section_maps cilium_proxy4 = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct proxy4_tbl_key),
	.size_value	= sizeof(struct proxy4_tbl_value),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= PROXY_MAP_SIZE,
};

struct bpf_elf_map __section_maps cilium_proxy6= {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct proxy6_tbl_key),
	.size_value	= sizeof(struct proxy6_tbl_value),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= PROXY_MAP_SIZE,
};

#ifndef SKIP_CALLS_MAP
/* Private per EP map for internal tail calls */
struct bpf_elf_map __section_maps CALLS_MAP = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_CALLS,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_CALL_SIZE,
};
#endif /* SKIP_CALLS_MAP */

#ifdef ENCAP_IFINDEX

struct bpf_elf_map __section_maps cilium_tunnel_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct endpoint_key),
	.size_value	= sizeof(struct endpoint_key),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= TUNNEL_ENDPOINT_MAP_SIZE,
};

#endif

#ifdef HAVE_LPM_MAP_TYPE
#define LPM_MAP_TYPE BPF_MAP_TYPE_LPM_TRIE
#else
#define LPM_MAP_TYPE BPF_MAP_TYPE_HASH
#endif

#if defined POLICY_INGRESS || defined POLICY_EGRESS

#ifndef HAVE_LPM_MAP_TYPE
/* Define a function with the following NAME which iterates through PREFIXES
 * (a list of integers ordered from high to low representing prefix length),
 * performing a lookup in MAP using LOOKUP_FN to find a provided IP of type
 * IPTYPE. */
#define LPM_LOOKUP_FN(NAME, IPTYPE, PREFIXES, MAP, LOOKUP_FN)		\
static __always_inline int __##NAME(IPTYPE addr)			\
{									\
	int prefixes[] = { PREFIXES };					\
	const int size = (sizeof(prefixes) / sizeof(prefixes[0]));	\
	int i;								\
									\
_Pragma("unroll")							\
	for (i = 0; i < size; i++)					\
		if (LOOKUP_FN(&MAP, addr, prefixes[i]))			\
			return 1;					\
									\
	return 0;							\
}
#endif /* HAVE_LPM_MAP_TYPE */

#endif /* POLICY_INGRESS || POLICY_EGRESS */

#if defined(POLICY_INGRESS) || defined(POLICY_EGRESS)
#ifndef SKIP_UNDEF_LPM_LOOKUP_FN
#undef LPM_LOOKUP_FN
#endif
#endif /* POLICY_INGRESS || POLICY_EGRESS */

struct ipcache_key {
	struct bpf_lpm_trie_key lpm_key;
	__u8 pad[3];
	__u8 family;
	union {
		struct {
			__u32		ip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	ip6;
	};
} __attribute__((packed));

/* Global IP -> Identity map for applying egress label-based policy */
struct bpf_elf_map __section_maps cilium_ipcache = {
	.type		= LPM_MAP_TYPE,
	.size_key	= sizeof(struct ipcache_key),
	.size_value	= sizeof(struct remote_endpoint_info),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= IPCACHE_MAP_SIZE,
	.flags		= BPF_F_NO_PREALLOC,
};

#ifndef SKIP_CALLS_MAP
static __always_inline void ep_tail_call(struct __sk_buff *skb, uint32_t index)
{
	tail_call(skb, &CALLS_MAP, index);
}
#endif /* SKIP_CALLS_MAP */
#endif
