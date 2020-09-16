/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2021 Authors of Cilium */

#ifndef __LIB_MAPS_H_
#define __LIB_MAPS_H_

#include "common.h"
#include "ipv6.h"
#include "ids.h"

#include "bpf/compiler.h"

struct bpf_elf_map __section_maps ENDPOINTS_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct endpoint_key),
	.size_value	= sizeof(struct endpoint_info),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= ENDPOINTS_MAP_SIZE,
	.flags		= CONDITIONAL_PREALLOC,
};

struct bpf_elf_map __section_maps METRICS_MAP = {
	.type		= BPF_MAP_TYPE_PERCPU_HASH,
	.size_key	= sizeof(struct metrics_key),
	.size_value	= sizeof(struct metrics_value),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= METRICS_MAP_SIZE,
	.flags		= CONDITIONAL_PREALLOC,
};

#ifndef SKIP_POLICY_MAP
/* Global map to jump into policy enforcement of receiving endpoint */
struct bpf_elf_map __section_maps POLICY_CALL_MAP = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_POLICY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= POLICY_PROG_MAP_SIZE,
};
#endif /* SKIP_POLICY_MAP */

#ifdef ENABLE_BANDWIDTH_MANAGER
struct bpf_elf_map __section_maps THROTTLE_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct edt_id),
	.size_value	= sizeof(struct edt_info),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= THROTTLE_MAP_SIZE,
	.flags		= BPF_F_NO_PREALLOC,
};
#endif /* ENABLE_BANDWIDTH_MANAGER */

/* Map to link endpoint id to per endpoint cilium_policy map */
#ifdef SOCKMAP
struct bpf_elf_map __section_maps EP_POLICY_MAP = {
	.type		= BPF_MAP_TYPE_HASH_OF_MAPS,
	.size_key	= sizeof(struct endpoint_key),
	.size_value	= sizeof(int),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= ENDPOINTS_MAP_SIZE,
};
#endif

#ifdef POLICY_MAP
/* Per-endpoint policy enforcement map */
struct bpf_elf_map __section_maps POLICY_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct policy_key),
	.size_value	= sizeof(struct policy_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= POLICY_MAP_SIZE,
	.flags		= CONDITIONAL_PREALLOC,
};
#endif

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

struct bpf_elf_map __section_maps TUNNEL_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct endpoint_key),
	.size_value	= sizeof(struct endpoint_key),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= TUNNEL_ENDPOINT_MAP_SIZE,
	.flags		= CONDITIONAL_PREALLOC,
};

#endif

#if defined(CUSTOM_CALLS_MAP)
/* Private per-EP map for tail calls to user-defined programs.
 * CUSTOM_CALLS_MAP is a per-EP map name, only defined for programs that need
 * to use the map, so we do not want to compile this definition if
 * CUSTOM_CALLS_MAP has not been #define-d.
 */
struct bpf_elf_map __section_maps CUSTOM_CALLS_MAP = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_CUSTOM_CALLS,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 2,	/* ingress and egress */
};

#define CUSTOM_CALLS_IDX_IPV4_INGRESS	0
#define CUSTOM_CALLS_IDX_IPV4_EGRESS	1
#endif /* ENABLE_CUSTOM_CALLS && CUSTOM_CALLS_MAP */

#ifdef HAVE_LPM_TRIE_MAP_TYPE
#define LPM_MAP_TYPE BPF_MAP_TYPE_LPM_TRIE
#else
#define LPM_MAP_TYPE BPF_MAP_TYPE_HASH
#endif

#ifndef HAVE_LPM_TRIE_MAP_TYPE
/* Define a function with the following NAME which iterates through PREFIXES
 * (a list of integers ordered from high to low representing prefix length),
 * performing a lookup in MAP using LOOKUP_FN to find a provided IP of type
 * IPTYPE.
 */
#define LPM_LOOKUP_FN(NAME, IPTYPE, PREFIXES, MAP, LOOKUP_FN)		\
static __always_inline int __##NAME(IPTYPE addr)			\
{									\
	int prefixes[] = { PREFIXES };					\
	const int size = ARRAY_SIZE(prefixes);				\
	int i;								\
									\
_Pragma("unroll")							\
	for (i = 0; i < size; i++)					\
		if (LOOKUP_FN(&MAP, addr, prefixes[i]))			\
			return 1;					\
									\
	return 0;							\
}
#endif /* HAVE_LPM_TRIE_MAP_TYPE */

#ifndef SKIP_UNDEF_LPM_LOOKUP_FN
#undef LPM_LOOKUP_FN
#endif

struct ipcache_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16 pad1;
	__u8 pad2;
	__u8 family;
	union {
		struct {
			__u32		ip4;
			__u32		pad4;
			__u32		pad5;
			__u32		pad6;
		};
		union v6addr	ip6;
	};
} __packed;

/* Global IP -> Identity map for applying egress label-based policy */
struct bpf_elf_map __section_maps IPCACHE_MAP = {
	.type		= LPM_MAP_TYPE,
	.size_key	= sizeof(struct ipcache_key),
	.size_value	= sizeof(struct remote_endpoint_info),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= IPCACHE_MAP_SIZE,
	.flags		= BPF_F_NO_PREALLOC,
};

struct bpf_elf_map __section_maps ENCRYPT_MAP = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(struct encrypt_key),
	.size_value	= sizeof(struct encrypt_config),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 1,
};

struct egress_key {
	struct bpf_lpm_trie_key lpm_key;
	__u32 sip;
	__u32 dip;
};

#ifdef ENABLE_EGRESS_GATEWAY
struct bpf_elf_map __section_maps EGRESS_MAP = {
	.type		= LPM_MAP_TYPE,
	.size_key	= sizeof(struct egress_key),
	.size_value	= sizeof(struct egress_info),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= EGRESS_MAP_SIZE,
	.flags		= BPF_F_NO_PREALLOC,
};
#endif /* ENABLE_EGRESS_GATEWAY */

#ifndef SKIP_CALLS_MAP
static __always_inline void ep_tail_call(struct __ctx_buff *ctx,
					 const __u32 index)
{
	tail_call_static(ctx, &CALLS_MAP, index);
}
#endif /* SKIP_CALLS_MAP */
#endif
