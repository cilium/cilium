/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_MAPS_H_
#define __LIB_MAPS_H_

#include "common.h"
#include "ipv6.h"
#include "ids.h"

#include "bpf/compiler.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct endpoint_key);
	__type(value, struct endpoint_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, ENDPOINTS_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} ENDPOINTS_MAP __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct metrics_key);
	__type(value, struct metrics_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, METRICS_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} METRICS_MAP __section_maps_btf;


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

#ifdef ENABLE_L7_LB
/* Global map to jump into policy enforcement of sending endpoint */
struct bpf_elf_map __section_maps POLICY_EGRESSCALL_MAP = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_EGRESSPOLICY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= POLICY_PROG_MAP_SIZE,
};
#endif

#ifdef ENABLE_BANDWIDTH_MANAGER
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct edt_id);
	__type(value, struct edt_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, THROTTLE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} THROTTLE_MAP __section_maps_btf;
#endif /* ENABLE_BANDWIDTH_MANAGER */

#ifdef POLICY_MAP
/* Per-endpoint policy enforcement map */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct policy_key);
	__type(value, struct policy_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} POLICY_MAP __section_maps_btf;
#endif

#ifdef AUTH_MAP
/* Global auth map for enforcing authentication policy */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct auth_key);
	__type(value, struct auth_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, AUTH_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} AUTH_MAP __section_maps_btf;
#endif

#ifdef CONFIG_MAP
/*
 * CONFIG_MAP is an array containing runtime configuration information to the
 * bpf datapath.  Each element in the array is a 64-bit integer, meaning of
 * which is defined by the source of that index.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CONFIG_MAP_SIZE);
} CONFIG_MAP __section_maps_btf;
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

#ifdef HAVE_ENCAP

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct tunnel_key);
	__type(value, struct tunnel_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, TUNNEL_ENDPOINT_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} TUNNEL_MAP __section_maps_btf;

#endif

#if defined(ENABLE_CUSTOM_CALLS) && defined(CUSTOM_CALLS_MAP)
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
	.max_elem	= 4,	/* ingress and egress, IPv4 and IPv6 */
};

#define CUSTOM_CALLS_IDX_IPV4_INGRESS	0
#define CUSTOM_CALLS_IDX_IPV4_EGRESS	1
#define CUSTOM_CALLS_IDX_IPV6_INGRESS	2
#define CUSTOM_CALLS_IDX_IPV6_EGRESS	3
#endif /* ENABLE_CUSTOM_CALLS && CUSTOM_CALLS_MAP */

struct ipcache_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16 pad1;
	__u8 cluster_id;
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
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct ipcache_key);
	__type(value, struct remote_endpoint_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, IPCACHE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} IPCACHE_MAP __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct encrypt_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} ENCRYPT_MAP __section_maps_btf;

struct node_key {
	__u16 pad1;
	__u8 pad2;
	__u8 family;
	union {
		struct {
			__u32 ip4;
			__u32 pad4;
			__u32 pad5;
			__u32 pad6;
		};
		union v6addr    ip6;
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct node_key);
	__type(value, __u16);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, NODE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} NODE_MAP __section_maps_btf;

#ifdef ENABLE_EGRESS_GATEWAY
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct egress_gw_policy_key);
	__type(value, struct egress_gw_policy_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} EGRESS_POLICY_MAP __section_maps_btf;

#endif /* ENABLE_EGRESS_GATEWAY */

#ifdef ENABLE_SRV6
# define SRV6_VRF_MAP(IP_FAMILY)				\
struct {						\
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);		\
	__type(key, struct srv6_vrf_key ## IP_FAMILY);	\
	__type(value, __u32);				\
	__uint(pinning, LIBBPF_PIN_BY_NAME);		\
	__uint(max_entries, SRV6_VRF_MAP_SIZE);		\
	__uint(map_flags, BPF_F_NO_PREALLOC);		\
} SRV6_VRF_MAP ## IP_FAMILY __section_maps_btf;

# define SRV6_POLICY_MAP(IP_FAMILY)				\
struct {							\
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);			\
	__type(key, struct srv6_policy_key ## IP_FAMILY);	\
	__type(value, union v6addr);				\
	__uint(pinning, LIBBPF_PIN_BY_NAME);			\
	__uint(max_entries, SRV6_POLICY_MAP_SIZE);		\
	__uint(map_flags, BPF_F_NO_PREALLOC);			\
} SRV6_POLICY_MAP ## IP_FAMILY __section_maps_btf;

# define SRV6_STATE_MAP(IP_FAMILY)							\
struct {										\
	__uint(type, BPF_MAP_TYPE_LRU_HASH);						\
	__type(key, struct srv6_ipv ## IP_FAMILY ## _2tuple); /* inner header */	\
	__type(value, struct srv6_ipv6_2tuple);               /* outer header */	\
	__uint(pinning, LIBBPF_PIN_BY_NAME);						\
	__uint(max_entries, SRV6_STATE_MAP_SIZE);					\
} SRV6_STATE_MAP ## IP_FAMILY __section_maps_btf;

# ifdef ENABLE_IPV4
SRV6_VRF_MAP(4)
SRV6_POLICY_MAP(4)
SRV6_STATE_MAP(4)
# endif /* ENABLE_IPV4 */

SRV6_VRF_MAP(6)
SRV6_POLICY_MAP(6)
SRV6_STATE_MAP(6)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, union v6addr); /* SID */
    __type(value, __u32);      /* VRF ID */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, SRV6_SID_MAP_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} SRV6_SID_MAP __section_maps_btf;
#endif /* ENABLE_SRV6 */

#ifdef ENABLE_VTEP
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct vtep_key);
	__type(value, struct vtep_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, VTEP_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} VTEP_MAP __section_maps_btf;
#endif /* ENABLE_VTEP */

#ifdef ENABLE_HIGH_SCALE_IPCACHE
struct world_cidrs_key4 {
	struct bpf_lpm_trie_key lpm_key;
	__u32 ip;
} __packed;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct world_cidrs_key4);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, WORLD_CIDRS4_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} WORLD_CIDRS4_MAP __section_maps_btf;
#endif /* ENABLE_HIGH_SCALE_IPCACHE */

#ifndef SKIP_CALLS_MAP
static __always_inline void ep_tail_call(struct __ctx_buff *ctx __maybe_unused,
					 const __u32 index __maybe_unused)
{
	tail_call_static(ctx, &CALLS_MAP, index);
}
#endif /* SKIP_CALLS_MAP */
#endif
