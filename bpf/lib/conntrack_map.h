/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "config.h"

#ifdef ENABLE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv6_ct_tuple);
	__type(value, struct ct_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CT_MAP_SIZE_TCP);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_ct6_global __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv6_ct_tuple);
	__type(value, struct ct_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CT_MAP_SIZE_ANY);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_ct_any6_global __section_maps_btf;

#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
/*
 * Per-cluster conntrack map
 *
 * When we have an overlapping IPs among cluster, we need to
 * identify the network endpoints using IP address + ClusterID.
 * We wanted to add cluster_id field to struct ip{v4,v6}_ct_tuple,
 * but there were no enough bit. Since we cannot change the type
 * of conntrack map, we decided to separate the conntrack instance
 * per cluster. So that we can distinguish the network endpoints
 * with the same IP but belong to the different clusters by the
 * conntrack instance we are using.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 256);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_LRU_HASH);
		__type(key, struct ipv6_ct_tuple);
		__type(value, struct ct_entry);
		__uint(max_entries, CT_MAP_SIZE_TCP);
		__uint(map_flags, LRU_MEM_FLAVOR);
	});
} cilium_per_cluster_ct_tcp6 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 256);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_LRU_HASH);
		__type(key, struct ipv6_ct_tuple);
		__type(value, struct ct_entry);
		__uint(max_entries, CT_MAP_SIZE_ANY);
		__uint(map_flags, LRU_MEM_FLAVOR);
	});
} cilium_per_cluster_ct_any6 __section_maps_btf;
#endif

static __always_inline void *
get_ct_map6(const struct ipv6_ct_tuple *tuple)
{
	if (tuple->nexthdr == IPPROTO_TCP)
		return &cilium_ct6_global;

	return &cilium_ct_any6_global;
}

static __always_inline void *
get_cluster_ct_map6(const struct ipv6_ct_tuple *tuple, __u32 cluster_id __maybe_unused)
{
#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
	if (cluster_id != 0 && cluster_id != CLUSTER_ID) {
		if (tuple->nexthdr == IPPROTO_TCP)
			return map_lookup_elem(&cilium_per_cluster_ct_tcp6, &cluster_id);

		return map_lookup_elem(&cilium_per_cluster_ct_any6, &cluster_id);
	}
#endif

	return get_ct_map6(tuple);
}

static __always_inline void *
get_cluster_ct_any_map6(__u32 cluster_id __maybe_unused)
{
#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
	if (cluster_id != 0 && cluster_id != CLUSTER_ID)
		return map_lookup_elem(&cilium_per_cluster_ct_any6, &cluster_id);
#endif
	return &cilium_ct_any6_global;
}
#endif

#ifdef ENABLE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ct_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CT_MAP_SIZE_TCP);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_ct4_global __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ct_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CT_MAP_SIZE_ANY);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_ct_any4_global __section_maps_btf;

#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
struct per_cluster_ct_map4_inner_map {
		__uint(type, BPF_MAP_TYPE_LRU_HASH);
		__type(key, struct ipv4_ct_tuple);
		__type(value, struct ct_entry);
		__uint(max_entries, CT_MAP_SIZE_TCP);
		__uint(map_flags, LRU_MEM_FLAVOR);
#ifndef BPF_TEST
};
#else
} per_cluster_ct_tcp4_1 __section_maps_btf,
  per_cluster_ct_tcp4_2 __section_maps_btf,
  per_cluster_ct_any4_1 __section_maps_btf,
  per_cluster_ct_any4_2 __section_maps_btf;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 256); /* Keep this sync with ClusterIDMax */
	__array(values, struct per_cluster_ct_map4_inner_map);
#ifndef BPF_TEST
} cilium_per_cluster_ct_tcp4 __section_maps_btf;
#else
} cilium_per_cluster_ct_tcp4 __section_maps_btf = {
	.values = {
		[1] = &per_cluster_ct_tcp4_1,
		[2] = &per_cluster_ct_tcp4_2,
	},
};
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 256); /* Keep this sync with ClusterIDMax */
	__array(values, struct per_cluster_ct_map4_inner_map);
#ifndef BPF_TEST
} cilium_per_cluster_ct_any4 __section_maps_btf;
#else
} cilium_per_cluster_ct_any4 __section_maps_btf = {
	.values = {
		[1] = &per_cluster_ct_any4_1,
		[2] = &per_cluster_ct_any4_2,
	},
};
#endif
#endif

static __always_inline void *
get_ct_map4(const struct ipv4_ct_tuple *tuple)
{
	if (tuple->nexthdr == IPPROTO_TCP)
		return &cilium_ct4_global;

	return &cilium_ct_any4_global;
}

static __always_inline void *
get_cluster_ct_map4(const struct ipv4_ct_tuple *tuple, __u32 cluster_id __maybe_unused)
{
#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
	if (cluster_id != 0 && cluster_id != CLUSTER_ID) {
		if (tuple->nexthdr == IPPROTO_TCP)
			return map_lookup_elem(&cilium_per_cluster_ct_tcp4, &cluster_id);

		return map_lookup_elem(&cilium_per_cluster_ct_any4, &cluster_id);
	}
#endif

	return get_ct_map4(tuple);
}

static __always_inline void *
get_cluster_ct_any_map4(__u32 cluster_id __maybe_unused)
{
#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
	if (cluster_id != 0 && cluster_id != CLUSTER_ID)
		return map_lookup_elem(&cilium_per_cluster_ct_any4, &cluster_id);
#endif
	return &cilium_ct_any4_global;
}
#endif
