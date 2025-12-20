/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"

#include <linux/ip.h>
#include "ipv6.h"

#define ENDPOINT_KEY_IPV4 1
#define ENDPOINT_KEY_IPV6 2

/* Structure representing an IPv4 or IPv6 address, being used as the key
 * for the endpoints map.
 */
struct endpoint_key {
	union {
		struct {
			__u32		ip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	ip6;
	};
	__u8 family;
	__u8 key;
	__u16 cluster_id;
} __packed;

#define ENDPOINT_F_HOST			1 /* Special endpoint representing local host */
#define ENDPOINT_F_ATHOSTNS		2 /* Endpoint located at the host networking namespace */
#define ENDPOINT_F_NO_SNAT_V4	4 /* Endpoint should not be masqueraded for IPv4 */
#define ENDPOINT_F_NO_SNAT_V6	8 /* Endpoint should not be masqueraded for IPv6 */
#define ENDPOINT_MASK_HOST_DELIVERY	(ENDPOINT_F_HOST | ENDPOINT_F_ATHOSTNS)
#define ENDPOINT_MASK_SKIP_MASQ_V4 (ENDPOINT_F_HOST | ENDPOINT_F_NO_SNAT_V4)
#define ENDPOINT_MASK_SKIP_MASQ_V6 (ENDPOINT_F_HOST | ENDPOINT_F_NO_SNAT_V6)

/* Value of endpoint map */
struct endpoint_info {
	__u32		ifindex;
	__u16		unused; /* used to be sec_label, no longer used */
	__u16		lxc_id;
	__u32		flags;
	mac_t		mac;
	mac_t		node_mac;
	__u32		sec_id;
	__u32		parent_ifindex;
	__u32		pad[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct endpoint_key);
	__type(value, struct endpoint_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, ENDPOINTS_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} cilium_lxc __section_maps_btf;

static __always_inline __maybe_unused const struct endpoint_info *
__lookup_ip6_endpoint(const union v6addr *ip6)
{
	struct endpoint_key key = {};

	key.ip6 = *ip6;
	key.family = ENDPOINT_KEY_IPV6;

	return map_lookup_elem(&cilium_lxc, &key);
}

static __always_inline __maybe_unused const struct endpoint_info *
lookup_ip6_endpoint(const struct ipv6hdr *ip6)
{
	return __lookup_ip6_endpoint((union v6addr *)&ip6->daddr);
}

static __always_inline __maybe_unused const struct endpoint_info *
__lookup_ip4_endpoint(__u32 ip)
{
	struct endpoint_key key = {};

	key.ip4 = ip;
	key.family = ENDPOINT_KEY_IPV4;

	return map_lookup_elem(&cilium_lxc, &key);
}

static __always_inline __maybe_unused const struct endpoint_info *
lookup_ip4_endpoint(const struct iphdr *ip4)
{
	return __lookup_ip4_endpoint(ip4->daddr);
}

struct remote_endpoint_info {
	__u32		sec_identity;
	union {
		struct {
			__u32	ip4;
			__u32	pad1;
			__u32	pad2;
			__u32	pad3;
		};
		union v6addr	ip6;
	} tunnel_endpoint;
	__u16		pad;
	__u8		key;
	__u8		flag_skip_tunnel:1,
			flag_has_tunnel_ep:1,
			flag_ipv6_tunnel_ep:1,
			flag_remote_cluster:1,
			pad2:4;
};

struct ipcache_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16 cluster_id;
	__u8 pad1;
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
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_ipcache_v2 __section_maps_btf;

/* IPCACHE_STATIC_PREFIX gets sizeof non-IP, non-prefix part of ipcache_key */
#define IPCACHE_STATIC_PREFIX							\
	(8 * (sizeof(struct ipcache_key) - sizeof(struct bpf_lpm_trie_key)	\
	      - sizeof(union v6addr)))
#define IPCACHE_PREFIX_LEN(PREFIX) (IPCACHE_STATIC_PREFIX + (PREFIX))

#define V6_CACHE_KEY_LEN (sizeof(union v6addr)*8)

static __always_inline __maybe_unused const struct remote_endpoint_info *
ipcache_lookup6(const void *map, const union v6addr *addr,
		__u32 prefix, __u32 cluster_id)
{
	struct ipcache_key key = {
		.lpm_key = { IPCACHE_PREFIX_LEN(prefix), {} },
		.family = ENDPOINT_KEY_IPV6,
		.ip6 = *addr,
	};

	/* Check overflow */
	if (cluster_id > UINT16_MAX)
		return NULL;

	key.cluster_id = (__u16)cluster_id;

	ipv6_addr_clear_suffix(&key.ip6, prefix);
	return map_lookup_elem(map, &key);
}

#define V4_CACHE_KEY_LEN (sizeof(__u32)*8)

static __always_inline __maybe_unused const struct remote_endpoint_info *
ipcache_lookup4(const void *map, __be32 addr, __u32 prefix, __u32 cluster_id)
{
	struct ipcache_key key = {
		.lpm_key = { IPCACHE_PREFIX_LEN(prefix), {} },
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = addr,
	};

	/* Check overflow */
	if (cluster_id > UINT16_MAX)
		return NULL;

	key.cluster_id = (__u16)cluster_id;

	key.ip4 &= GET_PREFIX(prefix);
	return map_lookup_elem(map, &key);
}

#define lookup_ip6_remote_endpoint(addr, cluster_id) \
	ipcache_lookup6(&cilium_ipcache_v2, addr, V6_CACHE_KEY_LEN, cluster_id)
#define lookup_ip4_remote_endpoint(addr, cluster_id) \
	ipcache_lookup4(&cilium_ipcache_v2, addr, V4_CACHE_KEY_LEN, cluster_id)
