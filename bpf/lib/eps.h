/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_EPS_H_
#define __LIB_EPS_H_

#include <linux/ip.h>
#include <linux/ipv6.h>

#include "maps.h"

static __always_inline __maybe_unused struct endpoint_info *
__lookup_ip6_endpoint(const union v6addr *ip6)
{
	struct endpoint_key key = {};

	key.ip6 = *ip6;
	key.family = ENDPOINT_KEY_IPV6;

	return map_lookup_elem(&ENDPOINTS_MAP, &key);
}

static __always_inline __maybe_unused struct endpoint_info *
lookup_ip6_endpoint(const struct ipv6hdr *ip6)
{
	return __lookup_ip6_endpoint((union v6addr *)&ip6->daddr);
}

static __always_inline __maybe_unused struct endpoint_info *
__lookup_ip4_endpoint(__u32 ip)
{
	struct endpoint_key key = {};

	key.ip4 = ip;
	key.family = ENDPOINT_KEY_IPV4;

	return map_lookup_elem(&ENDPOINTS_MAP, &key);
}

static __always_inline __maybe_unused struct endpoint_info *
lookup_ip4_endpoint(const struct iphdr *ip4)
{
	return __lookup_ip4_endpoint(ip4->daddr);
}

/* IPCACHE_STATIC_PREFIX gets sizeof non-IP, non-prefix part of ipcache_key */
#define IPCACHE_STATIC_PREFIX							\
	(8 * (sizeof(struct ipcache_key) - sizeof(struct bpf_lpm_trie_key)	\
	      - sizeof(union v6addr)))
#define IPCACHE_PREFIX_LEN(PREFIX) (IPCACHE_STATIC_PREFIX + (PREFIX))

#define V6_CACHE_KEY_LEN (sizeof(union v6addr)*8)

static __always_inline __maybe_unused struct remote_endpoint_info *
ipcache_lookup6(const void *map, const union v6addr *addr,
		__u32 prefix, __u32 cluster_id)
{
	struct ipcache_key key = {
		.lpm_key = { IPCACHE_PREFIX_LEN(prefix), {} },
		.family = ENDPOINT_KEY_IPV6,
		.ip6 = *addr,
	};

	/* Check overflow */
	if (cluster_id > UINT8_MAX)
		return NULL;

	key.cluster_id = (__u8)cluster_id;

	ipv6_addr_clear_suffix(&key.ip6, prefix);
	return map_lookup_elem(map, &key);
}

#define V4_CACHE_KEY_LEN (sizeof(__u32)*8)

static __always_inline __maybe_unused struct remote_endpoint_info *
ipcache_lookup4(const void *map, __be32 addr, __u32 prefix, __u32 cluster_id)
{
	struct ipcache_key key = {
		.lpm_key = { IPCACHE_PREFIX_LEN(prefix), {} },
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = addr,
	};

	/* Check overflow */
	if (cluster_id > UINT8_MAX)
		return NULL;

	key.cluster_id = (__u8)cluster_id;

	key.ip4 &= GET_PREFIX(prefix);
	return map_lookup_elem(map, &key);
}

#define lookup_ip6_remote_endpoint(addr, cluster_id) \
	ipcache_lookup6(&IPCACHE_MAP, addr, V6_CACHE_KEY_LEN, cluster_id)
#define lookup_ip4_remote_endpoint(addr, cluster_id) \
	ipcache_lookup4(&IPCACHE_MAP, addr, V4_CACHE_KEY_LEN, cluster_id)
#endif /* __LIB_EPS_H_ */
