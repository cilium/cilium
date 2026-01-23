/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"

#include <linux/ip.h>
#include "ipv6.h"

DECLARE_CONFIG(bool, hybrid_routing_enabled, "Enable hybrid mode routing based on subnet IDs")

#define SUBNET_MAP_SIZE 1024

struct subnet_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16 pad0;
	__u8 pad1;
	__u8 family;
	union {
		struct {
			__u32		ip4;
			__u32		pad2;
			__u32		pad3;
			__u32		pad4;
		};
		union v6addr	ip6;
	};
} __packed;

struct subnet_value {
    __u32 identity;
};

/* CIDR -> Subnet Identity map */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct subnet_key);
	__type(value, struct subnet_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SUBNET_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_subnet_map __section_maps_btf;

/* SUBNET_STATIC_PREFIX gets sizeof non-IP, non-prefix part of subnet_key */
#define SUBNET_STATIC_PREFIX							\
	(8 * (sizeof(struct subnet_key) - sizeof(struct bpf_lpm_trie_key)	\
	      - sizeof(union v6addr)))
#define SUBNET_PREFIX_LEN(PREFIX) (SUBNET_STATIC_PREFIX + (PREFIX))

#define V6_SUBNET_KEY_LEN (sizeof(union v6addr) * 8)

static __always_inline __maybe_unused __u32
subnet_lookup(const void *map, const struct subnet_key *key)
{
	const struct subnet_value *value;

	value = map_lookup_elem(map, key);
	if (!value)
		return 0;

	return value->identity;
}

static __always_inline __maybe_unused __u32
subnet_lookup6(const void *map, const union v6addr *addr)
{
	__u32 prefix = V6_SUBNET_KEY_LEN;
	struct subnet_key key = {
		.lpm_key = { SUBNET_PREFIX_LEN(prefix), {} },
		.family = ENDPOINT_KEY_IPV6,
		.ip6 = *addr,
	};

	/* Normalize the key before lookup.
	 * Clear the lower bits of the IPv6 address according to the prefix length.
	 * Note: Given that prefix length is always 128 here, this operation is effectively a no-op.
	 * However, it is included for completeness and future-proofing.
	 */
	ipv6_addr_clear_suffix(&key.ip6, prefix);

	return subnet_lookup(map, &key);
}

#define V4_SUBNET_KEY_LEN (sizeof(__u32) * 8)

static __always_inline __maybe_unused __u32
subnet_lookup4(const void *map, __be32 addr)
{
	__u32 prefix = V4_SUBNET_KEY_LEN;
	struct subnet_key key = {
		.lpm_key = { SUBNET_PREFIX_LEN(prefix), {} },
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = addr,
	};

	/* Normalize the key before lookup.
	 * Clear the lower bits of the IPv4 address according to the prefix length.
	 */
	key.ip4 &= GET_PREFIX(prefix);

	return subnet_lookup(map, &key);
}

#define lookup_ip6_subnet_id(addr) \
	subnet_lookup6(&cilium_subnet_map, addr)
#define lookup_ip4_subnet_id(addr) \
	subnet_lookup4(&cilium_subnet_map, addr)
