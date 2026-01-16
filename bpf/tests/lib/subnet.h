/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

static __always_inline void
subnet_map_add_entry(struct subnet_key *key, __u32 identity)
{
    struct subnet_value value = {};

    value.identity = identity;
    map_update_elem(&cilium_subnet_map, key, &value, BPF_ANY);
}

static __always_inline void
__subnet_v4_add_entry(__be32 addr, __u32 identity, __u32 mask_size)
{
	struct subnet_key key = {
		.lpm_key.prefixlen = SUBNET_PREFIX_LEN(mask_size),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = addr,
	};

    subnet_map_add_entry(&key, identity);
}

static __always_inline void
subnet_v4_add_entry(__be32 addr, __u32 identity)
{
    __subnet_v4_add_entry(addr, identity, V4_SUBNET_KEY_LEN);
}

static __always_inline void
__subnet_v6_add_entry(const union v6addr *addr, __u32 identity, __u32 mask_size)
{
	struct subnet_key key __align_stack_8 = {
		.lpm_key.prefixlen = SUBNET_PREFIX_LEN(mask_size),
		.family = ENDPOINT_KEY_IPV6,
	};

    memcpy(&key.ip6, addr, sizeof(*addr));

    subnet_map_add_entry(&key, identity);
}

static __always_inline void
subnet_v6_add_entry(const union v6addr *addr, __u32 identity)
{
    __subnet_v6_add_entry(addr, identity, V6_SUBNET_KEY_LEN);
}
