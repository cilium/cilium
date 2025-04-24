/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

static __always_inline void
node_add_entry(struct node_key *key, __u16 node_id, __u8 spi)
{
	struct node_value value = {
		.id = node_id,
		.spi = spi,
	};

	map_update_elem(&cilium_node_map_v2, key, &value, BPF_ANY);
}

static __always_inline void
node_v4_add_entry(__be32 node_ip, __u16 node_id, __u8 spi)
{
	struct node_key key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = node_ip,
	};

	node_add_entry(&key, node_id, spi);
}

static __always_inline void
node_v6_add_entry(const union v6addr *node_ip, __u16 node_id, __u8 spi)
{
	struct node_key key = {
		.family = ENDPOINT_KEY_IPV6,
		.ip6 = *node_ip,
	};

	node_add_entry(&key, node_id, spi);
}
