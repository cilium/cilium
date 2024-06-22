/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

static __always_inline void
node_v4_add_entry(__be32 node_ip, __u16 node_id, __u8 spi)
{
	struct node_key key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = node_ip,
	};
	struct node_value value = {
		.id = node_id,
		.spi = spi,
	};

	map_update_elem(&NODE_MAP_V2, &key, &value, BPF_ANY);
}
