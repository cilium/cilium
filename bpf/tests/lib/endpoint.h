/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

static __always_inline void
endpoint_v4_add_entry(__be32 addr, __u32 ifindex, __u16 lxc_id, __u32 flags, __u32 sec_id,
		      const __u8 *ep_mac_addr, const __u8 *node_mac_addr)
{
	struct endpoint_key key = {
		.ip4 = addr,
		.family = ENDPOINT_KEY_IPV4,
	};
	struct endpoint_info value = {
		.ifindex = ifindex,
		.lxc_id = lxc_id,
		.flags = flags,
		.sec_id = sec_id,
	};

	if (ep_mac_addr)
		memcpy(&value.mac, ep_mac_addr, ETH_ALEN);
	if (node_mac_addr)
		memcpy(&value.node_mac, node_mac_addr, ETH_ALEN);

	map_update_elem(&ENDPOINTS_MAP, &key, &value, BPF_ANY);
}

static __always_inline void
endpoint_v4_del_entry(__be32 addr)
{
	struct endpoint_key key = {
		.ip4 = addr,
		.family = ENDPOINT_KEY_IPV4,
	};

	map_delete_elem(&ENDPOINTS_MAP, &key);
}

static __always_inline void
endpoint_v6_add_entry(const union v6addr *addr, __u32 ifindex, __u16 lxc_id,
		      __u32 flags, __u32 sec_id,
		      const __u8 *ep_mac_addr, const __u8 *node_mac_addr)
{
	struct endpoint_key key = {
		.family = ENDPOINT_KEY_IPV6,
	};

	struct endpoint_info value = {
		.ifindex = ifindex,
		.lxc_id = lxc_id,
		.flags = flags,
		.sec_id = sec_id,
	};

	memcpy(&key.ip6, addr, sizeof(*addr));

	if (ep_mac_addr)
		memcpy(&value.mac, ep_mac_addr, ETH_ALEN);
	if (node_mac_addr)
		memcpy(&value.node_mac, node_mac_addr, ETH_ALEN);

	map_update_elem(&ENDPOINTS_MAP, &key, &value, BPF_ANY);
}
