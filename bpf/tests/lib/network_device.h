/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

static __always_inline void
device_add_entry(__u32 ifindex, const __u8 *mac, __u8 l3)
{
	struct device_key key = {
		.ifindex = ifindex,
	};
	struct device_value value = {
		.l3 = l3,
	};

	if (mac)
		memcpy(&value.mac, mac, ETH_ALEN);

	map_update_elem(&cilium_device_map, &key, &value, BPF_ANY);
}
