/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

static __always_inline void
ipcache_v4_add_entry(__be32 addr, __u8 cluster_id, __u32 sec_identity,
		     __u32 tunnel_ep, __u8 spi)
{
	struct ipcache_key key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(V4_CACHE_KEY_LEN),
		.cluster_id = cluster_id,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = addr,
	};
	struct remote_endpoint_info value = {};

	value.sec_identity = sec_identity;
	value.tunnel_endpoint = tunnel_ep;
	value.key = spi;

	map_update_elem(&IPCACHE_MAP, &key, &value, BPF_ANY);
}

static __always_inline void
ipcache_v6_add_entry(const union v6addr *addr, __u8 cluster_id, __u32 sec_identity,
		     __u32 tunnel_ep, __u8 spi)
{
	struct ipcache_key key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(V6_CACHE_KEY_LEN),
		.cluster_id = cluster_id,
		.family = ENDPOINT_KEY_IPV6,
	};
	struct remote_endpoint_info value = {};

	value.sec_identity = sec_identity;
	value.tunnel_endpoint = tunnel_ep;
	value.key = spi;

	memcpy(&key.ip6, addr, sizeof(*addr));

	map_update_elem(&IPCACHE_MAP, &key, &value, BPF_ANY);
}
