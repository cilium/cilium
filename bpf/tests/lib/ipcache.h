/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

static __always_inline void
ipcache_add_entry(struct ipcache_key *key, __u32 sec_identity,
		  const union v6addr *tunnel_ep, __u8 spi, bool flag_skip_tunnel,
		  bool ipv6_underlay)
{
	struct remote_endpoint_info value = {};

	value.sec_identity = sec_identity;
	if (ipv6_underlay) {
		/* The tunnel endpoint is misaligned on the stack so we need to use the builtin. */
		__bpf_memcpy_builtin(&value.tunnel_endpoint.ip6, tunnel_ep, sizeof(*tunnel_ep));
		value.flag_ipv6_tunnel_ep = true;
	} else {
		value.tunnel_endpoint.ip4 = tunnel_ep->p1;
	}
	value.key = spi;
	value.flag_skip_tunnel = flag_skip_tunnel;
	if (tunnel_ep->p1)
		value.flag_has_tunnel_ep = true;

	map_update_elem(&cilium_ipcache_v2, key, &value, BPF_ANY);
}

static __always_inline void
__ipcache_v4_add_entry(__be32 addr, __u8 cluster_id, __u32 sec_identity,
		       const union v6addr *tunnel_ep, __u8 spi, bool flag_skip_tunnel,
		       bool ipv6_underlay, __u32 mask_size)
{
	struct ipcache_key key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(mask_size),
		.cluster_id = cluster_id,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = addr,
	};

	ipcache_add_entry(&key, sec_identity, tunnel_ep, spi,
			  flag_skip_tunnel, ipv6_underlay);
}

static __always_inline void
ipcache_v4_add_world_entry()
{
	union v6addr tunnel_ep = {0};

	__ipcache_v4_add_entry(v4_all, 0, WORLD_IPV4_ID, &tunnel_ep, 0, false, false, 0);
}

static __always_inline void
ipcache_v4_add_entry(__be32 addr, __u8 cluster_id, __u32 sec_identity,
		     __u32 tunnel_ep, __u8 spi)
{
	__ipcache_v4_add_entry(addr, cluster_id, sec_identity, (union v6addr *)&tunnel_ep, spi,
			       false, false, V4_CACHE_KEY_LEN);
}

static __always_inline void
ipcache_v4_add_entry_ipv6_underlay(__be32 addr, __u8 cluster_id, __u32 sec_identity,
				   const union v6addr *tunnel_ep, __u8 spi)
{
	__ipcache_v4_add_entry(addr, cluster_id, sec_identity, tunnel_ep, spi, false, true,
			       V4_CACHE_KEY_LEN);
}

static __always_inline void
ipcache_v4_add_entry_with_flags(__be32 addr, __u8 cluster_id, __u32 sec_identity,
				__u32 tunnel_ep, __u8 spi, bool flag_skip_tunnel)
{
	__ipcache_v4_add_entry(addr, cluster_id, sec_identity, (union v6addr *)&tunnel_ep, spi,
			       flag_skip_tunnel, false, V4_CACHE_KEY_LEN);
}

static __always_inline void
ipcache_v4_add_entry_with_mask_size(__be32 addr, __u8 cluster_id, __u32 sec_identity,
				    __u32 tunnel_ep, __u8 spi, __u32 mask_size)
{
	__ipcache_v4_add_entry(addr, cluster_id, sec_identity, (union v6addr *)&tunnel_ep, spi,
			       false, false, mask_size);
}

static __always_inline void
__ipcache_v6_add_entry(const union v6addr *addr, __u8 cluster_id, __u32 sec_identity,
		       const union v6addr *tunnel_ep, __u8 spi, bool flag_skip_tunnel,
		       bool ipv6_underlay, __u32 mask_size)
{
	struct ipcache_key key __align_stack_8 = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(mask_size),
		.cluster_id = cluster_id,
		.family = ENDPOINT_KEY_IPV6,
	};

	memcpy(&key.ip6, addr, sizeof(*addr));

	ipcache_add_entry(&key, sec_identity, tunnel_ep, spi,
			  flag_skip_tunnel, ipv6_underlay);
}

static __always_inline void
ipcache_v6_add_world_entry()
{
	union v6addr tunnel_ep = {0};

	__ipcache_v6_add_entry((union v6addr *)v6_all, 0, WORLD_IPV6_ID,
			       &tunnel_ep, 0, false, false, 0);
}

static __always_inline void
ipcache_v6_add_entry(const union v6addr *addr, __u8 cluster_id, __u32 sec_identity,
		     __u32 tunnel_ep, __u8 spi)
{
	__ipcache_v6_add_entry(addr, cluster_id, sec_identity, (union v6addr *)&tunnel_ep, spi,
			       false, false, V6_CACHE_KEY_LEN);
}

static __always_inline void
ipcache_v6_add_entry_ipv6_underlay(const union v6addr *addr, __u8 cluster_id, __u32 sec_identity,
				   const union v6addr *tunnel_ep, __u8 spi)
{
	__ipcache_v6_add_entry(addr, cluster_id, sec_identity, tunnel_ep, spi, false, true,
			       V6_CACHE_KEY_LEN);
}

static __always_inline void
ipcache_v6_add_entry_with_flags(const union v6addr *addr, __u8 cluster_id, __u32 sec_identity,
				__u32 tunnel_ep, __u8 spi, bool flag_skip_tunnel)
{
	__ipcache_v6_add_entry(addr, cluster_id, sec_identity, (union v6addr *)&tunnel_ep, spi,
			       flag_skip_tunnel, false, V6_CACHE_KEY_LEN);
}
