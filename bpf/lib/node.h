/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <bpf/section.h>
#include <bpf/loader.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct node_key);
	__type(value, struct node_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, NODE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_node_map_v2 __section_maps_btf;

static __always_inline struct node_value *
lookup_ip4_node(__be32 ip4)
{
	struct node_key key = {};

	key.family = ENDPOINT_KEY_IPV4;
	key.ip4 = ip4;

	return map_lookup_elem(&cilium_node_map_v2, &key);
}

static __always_inline __u16
lookup_ip4_node_id(__be32 ip4)
{
	struct node_value *node_value;

	node_value = lookup_ip4_node(ip4);
	if (!node_value)
		return 0;
	if (!node_value->id)
		return 0;
	return node_value->id;
}

# ifdef ENABLE_IPV6
static __always_inline struct node_value *
lookup_ip6_node(const union v6addr *ip6)
{
	struct node_key key = {};

	key.family = ENDPOINT_KEY_IPV6;
	key.ip6 = *ip6;

	return map_lookup_elem(&cilium_node_map_v2, &key);
}

static __always_inline __u16
lookup_ip6_node_id(const union v6addr *ip6)
{
	struct node_value *node_value;

	node_value = lookup_ip6_node(ip6);
	if (!node_value)
		return 0;
	if (!node_value->id)
		return 0;
	return node_value->id;
}
# endif /* ENABLE_IPV6 */

static __always_inline struct node_value *
lookup_node(const struct remote_endpoint_info *info)
{
# ifdef ENABLE_IPV6
	if (info->flag_ipv6_tunnel_ep)
		return lookup_ip6_node(&info->tunnel_endpoint.ip6);
# endif /* ENABLE_IPV6 */
	return lookup_ip4_node(info->tunnel_endpoint.ip4);
}
