/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_NEIGH_H_
#define __LIB_NEIGH_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "common.h"
#include "eth.h"

#if defined(ENABLE_NODEPORT) && defined(ENABLE_IPV6)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, union v6addr);	/* ipv6 addr */
	__type(value, union macaddr);	/* hw addr */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, NODEPORT_NEIGH6_SIZE);
} NODEPORT_NEIGH6 __section_maps_btf;

static __always_inline int neigh_record_ip6(struct __ctx_buff *ctx)
{
	union macaddr smac = {}, *mac;
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;
	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		return DROP_INVALID;

	mac = map_lookup_elem(&NODEPORT_NEIGH6, &ip6->saddr);
	if (!mac || eth_addrcmp(mac, &smac)) {
		int ret = map_update_elem(&NODEPORT_NEIGH6, &ip6->saddr,
					  &smac, 0);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static __always_inline union macaddr *neigh_lookup_ip6(const union v6addr *addr)
{
	return map_lookup_elem(&NODEPORT_NEIGH6, addr);
}
#else
static __always_inline union macaddr *
neigh_lookup_ip6(const union v6addr *addr __maybe_unused)
{
	return NULL;
}
#endif /* ENABLE_NODEPORT && ENABLE_IPV6 */

#if defined(ENABLE_NODEPORT) && defined(ENABLE_IPV4)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __be32);		/* ipv4 addr */
	__type(value, union macaddr);	/* hw addr */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, NODEPORT_NEIGH4_SIZE);
} NODEPORT_NEIGH4 __section_maps_btf;

static __always_inline int neigh_record_ip4(struct __ctx_buff *ctx)
{
	union macaddr smac = {}, *mac;
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		return DROP_INVALID;

	mac = map_lookup_elem(&NODEPORT_NEIGH4, &ip4->saddr);
	if (!mac || eth_addrcmp(mac, &smac)) {
		int ret = map_update_elem(&NODEPORT_NEIGH4, &ip4->saddr,
					  &smac, 0);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static __always_inline union macaddr *neigh_lookup_ip4(const __be32 *addr)
{
	return map_lookup_elem(&NODEPORT_NEIGH4, addr);
}
#else
static __always_inline union macaddr *
neigh_lookup_ip4(const __be32 *addr __maybe_unused)
{
	return NULL;
}
#endif /* ENABLE_NODEPORT && ENABLE_IPV4 */
#endif /* __LIB_NEIGH_H_ */
