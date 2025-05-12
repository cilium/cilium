/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/ip.h>

#include "dbg.h"
#include "l4.h"
#include "metrics.h"
#include "ipfrag.h"

#define IPV4_SADDR_OFF		offsetof(struct iphdr, saddr)
#define IPV4_DADDR_OFF		offsetof(struct iphdr, daddr)

struct ipv4_frag_id {
	__be32	daddr;
	__be32	saddr;
	__be16	id;		/* L4 datagram identifier */
	__u8	proto;
	__u8	pad;
} __packed;

struct ipv4_frag_l4ports {
	__be16	sport;
	__be16	dport;
} __packed;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_frag_id);
	__type(value, struct ipv4_frag_l4ports);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_ipv4_frag_datagrams __section_maps_btf;

static __always_inline int
ipv4_csum_update_by_value(struct __ctx_buff *ctx, int l3_off, __u64 old_val,
			  __u64 new_val, __u32 len)
{
	return l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check),
			       (__u32)old_val, (__u32)new_val, len);
}

static __always_inline int
ipv4_csum_update_by_diff(struct __ctx_buff *ctx, int l3_off, __u64 diff)
{
	return l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check),
			       0, (__u32)diff, 0);
}

static __always_inline int ipv4_load_daddr(struct __ctx_buff *ctx, int off,
					   __u32 *dst)
{
	return ctx_load_bytes(ctx, off + offsetof(struct iphdr, daddr), dst, 4);
}

static __always_inline int ipv4_dec_ttl(struct __ctx_buff *ctx, int off,
					struct iphdr *ip4)
{
	__u8 new_ttl, ttl = ip4->ttl;

	if (ttl <= 1)
		return DROP_TTL_EXCEEDED;

	new_ttl = ttl - 1;
	ip4->ttl = new_ttl;

	/* l3_csum_replace() takes at min 2 bytes, zero extended. */
	if (ipv4_csum_update_by_value(ctx, off, ttl, new_ttl, 2) < 0)
		return DROP_CSUM_L3;

	return 0;
}

static __always_inline int ipv4_hdrlen(const struct iphdr *ip4)
{
	return ip4->ihl * 4;
}

static __always_inline bool ipv4_is_in_subnet(__be32 addr,
					      __be32 subnet, int prefixlen)
{
	return (addr & bpf_htonl(~((1 << (32 - prefixlen)) - 1))) == subnet;
}

#ifdef ENABLE_IPV4_FRAGMENTS
static __always_inline int
ipv4_frag_get_l4ports(const struct ipv4_frag_id *frag_id,
		      struct ipv4_frag_l4ports *ports)
{
	struct ipv4_frag_l4ports *tmp;

	tmp = map_lookup_elem(&cilium_ipv4_frag_datagrams, frag_id);
	if (!tmp)
		return DROP_FRAG_NOT_FOUND;

	/* Do not make ports a pointer to map data, copy from map */
	memcpy(ports, tmp, sizeof(*ports));
	return 0;
}

static __always_inline int
ipv4_handle_fragmentation(struct __ctx_buff *ctx,
			  const struct iphdr *ip4,
			  fraginfo_t fraginfo,
			  int l4_off,
			  enum ct_dir ct_dir,
			  struct ipv4_frag_l4ports *ports)
{
	struct ipv4_frag_id frag_id = {
		.daddr = ip4->daddr,
		.saddr = ip4->saddr,
		.id = (__be16)ipfrag_get_id(fraginfo),
		.proto = ipfrag_get_protocol(fraginfo),
	};

	if (unlikely(!ipfrag_has_l4_header(fraginfo)))
		return ipv4_frag_get_l4ports(&frag_id, ports);

	/* load sport + dport into tuple */
	if (l4_load_ports(ctx, l4_off, (__be16 *)ports) < 0)
		return DROP_CT_INVALID_HDR;

	if (unlikely(ipfrag_is_fragment(fraginfo))) {
		/* First logical fragment for this datagram (not necessarily the first
		 * we receive). Fragment has L4 header, create an entry in datagrams map.
		 */
		if (map_update_elem(&cilium_ipv4_frag_datagrams, &frag_id, ports, BPF_ANY))
			update_metrics(ctx_full_len(ctx), ct_to_metrics_dir(ct_dir),
				       REASON_FRAG_PACKET_UPDATE);

		/* Do not return an error if map update failed, as nothing prevents us
		 * to process the current packet normally.
		 */
	}

	return 0;
}
#endif

static __always_inline int
ipv4_load_l4_ports(struct __ctx_buff *ctx, struct iphdr *ip4 __maybe_unused,
		   fraginfo_t fraginfo, int l4_off, enum ct_dir dir __maybe_unused,
		   __be16 *ports)
{
#ifdef ENABLE_IPV4_FRAGMENTS
	return ipv4_handle_fragmentation(ctx, ip4, fraginfo, l4_off, dir,
					 (struct ipv4_frag_l4ports *)ports);
#else
	if (unlikely(!ipfrag_has_l4_header(fraginfo)))
		return DROP_FRAG_NOSUPPORT;
	if (l4_load_ports(ctx, l4_off, ports) < 0)
		return DROP_CT_INVALID_HDR;
#endif

	return 0;
}
