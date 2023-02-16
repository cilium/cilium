/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_IPV4__
#define __LIB_IPV4__

#include <linux/ip.h>

#include "dbg.h"
#include "metrics.h"

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

#ifdef ENABLE_IPV4_FRAGMENTS
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_frag_id);
	__type(value, struct ipv4_frag_l4ports);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES);
} IPV4_FRAG_DATAGRAMS_MAP __section_maps_btf;
#endif

static __always_inline int
ipv4_csum_update_by_value(struct __ctx_buff *ctx, int l3_off, __u64 old_val,
			  __u64 new_val, __u32 len)
{
	return l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check),
			       old_val, new_val, len);
}

static __always_inline int
ipv4_csum_update_by_diff(struct __ctx_buff *ctx, int l3_off, __u64 diff)
{
	return l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check),
			       0, diff, 0);
}

static __always_inline int ipv4_load_daddr(struct __ctx_buff *ctx, int off,
					   __u32 *dst)
{
	return ctx_load_bytes(ctx, off + offsetof(struct iphdr, daddr), dst, 4);
}

static __always_inline int ipv4_dec_ttl(struct __ctx_buff *ctx, int off,
					const struct iphdr *ip4)
{
	__u8 new_ttl, ttl = ip4->ttl;

	if (ttl <= 1)
		return 1;

	new_ttl = ttl - 1;
	/* l3_csum_replace() takes at min 2 bytes, zero extended. */
	ipv4_csum_update_by_value(ctx, off, ttl, new_ttl, 2);
	ctx_store_bytes(ctx, off + offsetof(struct iphdr, ttl), &new_ttl, sizeof(new_ttl), 0);

	return 0;
}

static __always_inline int ipv4_hdrlen(const struct iphdr *ip4)
{
	return ip4->ihl * 4;
}

static __always_inline bool ipv4_is_fragment(const struct iphdr *ip4)
{
	/* The frag_off portion of the header consists of:
	 *
	 * +----+----+----+----------------------------------+
	 * | RS | DF | MF | ...13 bits of fragment offset... |
	 * +----+----+----+----------------------------------+
	 *
	 * If "More fragments" or the offset is nonzero, then this is an IP
	 * fragment (RFC791).
	 */
	return ip4->frag_off & bpf_htons(0x3FFF);
}

static __always_inline bool ipv4_is_not_first_fragment(const struct iphdr *ip4)
{
	/* Ignore "More fragments" bit to catch all fragments but the first */
	return ip4->frag_off & bpf_htons(0x1FFF);
}

/* Simply a reverse of ipv4_is_not_first_fragment to avoid double negative. */
static __always_inline bool ipv4_has_l4_header(const struct iphdr *ip4)
{
	return !ipv4_is_not_first_fragment(ip4);
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

	tmp = map_lookup_elem(&IPV4_FRAG_DATAGRAMS_MAP, frag_id);
	if (!tmp)
		return DROP_FRAG_NOT_FOUND;

	/* Do not make ports a pointer to map data, copy from map */
	memcpy(ports, tmp, sizeof(*ports));
	return 0;
}

static __always_inline int
ipv4_handle_fragmentation(struct __ctx_buff *ctx,
			  const struct iphdr *ip4, int l4_off,
			  enum ct_dir ct_dir,
			  struct ipv4_frag_l4ports *ports,
			  bool *has_l4_header)
{
	bool is_fragment, not_first_fragment;
	enum metric_dir dir;
	int ret;

	struct ipv4_frag_id frag_id = {
		.daddr = ip4->daddr,
		.saddr = ip4->saddr,
		.id = ip4->id,
		.proto = ip4->protocol,
		.pad = 0,
	};

	is_fragment = ipv4_is_fragment(ip4);
	dir = ct_to_metrics_dir(ct_dir);

	if (unlikely(is_fragment)) {
		update_metrics(ctx_full_len(ctx), dir, REASON_FRAG_PACKET);

		not_first_fragment = ipv4_is_not_first_fragment(ip4);
		if (has_l4_header)
			*has_l4_header = !not_first_fragment;

		if (likely(not_first_fragment))
			return ipv4_frag_get_l4ports(&frag_id, ports);
	}

	/* load sport + dport into tuple */
	ret = ctx_load_bytes(ctx, l4_off, ports, 4);
	if (ret < 0)
		return ret;

	if (unlikely(is_fragment)) {
		/* First logical fragment for this datagram (not necessarily the first
		 * we receive). Fragment has L4 header, create an entry in datagrams map.
		 */
		if (map_update_elem(&IPV4_FRAG_DATAGRAMS_MAP, &frag_id, ports, BPF_ANY))
			update_metrics(ctx_full_len(ctx), dir, REASON_FRAG_PACKET_UPDATE);

		/* Do not return an error if map update failed, as nothing prevents us
		 * to process the current packet normally.
		 */
	}

	return 0;
}
#endif

#endif /* __LIB_IPV4__ */
