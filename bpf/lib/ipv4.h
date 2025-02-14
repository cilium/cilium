/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/ip.h>
#include <linux/icmp.h>

#include "dbg.h"
#include "l4.h"
#include "metrics.h"

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

static __always_inline int
icmp4_load_info_from_header(struct __ctx_buff *ctx, const struct iphdr *ip4 __maybe_unused,
			    int l4_off, __u8 *type_out, __u8 *code_out, __be16 *identifier_out)
{
	int ret = 0;

	/* load identifier from ICMP header */
	if (ctx_load_bytes(ctx, l4_off, type_out, 1) < 0) {
		ret = DROP_CT_INVALID_HDR;
		goto out;
	}
	if (ctx_load_bytes(ctx, l4_off + 1, code_out, 1) < 0) {
		ret = DROP_CT_INVALID_HDR;
		goto out;
	}
	if ((*type_out == ICMP_ECHO || *type_out == ICMP_ECHOREPLY) &&
	    ctx_load_bytes(ctx, l4_off + offsetof(struct icmphdr, un.echo.id),
			       identifier_out, 2) < 0)
	{
		ret = DROP_CT_INVALID_HDR;
		goto out;
	}

out:
	return ret;
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
	int ret = CTX_ACT_OK;

	struct ipv4_frag_id frag_id = {
		.daddr = ip4->daddr,
		.saddr = ip4->saddr,
		.id = ip4->id,
		.proto = ip4->protocol,
		.pad = 0,
	};

	is_fragment = ipv4_is_fragment(ip4);

	if (unlikely(is_fragment)) {
		not_first_fragment = ipv4_is_not_first_fragment(ip4);
		if (has_l4_header)
			*has_l4_header = !not_first_fragment;

		if (likely(not_first_fragment))
			return ipv4_frag_get_l4ports(&frag_id, ports);
	}

	switch (ip4->protocol) {
		case IPPROTO_ICMP: {
			__u8 type = 0;
			__u8 code = 0;
			__be16 identifier = 0;

			icmp4_load_info_from_header(ctx, ip4, l4_off, &type, &code,
						    &identifier);

			ports->sport = (__be16)((type << 8) | code);
			ports->dport = identifier;
			break;
		}
		default: {
			/* load sport + dport into tuple */
			ret = l4_load_ports(ctx, l4_off, (__be16 *)ports);
			if (ret < 0) {
				ret = DROP_CT_INVALID_HDR;
				goto out;
			}
			break;
		}
	}

	if (unlikely(is_fragment)) {
		/* First logical fragment for this datagram (not necessarily the first
		 * we receive). Fragment has L4 header, create an entry in datagrams map.
		 */
		if (map_update_elem(&IPV4_FRAG_DATAGRAMS_MAP, &frag_id, ports, BPF_ANY))
			update_metrics(ctx_full_len(ctx), ct_to_metrics_dir(ct_dir),
				       REASON_FRAG_PACKET_UPDATE);

		/* Do not return an error if map update failed, as nothing prevents us
		 * to process the current packet normally.
		 */
	}

out:
	return ret;
}

static __always_inline int
icmp4_handle_fragmentation(struct __ctx_buff *ctx, const struct iphdr *ip4,
			   int l4_off, enum ct_dir ct_dir, bool *has_l4_header, __u8 *type_out,
				__u8 *code_out, __be16 *identifier_out)
{
	int ret = 0;
	struct ipv4_frag_l4ports ports;
	bool is_fragment, not_first_fragment;
	struct ipv4_frag_id frag_id;
	enum metric_dir mdir = ct_to_metrics_dir(ct_dir);

	/* fill the key */
	frag_id.daddr = ip4->daddr;
	frag_id.saddr = ip4->saddr;
	frag_id.id = ip4->id;
	frag_id.proto = ip4->protocol;
	frag_id.pad = 0;

	is_fragment = ipv4_is_fragment(ip4);

	if (unlikely(is_fragment)) {
		not_first_fragment = ipv4_is_not_first_fragment(ip4);
		if (has_l4_header)
			*has_l4_header = !not_first_fragment;

		if (likely(not_first_fragment)) {
			/* it should be a fragmented packet */
			update_metrics(ctx_full_len(ctx), mdir, REASON_FRAG_PACKET);

			/* load identifier from frag map */
			ret = ipv4_frag_get_l4ports(&frag_id, &ports);
			if (ret < 0)
				goto out;

			*type_out = (ports.sport & 0xff00) >> 8;
			*code_out = (ports.sport & 0x00ff);
			*identifier_out = ports.dport;
			goto out;
	}
	}

	ret = icmp4_load_info_from_header(ctx, ip4, l4_off, type_out, code_out,
					  identifier_out);
	if (ret < 0)
		goto out;

	if (is_fragment) {
		/* "more fragments" flag is set, or we have frag offset */
		/* it's fragmented ICMP, store header info to the map */
		ports.sport = (__be16)(((*type_out) << 8) | (*code_out));
		ports.dport = (*identifier_out);

		if (map_update_elem(&IPV4_FRAG_DATAGRAMS_MAP, &frag_id, &ports, BPF_ANY))
			update_metrics(ctx_full_len(ctx), mdir, REASON_FRAG_PACKET_UPDATE);
	}

out:
	return ret;
}
#endif

static __always_inline int
ipv4_load_l4_ports(struct __ctx_buff *ctx, struct iphdr *ip4 __maybe_unused,
		   int l4_off, enum ct_dir dir __maybe_unused,
		   __be16 *ports, bool *has_l4_header __maybe_unused)
{
#ifdef ENABLE_IPV4_FRAGMENTS
	return ipv4_handle_fragmentation(ctx, ip4, l4_off, dir,
					 (struct ipv4_frag_l4ports *)ports,
					 has_l4_header);
#else
	if (l4_load_ports(ctx, l4_off, ports) < 0)
		return DROP_CT_INVALID_HDR;
#endif

	return CTX_ACT_OK;
}

static __always_inline int
icmp4_load_info(struct __ctx_buff *ctx, const struct iphdr *ip4, int l4_off,
		enum ct_dir ct_dir __maybe_unused, bool *has_l4_header __maybe_unused,
				__u8 *type_out, __u8 *code_out, __be16 *identifier_out)
{
#ifdef ENABLE_IPV4_FRAGMENTS
	return icmp4_handle_fragmentation(ctx, ip4, l4_off, ct_dir, has_l4_header, type_out,
		code_out, identifier_out);
#else
	return icmp4_load_info_from_header(ctx, ip4, l4_off, type_out, code_out,
		identifier_out);
#endif
}

