/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/ipv6.h>

#include "dbg.h"
#include "l4.h"
#include "metrics.h"
#include "ipfrag.h"

/* Number of extension headers that can be skipped */
#define IPV6_MAX_HEADERS 4

#define NEXTHDR_HOP             0       /* Hop-by-hop option header. */
#define NEXTHDR_TCP             6       /* TCP segment. */
#define NEXTHDR_UDP             17      /* UDP message. */
#define NEXTHDR_IPV6            41      /* IPv6 in IPv6 */
#define NEXTHDR_ROUTING         43      /* Routing header. */
#define NEXTHDR_FRAGMENT        44      /* Fragmentation/reassembly header. */
#define NEXTHDR_GRE             47      /* GRE header. */
#define NEXTHDR_ESP             50      /* Encapsulating security payload. */
#define NEXTHDR_AUTH            51      /* Authentication header. */
#define NEXTHDR_ICMP            58      /* ICMP for IPv6. */
#define NEXTHDR_NONE            59      /* No next header */
#define NEXTHDR_DEST            60      /* Destination options header. */
#define NEXTHDR_SCTP            132     /* SCTP message. */
#define NEXTHDR_MOBILITY        135     /* Mobility header. */

#define NEXTHDR_MAX             255

#define IPV6_FRAGLEN            8

#define IPV6_SADDR_OFF		offsetof(struct ipv6hdr, saddr)
#define IPV6_DADDR_OFF		offsetof(struct ipv6hdr, daddr)

/* Follows the structure of ipv6hdr, see ipv6_handle_fragmentation. */
struct ipv6_frag_id {
	__be32 id;		/* L4 datagram identifier */
	__u8 proto;
	__u8 pad[3];
	union v6addr saddr;
	union v6addr daddr;
} __packed;

struct ipv6_frag_l4ports {
	__be16 sport;
	__be16 dport;
} __packed;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv6_frag_id);
	__type(value, struct ipv6_frag_l4ports);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_IPV6_FRAG_MAP_MAX_ENTRIES);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_ipv6_frag_datagrams __section_maps_btf;

static __always_inline int ipv6_optlen(const struct ipv6_opt_hdr *opthdr)
{
	return (opthdr->hdrlen + 1) << 3;
}

static __always_inline int ipv6_authlen(const struct ipv6_opt_hdr *opthdr)
{
	return (opthdr->hdrlen + 2) << 2;
}

static __always_inline int ipv6_skip_exthdr(struct __ctx_buff *ctx, __u8 *nexthdr, int off)
{
	struct ipv6_opt_hdr opthdr __align_stack_8;
	__u8 nh = *nexthdr;

	switch (nh) {
	case NEXTHDR_NONE:
		return DROP_INVALID_EXTHDR;

	case NEXTHDR_FRAGMENT:
	case NEXTHDR_AUTH:
	case NEXTHDR_HOP:
	case NEXTHDR_ROUTING:
	case NEXTHDR_DEST:
		if (ctx_load_bytes(ctx, off, &opthdr, sizeof(opthdr)) < 0)
			return DROP_INVALID;

		*nexthdr = opthdr.nexthdr;
		break;

	default: /* L4 protocol */
		return 0;
	}

	switch (nh) {
	case NEXTHDR_FRAGMENT:
		return IPV6_FRAGLEN;

	case NEXTHDR_AUTH:
		return ipv6_authlen(&opthdr);

	case NEXTHDR_HOP:
	case NEXTHDR_ROUTING:
	case NEXTHDR_DEST:
		return ipv6_optlen(&opthdr);

	default:
		/* Returned in the switch above. */
		__builtin_unreachable();
	}
}

static __always_inline int ipv6_hdrlen_offset(struct __ctx_buff *ctx, int l3_off,
					      __u8 *nexthdr, fraginfo_t *fraginfo)
{
	int i, len = sizeof(struct ipv6hdr);
	__u8 nh = *nexthdr;

	/* 0 is a valid fraginfo that encodes:
	 * - is_fragment = false
	 * - has_l4_header = true
	 * - protocol = 0 (unused when !is_fragment)
	 * This is the default in case no NEXTHDR_FRAGMENT is found.
	 */
	*fraginfo = 0;

#pragma unroll
	for (i = 0; i < IPV6_MAX_HEADERS; i++) {
		__u8 newnh = nh;
		int hdrlen = ipv6_skip_exthdr(ctx, &newnh, l3_off + len);

		if (hdrlen < 0)
			return hdrlen;

		if (!hdrlen) {
			*nexthdr = nh;
			return len;
		}

		if (nh == NEXTHDR_FRAGMENT) {
			struct ipv6_frag_hdr frag;

			if (ctx_load_bytes(ctx, l3_off + len, &frag, sizeof(frag)) < 0)
				return DROP_INVALID;

			*fraginfo = ipfrag_encode_ipv6(&frag);
		}

		len += hdrlen;
		nh = newnh;
	}

	/* Reached limit of supported extension headers */
	return DROP_INVALID_EXTHDR;
}

static __always_inline int ipv6_hdrlen_with_fraginfo(struct __ctx_buff *ctx,
						     __u8 *nexthdr,
						     fraginfo_t *fraginfo)
{
	return ipv6_hdrlen_offset(ctx, ETH_HLEN, nexthdr, fraginfo);
}

static __always_inline int ipv6_hdrlen(struct __ctx_buff *ctx, __u8 *nexthdr)
{
	fraginfo_t fraginfo;

	return ipv6_hdrlen_offset(ctx, ETH_HLEN, nexthdr, &fraginfo);
}

static __always_inline void ipv6_addr_copy(union v6addr *dst,
					   const union v6addr *src)
{
	memcpy(dst, src, sizeof(*dst));
}

static __always_inline void ipv6_addr_copy_unaligned(union v6addr *dst,
						     const union v6addr *src)
{
	dst->d1 = src->d1;
	dst->d2 = src->d2;
}

static __always_inline bool ipv6_addr_equals(const union v6addr *a,
					     const union v6addr *b)
{
	if (a->d1 != b->d1)
		return false;
	return a->d2 == b->d2;
}

/* Only works with contiguous masks. */
static __always_inline int ipv6_addr_in_net(const union v6addr *addr,
					    const union v6addr *net,
					    const union v6addr *mask)
{
	return ((addr->p1 & mask->p1) == net->p1)
		&& (!mask->p2
		    || (((addr->p2 & mask->p2) == net->p2)
			&& (!mask->p3
			    || (((addr->p3 & mask->p3) == net->p3)
				&& (!mask->p4 || ((addr->p4 & mask->p4) == net->p4))))));
}

#define GET_PREFIX(PREFIX)						\
	bpf_htonl(PREFIX <= 0 ? 0 : PREFIX < 32 ? ((1<<PREFIX) - 1) << (32-PREFIX)	\
			      : 0xFFFFFFFF)

static __always_inline void ipv6_addr_clear_suffix(union v6addr *addr,
						   int prefix)
{
	addr->p1 &= GET_PREFIX(prefix);
	prefix -= 32;
	addr->p2 &= GET_PREFIX(prefix);
	prefix -= 32;
	addr->p3 &= GET_PREFIX(prefix);
	prefix -= 32;
	addr->p4 &= GET_PREFIX(prefix);
}

static __always_inline int ipv6_dec_hoplimit(struct __ctx_buff *ctx, int off)
{
	__u8 hl;

	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
			   &hl, sizeof(hl)) < 0)
		return DROP_INVALID;

	if (hl <= 1)
		return DROP_TTL_EXCEEDED;
	hl--;
	if (ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
			    &hl, sizeof(hl), BPF_F_RECOMPUTE_CSUM) < 0)
		return DROP_WRITE_ERROR;
	return 0;
}

static __always_inline int ipv6_load_saddr(struct __ctx_buff *ctx, int off,
					   union v6addr *dst)
{
	return ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, saddr), dst->addr,
			      sizeof(((struct ipv6hdr *)NULL)->saddr));
}

/* Assumes that caller fixes checksum csum_diff() and l4_csum_replace() */
static __always_inline int ipv6_store_saddr(struct __ctx_buff *ctx, __u8 *addr,
					    int off)
{
	return ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, saddr), addr, 16, 0);
}

static __always_inline int ipv6_load_daddr(struct __ctx_buff *ctx, int off,
					   union v6addr *dst)
{
	return ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, daddr), dst->addr,
			      sizeof(((struct ipv6hdr *)NULL)->daddr));
}

/* Assumes that caller fixes checksum csum_diff() and l4_csum_replace() */
static __always_inline int
ipv6_store_daddr(struct __ctx_buff *ctx, const __u8 *addr, int off)
{
	return ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, daddr), addr, 16, 0);
}

static __always_inline int ipv6_load_nexthdr(struct __ctx_buff *ctx, int off,
					     __u8 *nexthdr)
{
	return ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, nexthdr), nexthdr,
			      sizeof(__u8));
}

/* Assumes that caller fixes checksum csum_diff() and l4_csum_replace() */
static __always_inline int ipv6_store_nexthdr(struct __ctx_buff *ctx, __u8 *nexthdr,
					      int off)
{
	return ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, nexthdr), nexthdr,
			      sizeof(__u8), 0);
}

static __always_inline int ipv6_load_paylen(struct __ctx_buff *ctx, int off,
					    __be16 *len)
{
	return ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, payload_len),
			      len, sizeof(*len));
}

/* Assumes that caller fixes checksum csum_diff() and l4_csum_replace() */
static __always_inline int ipv6_store_paylen(struct __ctx_buff *ctx, int off,
					     __be16 *len)
{
	return ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, payload_len),
			       len, sizeof(*len), 0);
}

static __always_inline __be32 ipv6_pseudohdr_checksum(struct ipv6hdr *hdr,
						      __u8 next_hdr,
						      __u16 payload_len, __be32 sum)
{
	__be32 len = bpf_htonl((__u32)payload_len);
	__be32 nexthdr = bpf_htonl((__u32)next_hdr);

	sum = csum_diff(NULL, 0, &hdr->saddr, sizeof(struct in6_addr), sum);
	sum = csum_diff(NULL, 0, &hdr->daddr, sizeof(struct in6_addr), sum);
	sum = csum_diff(NULL, 0, &len, sizeof(len), sum);
	sum = csum_diff(NULL, 0, &nexthdr, sizeof(nexthdr), sum);

	return sum;
}

/*
 * Ipv4 mapped address - 0:0:0:0:0:FFFF::/96
 */
static __always_inline int ipv6_addr_is_mapped(const union v6addr *addr)
{
	return addr->p1 == 0 && addr->p2 == 0 && addr->p3 == 0xFFFF0000;
}

/* As opposed to ipfrag_encode_ipv6, this function can return errors. */
static __always_inline fraginfo_t
ipv6_get_fraginfo(struct __ctx_buff *ctx, const struct ipv6hdr *ip6)
{
	int l3_off = (int)((void *)ip6 - ctx_data(ctx));
	int i, len = sizeof(struct ipv6hdr);
	__u8 nh = ip6->nexthdr;

#pragma unroll
	for (i = 0; i < IPV6_MAX_HEADERS; i++) {
		__u8 newnh = nh;
		int hdrlen = ipv6_skip_exthdr(ctx, &newnh, l3_off + len);

		if (hdrlen < 0)
			return hdrlen;

		if (!hdrlen) {
			/* No fragment header. 0 is a valid fraginfo that encodes:
			 * - is_fragment = false
			 * - has_l4_header = true
			 * - protocol = 0 (unused when !is_fragment)
			 */
			return 0;
		}

		if (nh == NEXTHDR_FRAGMENT) {
			struct ipv6_frag_hdr frag;

			if (ctx_load_bytes(ctx, l3_off + len, &frag, sizeof(frag)) < 0)
				return DROP_INVALID;

			return ipfrag_encode_ipv6(&frag);
		}

		len += hdrlen;
		nh = newnh;
	}

	/* Reached limit of supported extension headers */
	return DROP_INVALID_EXTHDR;
}

#ifdef ENABLE_IPV6_FRAGMENTS
static __always_inline int
ipv6_frag_get_l4ports(const struct ipv6_frag_id *frag_id,
		      struct ipv6_frag_l4ports *ports)
{
	struct ipv6_frag_l4ports *tmp;

	tmp = map_lookup_elem(&cilium_ipv6_frag_datagrams, frag_id);
	if (!tmp)
		return DROP_FRAG_NOT_FOUND;

	memcpy(ports, tmp, sizeof(*ports));
	return 0;
}

static __always_inline int
ipv6_handle_fragmentation(struct __ctx_buff *ctx,
			  const struct ipv6hdr *ip6,
			  fraginfo_t fraginfo,
			  int l4_off,
			  enum ct_dir ct_dir,
			  struct ipv6_frag_l4ports *ports)
{
	/* frag_id and ip6 have saddr and daddr at the same offset, which allows
	 * to spare a bit of stack space and save a copy of 32 bytes.
	 */
	union {
		__u64 diff;
		struct ipv6_frag_id frag_id;
		struct ipv6hdr ip6;
	} *u = (void *)ip6;
	__u64 backup = u->diff;
	int ret = 0;

	u->diff = 0; /* Clear the padding. */
	u->frag_id.id = ipfrag_get_id(fraginfo);
	u->frag_id.proto = ipfrag_get_protocol(fraginfo);
	/* saddr and daddr are already there. */

	if (unlikely(!ipfrag_has_l4_header(fraginfo))) {
		ret = ipv6_frag_get_l4ports(&u->frag_id, ports);
		goto out;
	}

	if (l4_load_ports(ctx, l4_off, (__be16 *)ports) < 0) {
		ret = DROP_CT_INVALID_HDR;
		goto out;
	}

	if (unlikely(ipfrag_is_fragment(fraginfo))) {
		if (map_update_elem(&cilium_ipv6_frag_datagrams, &u->frag_id, ports, BPF_ANY))
			update_metrics(ctx_full_len(ctx), ct_to_metrics_dir(ct_dir),
				       REASON_FRAG_PACKET_UPDATE);
	}

out:
	u->diff = backup;
	return ret;
}
#endif

static __always_inline int
ipv6_load_l4_ports(struct __ctx_buff *ctx, struct ipv6hdr *ip6 __maybe_unused,
		   fraginfo_t fraginfo, int l4_off, enum ct_dir dir __maybe_unused,
		   __be16 *ports)
{
#ifdef ENABLE_IPV6_FRAGMENTS
	return ipv6_handle_fragmentation(ctx, ip6, fraginfo, l4_off, dir,
					 (struct ipv6_frag_l4ports *)ports);
#else
	if (unlikely(!ipfrag_has_l4_header(fraginfo)))
		return DROP_FRAG_NOSUPPORT;
	if (l4_load_ports(ctx, l4_off, ports) < 0)
		return DROP_CT_INVALID_HDR;
#endif

	return 0;
}
