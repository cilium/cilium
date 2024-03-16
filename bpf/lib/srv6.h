/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"
#include "lib/fib.h"
#include "lib/identity.h"

#include "maps.h"

#ifdef ENABLE_SRV6
struct srv6_srh {
	struct ipv6_rt_hdr rthdr;
	__u8 first_segment;
	__u8 flags;
	__u16 reserved;
	struct in6_addr segments[0];
};

# ifdef ENABLE_IPV4

/* SRV6_VRF_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of
 * srv6_vrf_key4.
 */
#  define SRV6_VRF_STATIC_PREFIX4						\
	(8 * (sizeof(struct srv6_vrf_key4) - sizeof(struct bpf_lpm_trie_key)\
	      - 4))
#  define SRV6_VRF_PREFIX4_LEN(PREFIX) (SRV6_VRF_STATIC_PREFIX4 + (PREFIX))
#  define SRV6_VRF_IPV4_PREFIX SRV6_VRF_PREFIX4_LEN(32)
static __always_inline __u32*
srv6_lookup_vrf4(__be32 sip, __be32 dip)
{
	struct srv6_vrf_key4 key = {
		.lpm = { SRV6_VRF_IPV4_PREFIX, {} },
		.src_ip = sip,
		.dst_cidr = dip,
	};
	return map_lookup_elem(&SRV6_VRF_MAP4, &key);
}

/* SRV6_POLICY_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of
 * srv6_policy_key4.
 */
#  define SRV6_POLICY_STATIC_PREFIX4						\
	(8 * (sizeof(struct srv6_policy_key4) - sizeof(struct bpf_lpm_trie_key)	\
	      - 4))
#  define SRV6_POLICY_PREFIX4_LEN(PREFIX) (SRV6_POLICY_STATIC_PREFIX4 + (PREFIX))
#  define SRV6_POLICY_IPV4_PREFIX SRV6_POLICY_PREFIX4_LEN(32)
static __always_inline union v6addr *
srv6_lookup_policy4(__u32 vrf_id, __be32 dip)
{
	struct srv6_policy_key4 key = {
		.lpm = { SRV6_POLICY_IPV4_PREFIX, {} },
		.vrf_id = vrf_id,
		.dst_cidr = dip,
	};
	return map_lookup_elem(&SRV6_POLICY_MAP4, &key);
}
# endif /* ENABLE_IPV4 */

/* SRV6_VRF_STATIC_PREFIX6 gets sizeof non-IP, non-prefix part of
 * srv6_vrf_key6.
 */
#  define SRV6_VRF_STATIC_PREFIX6						\
	(8 * (sizeof(struct srv6_vrf_key6) - sizeof(struct bpf_lpm_trie_key)\
	      - 4))
#  define SRV6_VRF_PREFIX6_LEN(PREFIX) (SRV6_VRF_STATIC_PREFIX6 + (PREFIX))
#  define SRV6_VRF_IPV6_PREFIX SRV6_VRF_PREFIX6_LEN(32)
static __always_inline __u32*
srv6_lookup_vrf6(const struct in6_addr *sip, const struct in6_addr *dip)
{
	struct srv6_vrf_key6 key = {
		.lpm = { SRV6_VRF_IPV6_PREFIX, {} },
		.src_ip = *(union v6addr *)sip,
		.dst_cidr = *(union v6addr *)dip,
	};
	return map_lookup_elem(&SRV6_VRF_MAP6, &key);
}

/* SRV6_POLICY_STATIC_PREFIX6 gets sizeof non-IP, non-prefix part of
 * srv6_policy_key6.
 */
# define SRV6_POLICY_STATIC_PREFIX6						\
	(8 * (sizeof(struct srv6_policy_key6) - sizeof(struct bpf_lpm_trie_key)	\
	      - 4))
# define SRV6_POLICY_PREFIX6_LEN(PREFIX) (SRV6_POLICY_STATIC_PREFIX6 + (PREFIX))
# define SRV6_POLICY_IPV6_PREFIX SRV6_POLICY_PREFIX6_LEN(128)

static __always_inline union v6addr *
srv6_lookup_policy6(__u32 vrf_id, const struct in6_addr *dip)
{
	struct srv6_policy_key6 key = {
		.lpm = { SRV6_POLICY_IPV6_PREFIX, {} },
		.vrf_id = vrf_id,
		.dst_cidr = *(union v6addr *)dip,
	};
	return map_lookup_elem(&SRV6_POLICY_MAP6, &key);
}

static __always_inline __u32
srv6_lookup_sid(const struct in6_addr *sid)
{
	__u32 *vrf_id;

	vrf_id = map_lookup_elem(&SRV6_SID_MAP, sid);
	if (vrf_id)
		return *vrf_id;
	return 0;
}

static __always_inline bool
is_srv6_packet(const struct ipv6hdr *ip6)
{
#ifdef ENABLE_SRV6_SRH_ENCAP
	if (ip6->nexthdr == NEXTHDR_ROUTING)
		return true;
#endif /* ENABLE_SRV6_SRH_ENCAP */
	return ip6->nexthdr == IPPROTO_IPIP ||
	       ip6->nexthdr == IPPROTO_IPV6;
}

# ifndef SKIP_SRV6_HANDLING
static __always_inline int
srv6_encapsulation(struct __ctx_buff *ctx, int growth, __u16 new_payload_len,
		   __u8 nexthdr, union v6addr *saddr, struct in6_addr *sid)
{
	__u32 len = sizeof(struct ipv6hdr) - 2 * sizeof(struct in6_addr);
	struct ipv6hdr new_ip6 = {
		.version     = 0x6,
		.payload_len = bpf_htons(new_payload_len),
		.nexthdr     = nexthdr,
		.hop_limit   = IPDEFTTL,
	};

#ifdef ENABLE_SRV6_SRH_ENCAP
	/* If reduced encapsulation is disabled, the next header will be the
	 * segment routing header.
	 */
	new_ip6.nexthdr = NEXTHDR_ROUTING;
#endif /* ENABLE_SRV6_SRH_ENCAP */

	/* Add room between Ethernet and network headers. */
	if (ctx_adjust_hroom(ctx, growth, BPF_ADJ_ROOM_MAC,
			     BPF_F_ADJ_ROOM_ENCAP_L3_IPV6))
		return DROP_INVALID;
	if (ctx_store_bytes(ctx, ETH_HLEN, &new_ip6, len, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			    saddr, sizeof(union v6addr), 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
			    sid, sizeof(struct in6_addr), 0) < 0)
		return DROP_WRITE_ERROR;

#ifdef ENABLE_SRV6_SRH_ENCAP
	{
	/* If reduced encapsulation mode is disabled, we need to add a segment
	 * routing header.
	 */
	struct srv6_srh srh = {
		.rthdr.nexthdr       = nexthdr,
		.rthdr.hdrlen        = sizeof(struct in6_addr) / 8,
		.rthdr.type          = IPV6_SRCRT_TYPE_4,
		.rthdr.segments_left = 0,
		.first_segment       = 0,
		.flags               = 0,
		.reserved            = 0,
	};
	int segment_list_offset = ETH_HLEN + sizeof(struct ipv6hdr) +
				  offsetof(struct srv6_srh, segments);

	if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(struct ipv6hdr),
			    &srh, sizeof(struct srv6_srh), 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, segment_list_offset, sid,
			    sizeof(struct in6_addr), 0) < 0)
		return DROP_WRITE_ERROR;
	}
#endif /* ENABLE_SRV6_SRH_ENCAP */

	return 0;
}

static __always_inline int
srv6_decapsulation(struct __ctx_buff *ctx)
{
	__u16 new_proto = bpf_htons(ETH_P_IP);
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int shrink = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	switch (ip6->nexthdr) {
#ifdef ENABLE_SRV6_SRH_ENCAP
	case NEXTHDR_ROUTING: {
		struct srv6_srh *srh = (struct srv6_srh *)(ip6 + 1);

		if ((void *)srh + sizeof(struct srv6_srh) + sizeof(struct in6_addr) > data_end)
			return DROP_INVALID;

		/* We only support the SRH extension header for now. */
		if (srh->rthdr.type != IPV6_SRCRT_TYPE_4)
			return DROP_INVALID;

		shrink = sizeof(struct srv6_srh) + sizeof(struct in6_addr);

		switch (srh->rthdr.nexthdr) {
		case IPPROTO_IPIP:
			goto parse_outer_ipv4;
		case IPPROTO_IPV6:
			goto parse_outer_ipv6;
		default:
			return DROP_INVALID;
		}
	}
#endif /* ENABLE_SRV6_SRH_ENCAP */
	case IPPROTO_IPIP:
parse_outer_ipv4: __maybe_unused;
		if (ctx_change_proto(ctx, new_proto, 0) < 0)
			return DROP_WRITE_ERROR;
		if (ctx_store_bytes(ctx, offsetof(struct ethhdr, h_proto),
				    &new_proto, sizeof(new_proto), 0) < 0)
			return DROP_WRITE_ERROR;
		/* ctx_change_proto above shrinks the packet from IPv6 header
		 * length to IPv4 header length. It removes that space from the
		 * same header we will later delete.
		 * Thus, deduce this space from the next packet shrinking.
		 */
		shrink += sizeof(struct iphdr);
		break;
	case IPPROTO_IPV6:
parse_outer_ipv6: __maybe_unused;
		shrink += sizeof(struct ipv6hdr);
		break;
	default:
		return DROP_INVALID;
	}

	/* Remove the outer IPv6 header. */
	if (ctx_adjust_hroom(ctx, -shrink, BPF_ADJ_ROOM_MAC,
			     ctx_adjust_hroom_flags()))
		return DROP_INVALID;
	return 0;
}

static __always_inline int
srv6_handling4(struct __ctx_buff *ctx, union v6addr *src_sid,
	       struct in6_addr *dst_sid)
{
	__u16 new_payload_len, outer_proto = bpf_htons(ETH_P_IPV6);
	void *data, *data_end;
	struct iphdr *ip4;
	__u8 nexthdr;
	int growth = 0;

	/* Inner packet is IPv4. */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	nexthdr = IPPROTO_IPIP;
	/* IPv4's tot_len fields has the size of the entire packet
	 * including headers while IPv6's payload_len field has only
	 * the size of the IPv6 payload. Therefore, without IPv6
	 * extension headers (none here), the outer IPv6 payload_len
	 * is equal to the inner IPv4 tot_len.
	 */
	new_payload_len = bpf_ntohs(ip4->tot_len) - (__u16)(ip4->ihl << 2) + sizeof(struct iphdr);

	if (ctx_store_bytes(ctx, offsetof(struct ethhdr, h_proto),
			    &outer_proto, sizeof(outer_proto), 0) < 0)
		return DROP_WRITE_ERROR;

#ifdef ENABLE_SRV6_SRH_ENCAP
	growth += sizeof(struct ipv6hdr) + sizeof(struct srv6_srh) + sizeof(struct in6_addr);
	new_payload_len += sizeof(struct srv6_srh) + sizeof(struct in6_addr);
#else
	growth += sizeof(struct ipv6hdr);
#endif /* ENABLE_SRV6_SRH_ENCAP */

	return srv6_encapsulation(ctx, growth, new_payload_len, nexthdr,
				  src_sid, dst_sid);
}

static __always_inline int
srv6_handling6(struct __ctx_buff *ctx, union v6addr *src_sid,
	       struct in6_addr *dst_sid)
{
	__u16 new_payload_len;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u8 nexthdr;
	int growth;

	/* Inner packet is IPv6. */
	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;
	nexthdr = IPPROTO_IPV6;
	new_payload_len = bpf_ntohs(ip6->payload_len) + sizeof(struct ipv6hdr);
	growth = sizeof(struct ipv6hdr);

#ifdef ENABLE_SRV6_SRH_ENCAP
	growth += sizeof(struct srv6_srh) + sizeof(struct in6_addr);
	new_payload_len += sizeof(struct srv6_srh) + sizeof(struct in6_addr);
#endif /* ENABLE_SRV6_SRH_ENCAP */

	return srv6_encapsulation(ctx, growth, new_payload_len, nexthdr,
				  src_sid, dst_sid);
}

static __always_inline int
srv6_handling(struct __ctx_buff *ctx, struct in6_addr *dst_sid)
{
	void *data, *data_end;
	__u16 inner_proto;
	union v6addr router_ip;

	BPF_V6(router_ip, ROUTER_IP);

	if (!validate_ethertype(ctx, &inner_proto))
		return DROP_UNSUPPORTED_L2;

	switch (inner_proto) {
#  ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6): {
		struct ipv6hdr *ip6;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		return srv6_handling6(ctx, &router_ip, dst_sid);
	}
#  endif /* ENABLE_IPV6 */
#  ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		struct iphdr *ip4;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		return srv6_handling4(ctx, &router_ip, dst_sid);
	}
#  endif /* ENABLE_IPV4 */
	default:
		return DROP_INVALID;
	}
}

static __always_inline void
srv6_load_meta_sid(struct __ctx_buff *ctx, const struct in6_addr *sid)
{
	ctx_load_meta_ipv6(ctx, (union v6addr *)sid, CB_SRV6_SID_1);
}

static __always_inline void
srv6_store_meta_sid(struct __ctx_buff *ctx, const union v6addr *sid)
{
	ctx_store_meta_ipv6(ctx, CB_SRV6_SID_1, sid);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SRV6_ENCAP)
int tail_srv6_encap(struct __ctx_buff *ctx)
{
	struct in6_addr dst_sid;
	int ret = 0;
	int __maybe_unused ext_err = 0;

	srv6_load_meta_sid(ctx, &dst_sid);
	ret = srv6_handling(ctx, &dst_sid);
	if (ret < 0)
		return send_drop_notify_error(ctx, SECLABEL_IPV6, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);

	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL_IPV6, UNKNOWN_ID,
			  TRACE_EP_ID_UNKNOWN,
			  TRACE_IFINDEX_UNKNOWN, TRACE_REASON_SRV6_ENCAP, 0);

	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SRV6_DECAP)
int tail_srv6_decap(struct __ctx_buff *ctx)
{
	int ret = 0;

	ret = srv6_decapsulation(ctx);
	if (ret < 0)
		goto error_drop;

	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL_IPV6, UNKNOWN_ID,
			  TRACE_EP_ID_UNKNOWN,
			  TRACE_IFINDEX_UNKNOWN, TRACE_REASON_SRV6_DECAP, 0);
	return CTX_ACT_OK;
error_drop:
		return send_drop_notify_error(ctx, SECLABEL_IPV6, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);
}
# endif /* SKIP_SRV6_HANDLING */
#endif /* ENABLE_SRV6 */
