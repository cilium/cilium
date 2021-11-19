/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

#ifndef __LIB_EGRESS_POLICIES_H_
#define __LIB_EGRESS_POLICIES_H_

#include "lib/identity.h"

#if defined(ENABLE_EGRESS_GATEWAY) || defined(ENABLE_SRV6)
/* is_cluster_destination returns true if the given destination is part of the
 * cluster. It uses the ipcache and endpoint maps information.
 * We check three cases:
 *  - Remote endpoints (non-zero tunnel endpoint field in ipcache)
 *  - Cilium-managed node (remote or local)
 *  - Local endpoint (present in endpoint map)
 * Everything else is outside the cluster.
 */
# define IS_CLUSTER_DESTINATION(NAME, TYPE, LOOKUP_FN)	\
static __always_inline bool				\
NAME(TYPE ip, __u32 dst_id, __u32 tunnel_endpoint)	\
{							\
	if (tunnel_endpoint != 0)			\
		return true;				\
							\
	if (identity_is_node(dst_id))			\
		return true;				\
							\
	if (LOOKUP_FN(ip))				\
		return true;				\
							\
	return false;					\
}

# ifdef ENABLE_IPV4
IS_CLUSTER_DESTINATION(is_cluster_destination4, struct iphdr *, lookup_ip4_endpoint)
# endif /* ENABLE_IPV4 */
IS_CLUSTER_DESTINATION(is_cluster_destination6, struct ipv6hdr *, lookup_ip6_endpoint)
#endif /* ENABLE_EGRESS_GATEWAY || ENABLE_SRV6 */

#ifdef ENABLE_EGRESS_GATEWAY
/* EGRESS_STATIC_PREFIX gets sizeof non-IP, non-prefix part of egress_key */
# define EGRESS_STATIC_PREFIX							\
	(8 * (sizeof(struct egress_key) - sizeof(struct bpf_lpm_trie_key)	\
	      - 4))
# define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
# define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

static __always_inline __maybe_unused struct egress_info *
egress_lookup4(const void *map, __be32 sip, __be32 dip)
{
	struct egress_key key = {
		.lpm_key = { EGRESS_IPV4_PREFIX, {} },
		.sip = sip,
		.dip = dip,
	};
	return map_lookup_elem(map, &key);
}

# define lookup_ip4_egress_endpoint(sip, dip) \
	egress_lookup4(&EGRESS_MAP, sip, dip)
#endif /* ENABLE_EGRESS_GATEWAY */

#ifdef ENABLE_SRV6
# ifdef ENABLE_IPV4

/* SRV6_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of srv6_key4 */
#  define SRV6_STATIC_PREFIX4							\
	(8 * (sizeof(struct srv6_key4) - sizeof(struct bpf_lpm_trie_key)	\
	      - 4))
#  define SRV6_PREFIX4_LEN(PREFIX) (SRV6_STATIC_PREFIX4 + (PREFIX))
#  define SRV6_IPV4_PREFIX SRV6_PREFIX4_LEN(32)
static __always_inline __maybe_unused union v6addr *
srv6_lookup4(const void *map, __be32 sip, __be32 dip)
{
	struct srv6_key4 key = {
		.lpm = { SRV6_IPV4_PREFIX, {} },
		.src_ip = sip,
		.dst_cidr = dip,
	};
	return map_lookup_elem(map, &key);
}

#  define lookup_ip4_srv6(sip, dip) \
	srv6_lookup4(&SRV6_MAP4, sip, dip)
# endif /* ENABLE_IPV4 */

/* SRV6_STATIC_PREFIX6 gets sizeof non-IP, non-prefix part of srv6_key6 */
# define SRV6_STATIC_PREFIX6							\
	(8 * (sizeof(struct srv6_key6) - sizeof(struct bpf_lpm_trie_key)	\
	      - 4))
# define SRV6_PREFIX6_LEN(PREFIX) (SRV6_STATIC_PREFIX6 + (PREFIX))
# define SRV6_IPV6_PREFIX SRV6_PREFIX6_LEN(128)

static __always_inline __maybe_unused union v6addr *
srv6_lookup6(const void *map, const union v6addr *sip,
	     const union v6addr *dip)
{
	struct srv6_key6 key = {
		.lpm = { SRV6_IPV6_PREFIX, {} },
		.src_ip = *sip,
		.dst_cidr = *dip,
	};
	return map_lookup_elem(map, &key);
}

# define lookup_ip6_srv6(sip, dip) \
	srv6_lookup6(&SRV6_MAP6, (union v6addr *)sip, (union v6addr *)dip)

# ifndef SKIP_SRV6_HANDLING
static __always_inline __u64 ctx_adjust_hroom_flags(void)
{
#ifdef BPF_HAVE_CSUM_LEVEL
	return BPF_F_ADJ_ROOM_NO_CSUM_RESET;
#else
	return 0;
#endif
}

static __always_inline int
srv6_encapsulation(struct __ctx_buff *ctx, int growth, __u16 new_payload_len,
		   __u8 nexthdr, struct in6_addr *saddr, struct in6_addr *sid)
{
	__u32 len = sizeof(struct ipv6hdr) - 2 * sizeof(struct in6_addr);
	struct ipv6hdr new_ip6 = {
		.version     = 0x6,
		.payload_len = bpf_htons(new_payload_len),
		.nexthdr     = nexthdr,
		.hop_limit   = IPDEFTTL,
	};

	/* Add room between Ethernet and network headers. */
	if (ctx_adjust_hroom(ctx, growth, BPF_ADJ_ROOM_MAC,
			     ctx_adjust_hroom_flags()))
		return DROP_INVALID;
	if (ctx_store_bytes(ctx, ETH_HLEN, &new_ip6, len, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			    saddr, sizeof(struct in6_addr), 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
			    sid, sizeof(struct in6_addr), 0) < 0)
		return DROP_WRITE_ERROR;
	return 0;
}

static __always_inline int
srv6_handling(struct __ctx_buff *ctx, struct in6_addr *sid)
{
	__u16 inner_proto, new_payload_len, outer_proto = bpf_htons(ETH_P_IPV6);
	union v6addr nat46_prefix = NAT46_PREFIX;
	void *data, *data_end;
	struct in6_addr saddr;
	struct ipv6hdr *ip6;
	struct iphdr *ip4;
	__u8 nexthdr;
	int growth;

	if (!validate_ethertype(ctx, &inner_proto))
		return DROP_UNSUPPORTED_L2;

	switch (inner_proto) {
#  ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		/* Inner packet is IPv6. */
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
		nexthdr = IPPROTO_IPV6;
		new_payload_len = bpf_ntohs(ip6->payload_len) + sizeof(struct ipv6hdr);
		saddr = ip6->saddr;
		growth = sizeof(struct ipv6hdr);
		break;
#  endif /* ENABLE_IPV6 */
#  ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
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
		new_payload_len = bpf_ntohs(ip4->tot_len) - (ip4->ihl << 2) + sizeof(struct iphdr);
		/* We need to specify an SRv6 source address to which the
		 * reply will be sent. We use the IPv6-mapped IPv4 source
		 * address of the inner packet for that purpose.
		 */
		saddr.s6_addr32[0] = nat46_prefix.p1;
		/* TODO: Temporary inverted to avoid drop in kernel (cf. dcc32f4f). */
		saddr.s6_addr32[1] = nat46_prefix.p3;
		saddr.s6_addr32[2] = nat46_prefix.p2;
		saddr.s6_addr32[3] = bpf_htonl((bpf_ntohl(nat46_prefix.p4) & 0xFFFF0000) |
					       (bpf_ntohl(ip4->saddr) & 0xFFFF));

		/* We need to change skb->protocol and the corresponding packet
		 * field because the L3 protocol will now be IPv6.
		 */
		if (ctx_change_proto(ctx, outer_proto, 0) < 0)
			return DROP_WRITE_ERROR;
		if (ctx_store_bytes(ctx, offsetof(struct ethhdr, h_proto),
				    &outer_proto, sizeof(outer_proto), 0) < 0)
			return DROP_WRITE_ERROR;
		/* ctx_change_proto above grows the packet from IPv4 header
		 * length to IPv6 header length. It adds the additional space
		 * before the inner L3 header, in the same place we will later
		 * add the outer IPv6 header.
		 * Thus, deduce this space from the next packet growth.
		 */
		growth = sizeof(struct iphdr);
		break;
#  endif /* ENABLE_IPV4 */
	default:
		return DROP_INVALID;
	}

	return srv6_encapsulation(ctx, growth, new_payload_len, nexthdr,
				  &saddr, sid);
}

static __always_inline void
srv6_load_meta_sid(struct __ctx_buff *ctx, struct in6_addr *sid)
{
	sid->s6_addr32[0] = ctx_load_meta(ctx, CB_SRV6_SID_1);
	sid->s6_addr32[1] = ctx_load_meta(ctx, CB_SRV6_SID_2);
	sid->s6_addr32[2] = ctx_load_meta(ctx, CB_SRV6_SID_3);
	sid->s6_addr32[3] = ctx_load_meta(ctx, CB_SRV6_SID_4);
}

static __always_inline void
srv6_store_meta_sid(struct __ctx_buff *ctx, union v6addr *sid)
{
	ctx_store_meta(ctx, CB_SRV6_SID_1, sid->p1);
	ctx_store_meta(ctx, CB_SRV6_SID_2, sid->p2);
	ctx_store_meta(ctx, CB_SRV6_SID_3, sid->p3);
	ctx_store_meta(ctx, CB_SRV6_SID_4, sid->p4);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SRV6)
int tail_srv6_encap(struct __ctx_buff *ctx)
{
	struct in6_addr sid;
	int ret = 0;

	srv6_load_meta_sid(ctx, &sid);
	ret = srv6_handling(ctx, &sid);

	if (ret < 0)
		return send_drop_notify_error(ctx, SECLABEL, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);

	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, 0, 0, 0, 0, 0);
	return CTX_ACT_OK;
}
# endif /* SKIP_SRV6_HANDLING */

#endif /* ENABLE_SRV6 */
#endif /* __LIB_EGRESS_POLICIES_H_ */
