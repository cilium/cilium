/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_EGRESS_POLICIES_H_
#define __LIB_EGRESS_POLICIES_H_

#include "lib/identity.h"

#include "maps.h"

#ifdef ENABLE_EGRESS_GATEWAY

/* EGRESS_STATIC_PREFIX represents the size in bits of the static prefix part of
 * an egress policy key (i.e. the source IP).
 */
#define EGRESS_STATIC_PREFIX (sizeof(__be32) * 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)
/* These are special IP values in the CIDR 0.0.0.0/8 range that map to specific
 * case for in the egress gateway policies handling.
 */
#define EGRESS_GATEWAY_NO_GATEWAY (0)
#define EGRESS_GATEWAY_EXCLUDED_CIDR bpf_htonl(1)

static __always_inline
struct egress_gw_policy_entry *lookup_ip4_egress_gw_policy(__be32 saddr, __be32 daddr)
{
	struct egress_gw_policy_key key = {
		.lpm_key = { EGRESS_IPV4_PREFIX, {} },
		.saddr = saddr,
		.daddr = daddr,
	};
	return map_lookup_elem(&EGRESS_POLICY_MAP, &key);
}

static __always_inline
bool egress_gw_request_needs_redirect(struct iphdr *ip4, __u32 *tunnel_endpoint)
{
	struct egress_gw_policy_entry *egress_gw_policy;
	struct endpoint_info *gateway_node_ep;

	egress_gw_policy = lookup_ip4_egress_gw_policy(ip4->saddr, ip4->daddr);
	if (!egress_gw_policy)
		return false;

	switch (egress_gw_policy->gateway_ip) {
	case EGRESS_GATEWAY_NO_GATEWAY:
		/* If no gateway is found we return that the connection is
		 * "redirected" and the caller will handle this special case
		 * and drop the traffic.
		 */
		*tunnel_endpoint = EGRESS_GATEWAY_NO_GATEWAY;
		return true;
	case EGRESS_GATEWAY_EXCLUDED_CIDR:
		return false;
	}

	/* If the gateway node is the local node, then just let the
	 * packet go through, as it will be SNATed later on by
	 * handle_nat_fwd().
	 */
	gateway_node_ep = __lookup_ip4_endpoint(egress_gw_policy->gateway_ip);
	if (gateway_node_ep && (gateway_node_ep->flags & ENDPOINT_F_HOST))
		return false;

	*tunnel_endpoint = egress_gw_policy->gateway_ip;
	return true;
}

static __always_inline
bool egress_gw_snat_needed(struct iphdr *ip4, __be32 *snat_addr)
{
	struct egress_gw_policy_entry *egress_gw_policy;

	egress_gw_policy = lookup_ip4_egress_gw_policy(ip4->saddr, ip4->daddr);
	if (!egress_gw_policy)
		return false;

	if (egress_gw_policy->gateway_ip == EGRESS_GATEWAY_NO_GATEWAY ||
	    egress_gw_policy->gateway_ip == EGRESS_GATEWAY_EXCLUDED_CIDR)
		return false;

	*snat_addr = egress_gw_policy->egress_ip;
	return true;
}

static __always_inline
bool egress_gw_reply_needs_redirect(struct iphdr *ip4, __u32 *tunnel_endpoint,
				    __u32 *dst_sec_identity)
{
	struct egress_gw_policy_entry *egress_policy;
	struct remote_endpoint_info *info;

	/* Find a matching policy by looking up the reverse address tuple: */
	egress_policy = lookup_ip4_egress_gw_policy(ip4->daddr, ip4->saddr);
	if (!egress_policy)
		return false;

	if (egress_policy->gateway_ip == EGRESS_GATEWAY_NO_GATEWAY ||
	    egress_policy->gateway_ip == EGRESS_GATEWAY_EXCLUDED_CIDR)
		return false;

	info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN, 0);
	if (!info || info->tunnel_endpoint == 0)
		return false;

	*tunnel_endpoint = info->tunnel_endpoint;
	*dst_sec_identity = info->sec_identity;
	return true;
}

#endif /* ENABLE_EGRESS_GATEWAY */

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
			     ctx_adjust_hroom_flags()))
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
srv6_create_state_entry(struct __ctx_buff *ctx)
{
	struct srv6_ipv6_2tuple *outer_ips;
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	outer_ips = (struct srv6_ipv6_2tuple *)&ip6->saddr;

	switch (ip6->nexthdr) {
	case IPPROTO_IPV6: {
		struct ipv6hdr *inner = ip6 + 1;
		struct srv6_ipv6_2tuple *inner_ips;

		if ((void *)inner + sizeof(*inner) > data_end)
			return DROP_INVALID;
		inner_ips = (struct srv6_ipv6_2tuple *)&inner->saddr;

		if (map_update_elem(&SRV6_STATE_MAP6, inner_ips, outer_ips, 0) < 0)
			return DROP_INVALID;
	}
#  ifdef ENABLE_IPV4
	case IPPROTO_IPIP: {
		struct iphdr *inner = (struct iphdr *)(ip6 + 1);
		struct srv6_ipv4_2tuple *inner_ips;

		if ((void *)inner + sizeof(*inner) > data_end)
			return DROP_INVALID;
		inner_ips = (struct srv6_ipv4_2tuple *)&inner->saddr;

		if (map_update_elem(&SRV6_STATE_MAP4, inner_ips, outer_ips, 0) < 0)
			return DROP_INVALID;
	}
#  endif /* ENABLE_IPV4 */
	}

	return 0;
}

#  ifdef ENABLE_IPV4
static __always_inline struct srv6_ipv6_2tuple *
srv6_lookup_state_entry4(struct iphdr *ip4)
{
	return map_lookup_elem(&SRV6_STATE_MAP4,
			       (struct srv6_ipv4_2tuple *)&ip4->saddr);
}
#  endif /* ENABLE_IPV4 */

static __always_inline struct srv6_ipv6_2tuple *
srv6_lookup_state_entry6(struct ipv6hdr *ip6)
{
	return map_lookup_elem(&SRV6_STATE_MAP6,
			       (struct srv6_ipv6_2tuple *)&ip6->saddr);
}

static __always_inline int
srv6_handling4(struct __ctx_buff *ctx, union v6addr *src_sid,
	       struct in6_addr *dst_sid)
{
	__u16 new_payload_len, outer_proto = bpf_htons(ETH_P_IPV6);
	void *data, *data_end;
	struct iphdr *ip4;
	__u8 nexthdr;
	int growth;

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

#ifdef ENABLE_SRV6_SRH_ENCAP
	growth += sizeof(struct srv6_srh) + sizeof(struct in6_addr);
	new_payload_len += sizeof(struct srv6_srh) + sizeof(struct in6_addr);
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
srv6_handling(struct __ctx_buff *ctx, __u32 vrf_id, struct in6_addr *dst_sid)
{
	union v6addr *src_sid;
	void *data, *data_end;
	__u16 inner_proto;

	if (!validate_ethertype(ctx, &inner_proto))
		return DROP_UNSUPPORTED_L2;

	switch (inner_proto) {
#  ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6): {
		struct ipv6hdr *ip6;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		src_sid = srv6_lookup_policy6(vrf_id, &ip6->saddr);
		if (!src_sid)
			return DROP_NO_SID;
		return srv6_handling6(ctx, src_sid, dst_sid);
	}
#  endif /* ENABLE_IPV6 */
#  ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		struct iphdr *ip4;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		src_sid = srv6_lookup_policy4(vrf_id, ip4->saddr);
		if (!src_sid)
			return DROP_NO_SID;
		return srv6_handling4(ctx, src_sid, dst_sid);
	}
#  endif /* ENABLE_IPV4 */
	default:
		return DROP_INVALID;
	}
}

static __always_inline int
srv6_reply(struct __ctx_buff *ctx)
{
	struct srv6_ipv6_2tuple *outer_ips;
	struct iphdr *ip4 __maybe_unused;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		outer_ips = srv6_lookup_state_entry6(ip6);
		if (!outer_ips)
			return DROP_MISSING_SRV6_STATE;

		return srv6_handling6(ctx, &outer_ips->src,
				      (struct in6_addr *)&outer_ips->dst);
#  ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		outer_ips = srv6_lookup_state_entry4(ip4);
		if (!outer_ips)
			return DROP_MISSING_SRV6_STATE;

		return srv6_handling4(ctx, &outer_ips->src,
				      (struct in6_addr *)&outer_ips->dst);
#  endif /* ENABLE_IPV4 */
	}

	return CTX_ACT_OK;
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
srv6_store_meta_sid(struct __ctx_buff *ctx, const union v6addr *sid)
{
	ctx_store_meta(ctx, CB_SRV6_SID_1, sid->p1);
	ctx_store_meta(ctx, CB_SRV6_SID_2, sid->p2);
	ctx_store_meta(ctx, CB_SRV6_SID_3, sid->p3);
	ctx_store_meta(ctx, CB_SRV6_SID_4, sid->p4);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SRV6_ENCAP)
int tail_srv6_encap(struct __ctx_buff *ctx)
{
	struct in6_addr dst_sid;
	__u32 vrf_id;
	int ret = 0;

	srv6_load_meta_sid(ctx, &dst_sid);
	vrf_id = ctx_load_meta(ctx, CB_SRV6_VRF_ID);

	ret = srv6_handling(ctx, vrf_id, &dst_sid);

	if (ret < 0)
		return send_drop_notify_error(ctx, SECLABEL, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);

	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, 0, 0, 0,
			  TRACE_REASON_UNKNOWN, 0);
	return CTX_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SRV6_DECAP)
int tail_srv6_decap(struct __ctx_buff *ctx)
{
	int ret = 0;

	ret = srv6_create_state_entry(ctx);
	if (ret < 0)
		goto error_drop;

	ret = srv6_decapsulation(ctx);
	if (ret < 0)
		goto error_drop;

	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, 0, 0, 0,
			  TRACE_REASON_UNKNOWN, 0);
	return CTX_ACT_OK;
error_drop:
		return send_drop_notify_error(ctx, SECLABEL, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SRV6_REPLY)
int tail_srv6_reply(struct __ctx_buff *ctx)
{
	int ret;

	ret = srv6_reply(ctx);
	if (ret < 0)
		return send_drop_notify_error(ctx, SECLABEL, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);
	return CTX_ACT_OK;
}
# endif /* SKIP_SRV6_HANDLING */
#endif /* ENABLE_SRV6 */
#endif /* __LIB_EGRESS_POLICIES_H_ */
