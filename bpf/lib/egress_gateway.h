/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/fib.h"
#include "lib/identity.h"
#include "lib/overloadable.h"

#include "encap.h"
#include "eps.h"

struct egress_gw_policy_key {
	struct bpf_lpm_trie_key lpm_key;
	__be32 saddr;
	__be32 daddr;
};

struct egress_gw_policy_entry {
	__be32 egress_ip;
	__be32 gateway_ip;
};

struct egress_gw_policy_key6 {
	struct bpf_lpm_trie_key lpm_key;
	union v6addr saddr;
	union v6addr daddr;
};

struct egress_gw_policy_entry6 {
	union v6addr egress_ip;
	__be32 gateway_ip;
	__u32 reserved[3]; /* reserved for future extension, e.g. v6 gateway_ip */
	__u32 egress_ifindex;
	__u32 reserved2; /* for even more future extension */
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct egress_gw_policy_key);
	__type(value, struct egress_gw_policy_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EGRESS_POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_egress_gw_policy_v4 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct egress_gw_policy_key6);
	__type(value, struct egress_gw_policy_entry6);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EGRESS_POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_egress_gw_policy_v6 __section_maps_btf;

#ifdef ENABLE_EGRESS_GATEWAY_COMMON

/* EGRESS_STATIC_PREFIX represents the size in bits of the static prefix part of
 * an egress policy key (i.e. the source IP).
 */
#define EGRESS_STATIC_PREFIX_V4 (sizeof(__be32) * 8)
#define EGRESS_STATIC_PREFIX_V6 (sizeof(union v6addr) * 8)
#define EGRESS_PREFIX_LEN_V4(PREFIX) (EGRESS_STATIC_PREFIX_V4 + (PREFIX))
#define EGRESS_PREFIX_LEN_V6(PREFIX) (EGRESS_STATIC_PREFIX_V6 + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN_V4(32)
#define EGRESS_IPV6_PREFIX EGRESS_PREFIX_LEN_V6(128)

/* These are special IP values in the CIDR 0.0.0.0/8 range that map to specific
 * case for in the egress gateway policies handling.
 */

/* Special values in the policy_entry->gateway_ip: */
#define EGRESS_GATEWAY_NO_GATEWAY (0)
#define EGRESS_GATEWAY_EXCLUDED_CIDR bpf_htonl(1)

/* Special values in the policy_entry->egress_ip: */
#define EGRESS_GATEWAY_NO_EGRESS_IP (0)
#define EGRESS_GATEWAY_NO_EGRESS_IP_V6 ((union v6addr){{0, 0, 0, 0}})

static __always_inline
int egress_gw_fib_lookup_and_redirect(struct __ctx_buff *ctx, __be32 egress_ip, __be32 daddr,
				      __u32 egress_ifindex, __s8 *ext_err)
{
	struct bpf_fib_lookup_padded fib_params = {};
	__u32 oif;
	int ret;

	/* Immediate redirect to egress_ifindex requires L2 resolution.
	 * Fall back to FIB lookup on older kernels.
	 */
	if (egress_ifindex && neigh_resolver_without_nh_available())
		return redirect_neigh(egress_ifindex, NULL, 0, 0);

	ret = (__s8)fib_lookup_v4(ctx, &fib_params, egress_ip, daddr, 0);

	switch (ret) {
	case BPF_FIB_LKUP_RET_SUCCESS:
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		break;
	default:
		*ext_err = (__s8)ret;
		return DROP_NO_FIB;
	}

	oif = fib_params.l.ifindex;

	/* Skip redirect in to-netdev if we stay on the same iface: */
	if (is_defined(IS_BPF_HOST) && oif == ctx_get_ifindex(ctx))
		return CTX_ACT_OK;

	return fib_do_redirect(ctx, true, &fib_params, false, ret, oif, ext_err);
}

# ifdef ENABLE_EGRESS_GATEWAY
static __always_inline const struct egress_gw_policy_entry *
lookup_ip4_egress_gw_policy(__be32 saddr, __be32 daddr)
{
	struct egress_gw_policy_key key = {
		.lpm_key = { EGRESS_IPV4_PREFIX, {} },
		.saddr = saddr,
		.daddr = daddr,
	};
	return map_lookup_elem(&cilium_egress_gw_policy_v4, &key);
}
# endif /* ENABLE_EGRESS_GATEWAY */

static __always_inline int
egress_gw_request_needs_redirect(struct ipv4_ct_tuple *rtuple __maybe_unused,
				 __be32 *gateway_ip __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	const struct egress_gw_policy_entry *egress_gw_policy;

	egress_gw_policy = lookup_ip4_egress_gw_policy(ipv4_ct_reverse_tuple_saddr(rtuple),
						       ipv4_ct_reverse_tuple_daddr(rtuple));
	if (!egress_gw_policy)
		return CTX_ACT_OK;

	switch (egress_gw_policy->gateway_ip) {
	case EGRESS_GATEWAY_NO_GATEWAY:
		/* If no gateway is found, drop the packet. */
		return DROP_NO_EGRESS_GATEWAY;
	case EGRESS_GATEWAY_EXCLUDED_CIDR:
		return CTX_ACT_OK;
	}

	*gateway_ip = egress_gw_policy->gateway_ip;
	return CTX_ACT_REDIRECT;
#else
	return CTX_ACT_OK;
#endif /* ENABLE_EGRESS_GATEWAY */
}

static __always_inline
bool egress_gw_snat_needed(__be32 saddr __maybe_unused,
			   __be32 daddr __maybe_unused,
			   __be32 *snat_addr __maybe_unused,
			   __u32 *egress_ifindex __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	const struct egress_gw_policy_entry *egress_gw_policy;

	egress_gw_policy = lookup_ip4_egress_gw_policy(saddr, daddr);
	if (!egress_gw_policy)
		return false;

	if (egress_gw_policy->gateway_ip == EGRESS_GATEWAY_NO_GATEWAY ||
	    egress_gw_policy->gateway_ip == EGRESS_GATEWAY_EXCLUDED_CIDR)
		return false;

	*snat_addr = egress_gw_policy->egress_ip;
#ifdef EGRESS_IFINDEX
	*egress_ifindex = EGRESS_IFINDEX;
#endif

	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY */
}

static __always_inline
bool egress_gw_reply_matches_policy(struct iphdr *ip4 __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	const struct egress_gw_policy_entry *egress_policy;

	/* Find a matching policy by looking up the reverse address tuple: */
	egress_policy = lookup_ip4_egress_gw_policy(ip4->daddr, ip4->saddr);
	if (!egress_policy)
		return false;

	if (egress_policy->gateway_ip == EGRESS_GATEWAY_NO_GATEWAY ||
	    egress_policy->gateway_ip == EGRESS_GATEWAY_EXCLUDED_CIDR)
		return false;

	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY */
}

/** Match a packet against EGW policy map, and return the gateway's IP.
 * @arg rtuple		CT tuple for the packet
 * @arg gateway_ip	returns the gateway node's IP
 *
 * Returns
 * * CTX_ACT_REDIRECT if a matching policy entry was found,
 * * CTX_ACT_OK if no EGW logic should be applied,
 * * DROP_* for error conditions.
 */
static __always_inline int
egress_gw_request_needs_redirect_hook(struct ipv4_ct_tuple *rtuple,
				      __be32 *gateway_ip)
{
	return egress_gw_request_needs_redirect(rtuple, gateway_ip);
}

static __always_inline
bool egress_gw_snat_needed_hook(__be32 saddr, __be32 daddr, __be32 *snat_addr,
				__u32 *egress_ifindex)
{
	const struct remote_endpoint_info *remote_ep;

	remote_ep = lookup_ip4_remote_endpoint(daddr, 0);
	/* If the packet is destined to an entity inside the cluster, either EP
	 * or node, skip SNAT since only traffic leaving the cluster is supposed
	 * to be masqueraded with an egress IP.
	 */
	if (remote_ep &&
	    identity_is_cluster(remote_ep->sec_identity))
		return false;

	return egress_gw_snat_needed(saddr, daddr, snat_addr, egress_ifindex);
}

static __always_inline
bool egress_gw_reply_needs_redirect_hook(struct iphdr *ip4, __u32 *tunnel_endpoint,
					 __u32 *dst_sec_identity)
{
	if (egress_gw_reply_matches_policy(ip4)) {
		const struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (!info || !info->flag_has_tunnel_ep)
			return false;

		*tunnel_endpoint = info->tunnel_endpoint.ip4;
		*dst_sec_identity = info->sec_identity;

		return true;
	}

	return false;
}

static __always_inline
int egress_gw_handle_packet(struct ipv4_ct_tuple *tuple,
			    __u32 dst_sec_identity, __be32 *gateway_ip)
{
	/* If the packet is destined to an entity inside the cluster,
	 * either EP or node, it should not be forwarded to an egress
	 * gateway since only traffic leaving the cluster is supposed to
	 * be masqueraded with an egress IP.
	 */
	if (identity_is_cluster(dst_sec_identity))
		return CTX_ACT_OK;

	return egress_gw_request_needs_redirect_hook(tuple, gateway_ip);
}

#ifdef ENABLE_IPV6
#ifdef ENABLE_EGRESS_GATEWAY
static __always_inline const struct egress_gw_policy_entry6 *
lookup_ip6_egress_gw_policy(const union v6addr *saddr, const union v6addr *daddr)
{
	struct egress_gw_policy_key6 key = {
		.lpm_key = { EGRESS_IPV6_PREFIX, {} },
		.saddr = *saddr,
		.daddr = *daddr,
	};
	return map_lookup_elem(&cilium_egress_gw_policy_v6, &key);
}
#endif /* ENABLE_EGRESS_GATEWAY */

static __always_inline int
egress_gw_request_needs_redirect_v6(struct ipv6_ct_tuple *rtuple __maybe_unused,
				    __be32 *gateway_ip __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	const struct egress_gw_policy_entry6 *egress_gw_policy;
	union v6addr saddr, daddr;

	saddr = ipv6_ct_reverse_tuple_saddr(rtuple);
	daddr = ipv6_ct_reverse_tuple_daddr(rtuple);

	egress_gw_policy = lookup_ip6_egress_gw_policy(&saddr, &daddr);
	if (!egress_gw_policy)
		return CTX_ACT_OK;

	switch (egress_gw_policy->gateway_ip) {
	case EGRESS_GATEWAY_NO_GATEWAY:
		/* If no gateway is found, drop the packet. */
		return DROP_NO_EGRESS_GATEWAY;
	case EGRESS_GATEWAY_EXCLUDED_CIDR:
		return CTX_ACT_OK;
	}

	*gateway_ip = egress_gw_policy->gateway_ip;
	return CTX_ACT_REDIRECT;
#else
	return CTX_ACT_OK;
#endif /* ENABLE_EGRESS_GATEWAY */
}

static __always_inline
bool egress_gw_snat_needed_v6(union v6addr *saddr __maybe_unused,
			      union v6addr *daddr __maybe_unused,
			      union v6addr *snat_addr __maybe_unused,
			      __u32 *egress_ifindex __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	const struct egress_gw_policy_entry6 *egress_gw_policy;

	egress_gw_policy = lookup_ip6_egress_gw_policy(saddr, daddr);
	if (!egress_gw_policy)
		return false;

	if (egress_gw_policy->gateway_ip == EGRESS_GATEWAY_NO_GATEWAY ||
	    egress_gw_policy->gateway_ip == EGRESS_GATEWAY_EXCLUDED_CIDR)
		return false;

	*snat_addr = egress_gw_policy->egress_ip;
	*egress_ifindex = egress_gw_policy->egress_ifindex;

	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY */
}

static __always_inline
bool egress_gw_reply_matches_policy_v6(struct ipv6hdr *ip6 __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	const struct egress_gw_policy_entry6 *egress_policy;

	egress_policy = lookup_ip6_egress_gw_policy((union v6addr *)&ip6->daddr,
						    (union v6addr *)&ip6->saddr);
	if (!egress_policy)
		return false;

	if (egress_policy->gateway_ip == EGRESS_GATEWAY_NO_GATEWAY ||
	    egress_policy->gateway_ip == EGRESS_GATEWAY_EXCLUDED_CIDR)
		return false;

	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY */
}

static __always_inline int
egress_gw_request_needs_redirect_hook_v6(struct ipv6_ct_tuple *rtuple,
					 __be32 *gateway_ip)
{
	return egress_gw_request_needs_redirect_v6(rtuple, gateway_ip);
}

static __always_inline
bool egress_gw_snat_needed_hook_v6(union v6addr *saddr, union v6addr *daddr,
				   union v6addr *snat_addr, __u32 *egress_ifindex)
{
	const struct remote_endpoint_info *remote_ep;

	remote_ep = lookup_ip6_remote_endpoint(daddr, 0);
	/* If the packet is destined to an entity inside the cluster, either EP
	 * or node, skip SNAT since only traffic leaving the cluster is supposed
	 * to be masqueraded with an egress IP.
	 */
	if (remote_ep && identity_is_cluster(remote_ep->sec_identity))
		return false;

	return egress_gw_snat_needed_v6(saddr, daddr, snat_addr, egress_ifindex);
}

static __always_inline
int egress_gw_fib_lookup_and_redirect_v6(struct __ctx_buff *ctx,
					 const union v6addr *egress_ip,
					 const union v6addr *daddr,
					 __u32 egress_ifindex, __s8 *ext_err)
{
	struct bpf_fib_lookup_padded fib_params = {};
	__u32 oif;
	int ret;

	if (egress_ifindex && neigh_resolver_without_nh_available())
		return redirect_neigh(egress_ifindex, NULL, 0, 0);

	ret = (__s8)fib_lookup_v6(ctx, &fib_params,
				  (struct in6_addr *)egress_ip,
				  (struct in6_addr *)daddr, 0);

	switch (ret) {
	case BPF_FIB_LKUP_RET_SUCCESS:
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		break;
	default:
		*ext_err = (__s8)ret;
		return DROP_NO_FIB;
	}

	oif = fib_params.l.ifindex;

	if (is_defined(IS_BPF_HOST) && oif == ctx_get_ifindex(ctx))
		return CTX_ACT_OK;

	return fib_do_redirect(ctx, true, &fib_params, false, ret, oif, ext_err);
}

static __always_inline
bool egress_gw_reply_needs_redirect_hook_v6(struct ipv6hdr *ip6,
					    const struct remote_endpoint_info **info)
{
	if (egress_gw_reply_matches_policy_v6(ip6)) {
		const struct remote_endpoint_info *egw_info;

		egw_info = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
		if (!egw_info || egw_info->tunnel_endpoint.ip4 == 0)
			return false;

		*info = egw_info;
		return true;
	}

	return false;
}

static __always_inline
int egress_gw_handle_packet_v6(struct ipv6_ct_tuple *tuple,
			       __u32 dst_sec_identity, __be32 *gateway_ip)
{
	/* If the packet is destined to an entity inside the cluster,
	 * either EP or node, it should not be forwarded to an egress
	 * gateway since only traffic leaving the cluster is supposed to
	 * be masqueraded with an egress IP.
	 */
	if (identity_is_cluster(dst_sec_identity))
		return CTX_ACT_OK;

	return egress_gw_request_needs_redirect_hook_v6(tuple, gateway_ip);
}
#endif /* ENABLE_IPV6 */

static __always_inline
int egress_gw_handle_request(struct __ctx_buff *ctx, __be16 proto,
			     __u32 src_sec_identity, __u32 dst_sec_identity,
			     struct trace_ctx *trace)
{
	struct remote_endpoint_info fake_info = {0};
	const struct endpoint_info *gateway_node_ep;
	__be32 gateway_ip = 0;
	void *data, *data_end;
	struct iphdr *ip4;
	struct ipv6hdr __maybe_unused *ip6;
	struct ipv4_ct_tuple tuple4 = {};
	struct ipv6_ct_tuple __maybe_unused tuple6 = {};
	int l4_off;
	const struct remote_endpoint_info *info;
	const struct endpoint_info *src_ep;
	bool is_reply;
	fraginfo_t fraginfo;
	int ret;

	if (src_sec_identity == HOST_ID)
		return CTX_ACT_OK;

	switch (proto) {
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		fraginfo = ipfrag_encode_ipv4(ip4);

		tuple4.nexthdr = ip4->protocol;
		tuple4.daddr = ip4->daddr;
		tuple4.saddr = ip4->saddr;

		l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
		ret = ct_extract_ports4(ctx, ip4, fraginfo, l4_off,
					CT_EGRESS, &tuple4);
		if (IS_ERR(ret)) {
			if (ret == DROP_CT_UNKNOWN_PROTO)
				return CTX_ACT_OK;
			return ret;
		}

		/* Only handle outbound connections: */
		is_reply = ct_is_reply4(get_ct_map4(&tuple4), &tuple4);
		if (is_reply)
			return CTX_ACT_OK;

		src_ep = __lookup_ip4_endpoint(ip4->saddr);
		if (src_ep)
			src_sec_identity = src_ep->sec_id;

		info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (info)
			dst_sec_identity = info->sec_identity;

		/* lower-level code expects CT tuple to be flipped: */
		__ipv4_ct_tuple_reverse(&tuple4);
		ret = egress_gw_handle_packet(&tuple4, dst_sec_identity,
					      &gateway_ip);
		break;
#if defined(ENABLE_IPV6)
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		tuple6.nexthdr = ip6->nexthdr;
		ipv6_addr_copy(&tuple6.daddr, (union v6addr *)&ip6->daddr);
		ipv6_addr_copy(&tuple6.saddr, (union v6addr *)&ip6->saddr);

		ret = ipv6_hdrlen_with_fraginfo(ctx, &tuple6.nexthdr, &fraginfo);
		if (ret < 0)
			return ret;

		l4_off = ETH_HLEN + ret;
		ret = ct_extract_ports6(ctx, ip6, fraginfo, l4_off,
					CT_EGRESS, &tuple6);
		if (IS_ERR(ret)) {
			if (ret == DROP_CT_UNKNOWN_PROTO)
				return CTX_ACT_OK;
			return ret;
		}

		/* Only handle outbound connections: */
		is_reply = ct_is_reply6(get_ct_map6(&tuple6), &tuple6);
		if (is_reply)
			return CTX_ACT_OK;

		src_ep = __lookup_ip6_endpoint((union v6addr *)&ip6->saddr);
		if (src_ep)
			src_sec_identity = src_ep->sec_id;

		info = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
		if (info)
			dst_sec_identity = info->sec_identity;

		/* lower-level code expects CT tuple to be flipped: */
		__ipv6_ct_tuple_reverse(&tuple6);
		ret = egress_gw_handle_packet_v6(&tuple6, dst_sec_identity,
						 &gateway_ip);
		break;
#endif
	default:
		return CTX_ACT_OK;
	}

	if (ret != CTX_ACT_REDIRECT)
		return ret;

	/* If the selected gateway node is the local node, then we don't
	 * need to redirect the packet.
	 */
	gateway_node_ep = __lookup_ip4_endpoint(gateway_ip);
	if (gateway_node_ep && (gateway_node_ep->flags & ENDPOINT_F_HOST))
		return CTX_ACT_OK;

	/* Send the packet to egress gateway node through a tunnel. */
	fake_info.tunnel_endpoint.ip4 = gateway_ip;
	fake_info.flag_has_tunnel_ep = true;
	return encap_and_redirect_with_nodeid(ctx, &fake_info,
					      src_sec_identity, dst_sec_identity,
					      trace, proto);
}

#endif /* ENABLE_EGRESS_GATEWAY_COMMON */
