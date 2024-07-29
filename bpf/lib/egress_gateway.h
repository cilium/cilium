/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/fib.h"
#include "lib/identity.h"
#include "lib/overloadable.h"

#include "encap.h"

#ifdef ENABLE_EGRESS_GATEWAY_COMMON

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
int egress_gw_fib_lookup_and_redirect(struct __ctx_buff *ctx, __be32 egress_ip, __be32 daddr,
				      __s8 *ext_err)
{
	struct bpf_fib_lookup_padded fib_params = {};
	int oif = 0;
	int ret;

	ret = (__s8)fib_lookup_v4(ctx, &fib_params, egress_ip, daddr, 0);

	switch (ret) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		break;
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		/* Don't redirect if we can't update the L2 DMAC: */
		if (!neigh_resolver_available())
			return CTX_ACT_OK;

		/* Don't redirect without a valid target ifindex: */
		if (!is_defined(HAVE_FIB_IFINDEX))
			return CTX_ACT_OK;
		break;
	default:
		*ext_err = (__s8)ret;
		return DROP_NO_FIB;
	}

	/* Skip redirect in to-netdev if we stay on the same iface: */
	if (is_defined(IS_BPF_HOST) && fib_params.l.ifindex == ctx_get_ifindex(ctx))
		return CTX_ACT_OK;

	return fib_do_redirect(ctx, true, &fib_params, false, ret, &oif, ext_err);
}

#ifdef ENABLE_EGRESS_GATEWAY
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct egress_gw_policy_key);
	__type(value, struct egress_gw_policy_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EGRESS_POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} EGRESS_POLICY_MAP __section_maps_btf;

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
#endif /* ENABLE_EGRESS_GATEWAY */

static __always_inline int
egress_gw_request_needs_redirect(struct ipv4_ct_tuple *rtuple __maybe_unused,
				 __be32 *gateway_ip __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	struct egress_gw_policy_entry *egress_gw_policy;

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
			   __be32 *snat_addr __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	struct egress_gw_policy_entry *egress_gw_policy;

	egress_gw_policy = lookup_ip4_egress_gw_policy(saddr, daddr);
	if (!egress_gw_policy)
		return false;

	if (egress_gw_policy->gateway_ip == EGRESS_GATEWAY_NO_GATEWAY ||
	    egress_gw_policy->gateway_ip == EGRESS_GATEWAY_EXCLUDED_CIDR)
		return false;

	*snat_addr = egress_gw_policy->egress_ip;
	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY */
}

static __always_inline
bool egress_gw_reply_matches_policy(struct iphdr *ip4 __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	struct egress_gw_policy_entry *egress_policy;

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
 * @arg ct_status	CT result, to identify egressing connections
 * @arg gateway_ip	returns the gateway node's IP
 *
 * Returns
 * * CTX_ACT_REDIRECT if a matching policy entry was found,
 * * CTX_ACT_OK if no EGW logic should be applied,
 * * DROP_* for error conditions.
 */
static __always_inline int
egress_gw_request_needs_redirect_hook(struct ipv4_ct_tuple *rtuple,
				      enum ct_status ct_status,
				      __be32 *gateway_ip)
{
#if defined(IS_BPF_LXC)
	/* If the packet is a reply or is related, it means that outside
	 * has initiated the connection, and so we should skip egress
	 * gateway, since an egress policy is only matching connections
	 * originating from a pod.
	 */
	if (ct_status == CT_REPLY || ct_status == CT_RELATED)
		return CTX_ACT_OK;
#else
	/* We lookup CT in forward direction at to-netdev and expect to
	 * get CT_ESTABLISHED for outbound connection as
	 * from_container should have already created a CT entry.
	 * If we get CT_NEW here, it's an indication that it's a reply
	 * for inbound connection or host-level outbound connection.
	 * We don't expect to receive any other ct_status here.
	 */
	if (ct_status != CT_ESTABLISHED)
		return CTX_ACT_OK;
#endif

	return egress_gw_request_needs_redirect(rtuple, gateway_ip);
}

static __always_inline
bool egress_gw_snat_needed_hook(__be32 saddr, __be32 daddr, __be32 *snat_addr)
{
	struct remote_endpoint_info *remote_ep;

	remote_ep = lookup_ip4_remote_endpoint(daddr, 0);
	/* If the packet is destined to an entity inside the cluster, either EP
	 * or node, skip SNAT since only traffic leaving the cluster is supposed
	 * to be masqueraded with an egress IP.
	 */
	if (remote_ep &&
	    identity_is_cluster(remote_ep->sec_identity))
		return false;

	return egress_gw_snat_needed(saddr, daddr, snat_addr);
}

static __always_inline
bool egress_gw_reply_needs_redirect_hook(struct iphdr *ip4, __u32 *tunnel_endpoint,
					 __u32 *dst_sec_identity)
{
	if (egress_gw_reply_matches_policy(ip4)) {
		struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (!info || info->tunnel_endpoint == 0)
			return false;

		*tunnel_endpoint = info->tunnel_endpoint;
		*dst_sec_identity = info->sec_identity;

		return true;
	}

	return false;
}

static __always_inline
int egress_gw_handle_packet(struct __ctx_buff *ctx,
			    struct ipv4_ct_tuple *tuple,
			    enum ct_status ct_status,
			    __u32 src_sec_identity, __u32 dst_sec_identity,
			    const struct trace_ctx *trace)
{
	struct endpoint_info *gateway_node_ep;
	__be32 gateway_ip = 0;
	int ret;

	/* If the packet is destined to an entity inside the cluster,
	 * either EP or node, it should not be forwarded to an egress
	 * gateway since only traffic leaving the cluster is supposed to
	 * be masqueraded with an egress IP.
	 */
	if (identity_is_cluster(dst_sec_identity))
		return CTX_ACT_OK;

	ret = egress_gw_request_needs_redirect_hook(tuple, ct_status, &gateway_ip);
	if (IS_ERR(ret))
		return ret;

	if (ret == CTX_ACT_OK)
		return ret;

	/* If the gateway node is the local node, then just let the
	 * packet go through, as it will be SNATed later on by
	 * handle_nat_fwd().
	 */
	gateway_node_ep = __lookup_ip4_endpoint(gateway_ip);
	if (gateway_node_ep && (gateway_node_ep->flags & ENDPOINT_F_HOST))
		return CTX_ACT_OK;

	/* Send the packet to egress gateway node through a tunnel. */
	return __encap_and_redirect_with_nodeid(ctx, 0, gateway_ip,
						src_sec_identity, dst_sec_identity,
						NOT_VTEP_DST, trace);
}

#endif /* ENABLE_EGRESS_GATEWAY_COMMON */
