/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_EGRESS_GATEWAY_H_
#define __LIB_EGRESS_GATEWAY_H_

#include "lib/fib.h"
#include "lib/identity.h"
#include "lib/overloadable.h"

#include "maps.h"

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
	__u32 old_oif = ctx_get_ifindex(ctx);

	*ext_err = (__s8)fib_lookup_v4(ctx, &fib_params, egress_ip, daddr, 0);

	if (*ext_err != BPF_FIB_LKUP_RET_SUCCESS && *ext_err != BPF_FIB_LKUP_RET_NO_NEIGH)
		return DROP_NO_FIB;

	if (old_oif == fib_params.l.ifindex)
		return CTX_ACT_OK;

	return fib_do_redirect(ctx, true, &fib_params, ext_err, (int *)&old_oif);
}

#ifdef ENABLE_EGRESS_GATEWAY
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

static __always_inline
bool egress_gw_request_needs_redirect(struct ipv4_ct_tuple *rtuple __maybe_unused,
				      enum ct_status ct_status __maybe_unused,
				      __u32 *tunnel_endpoint __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	struct egress_gw_policy_entry *egress_gw_policy;
	struct endpoint_info *gateway_node_ep;

	/* If the packet is a reply or is related, it means that outside
	* has initiated the connection, and so we should skip egress
	* gateway, since an egress policy is only matching connections
	* originating from a pod.
	*/
	if (ct_status == CT_REPLY || ct_status == CT_RELATED)
		return false;

	egress_gw_policy = lookup_ip4_egress_gw_policy(ipv4_ct_reverse_tuple_saddr(rtuple),
						       ipv4_ct_reverse_tuple_daddr(rtuple));
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
#else
	return false;
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
bool egress_gw_reply_needs_redirect(struct iphdr *ip4 __maybe_unused,
				    __u32 *tunnel_endpoint __maybe_unused,
				    __u32 *dst_sec_identity __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	struct egress_gw_policy_entry *egress_policy;
	struct remote_endpoint_info *info;

	/* Find a matching policy by looking up the reverse address tuple: */
	egress_policy = lookup_ip4_egress_gw_policy(ip4->daddr, ip4->saddr);
	if (!egress_policy)
		return false;

	if (egress_policy->gateway_ip == EGRESS_GATEWAY_NO_GATEWAY ||
	    egress_policy->gateway_ip == EGRESS_GATEWAY_EXCLUDED_CIDR)
		return false;

	info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
	if (!info || info->tunnel_endpoint == 0)
		return false;

	*tunnel_endpoint = info->tunnel_endpoint;
	*dst_sec_identity = info->sec_identity;
	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY */
}

static __always_inline
bool egress_gw_request_needs_redirect_hook(struct ipv4_ct_tuple *rtuple,
					   enum ct_status ct_status,
					   __u32 *tunnel_endpoint)
{
	return egress_gw_request_needs_redirect(rtuple, ct_status, tunnel_endpoint);
}

static __always_inline
bool egress_gw_snat_needed_hook(__be32 saddr, __be32 daddr, __be32 *snat_addr)
{
	return egress_gw_snat_needed(saddr, daddr, snat_addr);
}

static __always_inline
bool egress_gw_reply_needs_redirect_hook(struct iphdr *ip4, __u32 *tunnel_endpoint,
					 __u32 *dst_sec_identity)
{
	return egress_gw_reply_needs_redirect(ip4, tunnel_endpoint, dst_sec_identity);
}

#endif /* ENABLE_EGRESS_GATEWAY_COMMON */
#endif /* __LIB_EGRESS_GATEWAY_H_ */
