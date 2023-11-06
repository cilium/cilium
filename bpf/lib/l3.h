/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_L3_H_
#define __LIB_L3_H_

#include "common.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eps.h"
#include "eth.h"
#include "dbg.h"
#include "l4.h"
#include "icmp6.h"
#include "csum.h"

/*
 * When the host routing is enabled we need to check policies at source, as in
 * this case the skb is delivered directly to pod's namespace and the ingress
 * policy (the cil_to_container BPF program) is bypassed.
 */
#if defined(ENABLE_ENDPOINT_ROUTES) && defined(ENABLE_HOST_ROUTING)
#  ifndef FORCE_LOCAL_POLICY_EVAL_AT_SOURCE
#  define FORCE_LOCAL_POLICY_EVAL_AT_SOURCE
#  endif
#endif

#ifdef ENABLE_IPV6
static __always_inline int ipv6_l3(struct __ctx_buff *ctx, int l3_off,
				   const __u8 *smac, const __u8 *dmac,
				   __u8 direction)
{
	int ret;

	ret = ipv6_dec_hoplimit(ctx, l3_off);
	if (IS_ERR(ret)) {
		if (ret == DROP_TTL_EXCEEDED)
			return icmp6_send_time_exceeded(ctx, l3_off, direction);

		return ret;
	}

	if (smac && eth_store_saddr(ctx, smac, 0) < 0)
		return DROP_WRITE_ERROR;
	if (dmac && eth_store_daddr(ctx, dmac, 0) < 0)
		return DROP_WRITE_ERROR;

	return CTX_ACT_OK;
}
#endif /* ENABLE_IPV6 */

static __always_inline int ipv4_l3(struct __ctx_buff *ctx, int l3_off,
				   const __u8 *smac, const __u8 *dmac,
				   struct iphdr *ip4)
{
	int ret;

	ret = ipv4_dec_ttl(ctx, l3_off, ip4);
	/* FIXME: Send ICMP TTL */
	if (IS_ERR(ret))
		return ret;

	if (smac && eth_store_saddr(ctx, smac, 0) < 0)
		return DROP_WRITE_ERROR;
	if (dmac && eth_store_daddr(ctx, dmac, 0) < 0)
		return DROP_WRITE_ERROR;

	return CTX_ACT_OK;
}

#ifndef SKIP_POLICY_MAP
static __always_inline int
l3_local_delivery(struct __ctx_buff *ctx, __u32 seclabel,
		  const struct endpoint_info *ep __maybe_unused,
		  __u8 direction __maybe_unused,
		  bool from_host __maybe_unused, bool hairpin_flow __maybe_unused,
		  bool from_tunnel __maybe_unused, __u32 cluster_id __maybe_unused)
{
#ifdef LOCAL_DELIVERY_METRICS
	/*
	 * Special LXC case for updating egress forwarding metrics.
	 * Note that the packet could still be dropped but it would show up
	 * as an ingress drop counter in metrics.
	 */
	update_metrics(ctx_full_len(ctx), direction, REASON_FORWARDED);
#endif

#if defined(USE_BPF_PROG_FOR_INGRESS_POLICY) && \
	!defined(FORCE_LOCAL_POLICY_EVAL_AT_SOURCE)
	set_identity_mark(ctx, seclabel);

# if defined(IS_BPF_OVERLAY) && !defined(ENABLE_NODEPORT)
	/* In tunneling mode, we execute this code to send the packet from
	 * cilium_vxlan to lxc*. If we're using kube-proxy, we don't want to use
	 * redirect() because that would bypass conntrack and the reverse DNAT.
	 * Thus, we send packets to the stack, but since they have the wrong
	 * Ethernet addresses, we need to mark them as PACKET_HOST or the kernel
	 * will drop them.
	 */
	ctx_change_type(ctx, PACKET_HOST);
	return CTX_ACT_OK;
# else
	return redirect_ep(ctx, ep->ifindex, from_host);
# endif /* IS_BPF_OVERLAY && !ENABLE_NODEPORT */
#else
# ifndef DISABLE_LOOPBACK_LB
	/* Skip ingress policy enforcement for hairpin traffic. As the hairpin
	 * traffic is destined to a local pod (more specifically, the same pod
	 * the traffic originated from) we skip the tail call for ingress policy
	 * enforcement, and directly redirect it to the endpoint.
	 */
	if (unlikely(hairpin_flow))
		return redirect_ep(ctx, ep->ifindex, from_host);
# endif /* DISABLE_LOOPBACK_LB */

	/* Jumps to destination pod's BPF program to enforce ingress policies. */
	ctx_store_meta(ctx, CB_SRC_LABEL, seclabel);
	ctx_store_meta(ctx, CB_IFINDEX, ep->ifindex);
	ctx_store_meta(ctx, CB_FROM_HOST, from_host ? 1 : 0);
	ctx_store_meta(ctx, CB_FROM_TUNNEL, from_tunnel ? 1 : 0);
	ctx_store_meta(ctx, CB_CLUSTER_ID_INGRESS, cluster_id);

	tail_call_dynamic(ctx, &POLICY_CALL_MAP, ep->lxc_id);
	return DROP_MISSED_TAIL_CALL;
#endif
}

#ifdef ENABLE_IPV6
/* Performs IPv6 L2/L3 handling and delivers the packet to the destination pod
 * on the same node, either via the stack or via a redirect call.
 * Depending on the configuration, it may also enforce ingress policies for the
 * destination pod via a tail call.
 */
static __always_inline int ipv6_local_delivery(struct __ctx_buff *ctx, int l3_off,
					       __u32 seclabel,
					       const struct endpoint_info *ep,
					       __u8 direction, bool from_host)
{
	mac_t router_mac = ep->node_mac;
	mac_t lxc_mac = ep->mac;
	int ret;

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);

	ret = ipv6_l3(ctx, l3_off, (__u8 *)&router_mac, (__u8 *)&lxc_mac, direction);
	if (ret != CTX_ACT_OK)
		return ret;

	return l3_local_delivery(ctx, seclabel, ep, direction, from_host, false,
				 false, 0);
}
#endif /* ENABLE_IPV6 */

/* Performs IPv4 L2/L3 handling and delivers the packet to the destination pod
 * on the same node, either via the stack or via a redirect call.
 * Depending on the configuration, it may also enforce ingress policies for the
 * destination pod via a tail call.
 */
static __always_inline int ipv4_local_delivery(struct __ctx_buff *ctx, int l3_off,
					       __u32 seclabel, struct iphdr *ip4,
					       const struct endpoint_info *ep,
					       __u8 direction, bool from_host,
					       bool hairpin_flow, bool from_tunnel,
					       __u32 cluster_id)
{
	mac_t router_mac = ep->node_mac;
	mac_t lxc_mac = ep->mac;
	int ret;

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);

	ret = ipv4_l3(ctx, l3_off, (__u8 *) &router_mac, (__u8 *) &lxc_mac, ip4);
	if (ret != CTX_ACT_OK)
		return ret;

	return l3_local_delivery(ctx, seclabel, ep, direction, from_host, hairpin_flow,
				 from_tunnel, cluster_id);
}
#endif /* SKIP_POLICY_MAP */

#endif
