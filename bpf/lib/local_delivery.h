/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "dbg.h"
#include "l3.h"
#include "token_bucket.h"

/* Global map to jump into policy enforcement of sending endpoint */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, POLICY_PROG_MAP_SIZE);
} cilium_egresscall_policy __section_maps_btf __do_not_prune;

static __always_inline __must_check int
tail_call_egress_policy(struct __ctx_buff *ctx, __u16 endpoint_id)
{
	tail_call_dynamic(ctx, &cilium_egresscall_policy, endpoint_id);
	/* same issue as for the cilium_call_policy calls */
	return DROP_EP_NOT_READY;
}

/* Global map to jump into policy enforcement of receiving endpoint */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, POLICY_PROG_MAP_SIZE);
} cilium_call_policy __section_maps_btf __do_not_prune;

static __always_inline __must_check int
tail_call_policy(struct __ctx_buff *ctx, __u16 endpoint_id)
{
	if (__builtin_constant_p(endpoint_id)) {
		tail_call_static(ctx, cilium_call_policy, endpoint_id);
	} else {
		tail_call_dynamic(ctx, &cilium_call_policy, endpoint_id);
	}

	/* When forwarding from a BPF program to some endpoint,
	 * there are inherent races that can result in the endpoint's
	 * policy program being unavailable (eg. if the endpoint is
	 * terminating).
	 */
	return DROP_EP_NOT_READY;
}

static __always_inline int redirect_ep(struct __ctx_buff *ctx __maybe_unused,
				       int ifindex __maybe_unused,
				       bool needs_backlog __maybe_unused,
				       bool from_tunnel)
{
	/* Going via CPU backlog queue (aka needs_backlog) is required
	 * whenever we cannot do a fast ingress -> ingress switch but
	 * instead need an ingress -> egress netns traversal or vice
	 * versa.
	 *
	 * This is also the case if BPF host routing is disabled, or if
	 * we are currently on egress which is indicated by ingress_ifindex
	 * being 0. The latter is cleared upon skb scrubbing.
	 *
	 * In case of netkit, we're on the egress side and need a regular
	 * redirect to the peer device's ifindex. In case of veth we're
	 * on ingress and need a redirect peer to get to the target. Both
	 * only traverse the CPU backlog queue once. In case of phys ->
	 * Pod, the ingress_ifindex is > 0 and in both device types we
	 * do want a redirect peer into the target Pod's netns.
	 */
	if (needs_backlog || !is_defined(ENABLE_HOST_ROUTING) ||
	    ctx_get_ingress_ifindex(ctx) == 0) {
		return (int)ctx_redirect(ctx, ifindex, 0);
	}

	/* When coming from overlay, we need to set packet type
	 * to HOST as otherwise we might get dropped in IP layer.
	 */
	if (from_tunnel)
		ctx_change_type(ctx, PACKET_HOST);

	return ctx_redirect_peer(ctx, ifindex, 0);
}

/* Defines the calling convention for bpf_lxc's ingress policy tail-call.
 * Note that skb->tc_index is also passed through.
 *
 * As the callers (from-overlay, from-netdev, ...) are re-generated independently
 * from the policy tail-call of the inidividual endpoints, any change to this code
 * needs to be introduced with compatibility in mind.
 */
static __always_inline void
local_delivery_fill_meta(struct __ctx_buff *ctx, __u32 seclabel,
			 bool delivery_redirect, bool from_host,
			 bool from_tunnel, __u32 cluster_id)
{
	ctx_store_meta(ctx, CB_SRC_LABEL, seclabel);
	ctx_store_meta(ctx, CB_DELIVERY_REDIRECT, delivery_redirect ? 1 : 0);
	ctx_store_meta(ctx, CB_FROM_HOST, from_host ? 1 : 0);
	ctx_store_meta(ctx, CB_FROM_TUNNEL, from_tunnel ? 1 : 0);
	ctx_store_meta(ctx, CB_CLUSTER_ID_INGRESS, cluster_id);
}

static __always_inline int
local_delivery(struct __ctx_buff *ctx, __u32 seclabel,
	       __u32 magic __maybe_unused,
	       const struct endpoint_info *ep __maybe_unused,
	       __u8 direction __maybe_unused,
	       bool from_host __maybe_unused,
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

	if (direction == METRIC_INGRESS && !from_host) {
		/*
		 * Traffic from nodes, local endpoints, or hairpin connections is ignored
		 */
		int ret;

		ret = accept(ctx, ep->lxc_id);
		if (IS_ERR(ret))
			return ret;
	}

/*
 * When BPF host routing is enabled we need to check policies at source, as in
 * this case the skb is delivered directly to pod's namespace and the ingress
 * policy (the cil_to_container BPF program) is bypassed.
 */
#if defined(USE_BPF_PROG_FOR_INGRESS_POLICY) && \
    !defined(ENABLE_HOST_ROUTING)
	set_identity_mark(ctx, seclabel, magic);

# if !defined(ENABLE_NODEPORT)
	/* In tunneling mode, we execute this code to send the packet from
	 * cilium_vxlan to lxc*. If we're using kube-proxy, we don't want to use
	 * redirect() because that would bypass conntrack and the reverse DNAT.
	 * Thus, we send packets to the stack, but since they have the wrong
	 * Ethernet addresses, we need to mark them as PACKET_HOST or the kernel
	 * will drop them.
	 */
	if (from_tunnel) {
		ctx_change_type(ctx, PACKET_HOST);
		return CTX_ACT_OK;
	}
# endif /* !ENABLE_NODEPORT */

	return redirect_ep(ctx, ep->ifindex, from_host, from_tunnel);
#else

	/* Jumps to destination pod's BPF program to enforce ingress policies. */
	local_delivery_fill_meta(ctx, seclabel, true, from_host, from_tunnel, cluster_id);
	return tail_call_policy(ctx, ep->lxc_id);
#endif
}

#ifdef ENABLE_IPV6
/* Performs IPv6 L2/L3 handling and delivers the packet to the destination pod
 * on the same node, either via the stack or via a redirect call.
 * Depending on the configuration, it may also enforce ingress policies for the
 * destination pod via a tail call.
 */
static __always_inline int ipv6_local_delivery(struct __ctx_buff *ctx, int l3_off,
					       __u32 seclabel, __u32 magic,
					       const struct endpoint_info *ep,
					       __u8 direction, bool from_host,
					       bool from_tunnel)
{
	mac_t router_mac = ep->node_mac;
	mac_t lxc_mac = ep->mac;
	int ret;

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);

	ret = ipv6_l3(ctx, l3_off, (__u8 *)&router_mac, (__u8 *)&lxc_mac, direction);
	if (ret != CTX_ACT_OK)
		return ret;

	return local_delivery(ctx, seclabel, magic, ep, direction, from_host,
			      from_tunnel, 0);
}
#endif /* ENABLE_IPV6 */

/* Performs IPv4 L2/L3 handling and delivers the packet to the destination pod
 * on the same node, either via the stack or via a redirect call.
 * Depending on the configuration, it may also enforce ingress policies for the
 * destination pod via a tail call.
 */
static __always_inline int ipv4_local_delivery(struct __ctx_buff *ctx, int l3_off,
					       __u32 seclabel, __u32 magic,
					       struct iphdr *ip4,
					       const struct endpoint_info *ep,
					       __u8 direction, bool from_host,
					       bool from_tunnel, __u32 cluster_id)
{
	mac_t router_mac = ep->node_mac;
	mac_t lxc_mac = ep->mac;
	int ret;

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);

	ret = ipv4_l3(ctx, l3_off, (__u8 *)&router_mac, (__u8 *)&lxc_mac, ip4);
	if (ret != CTX_ACT_OK)
		return ret;

	return local_delivery(ctx, seclabel, magic, ep, direction, from_host,
			      from_tunnel, cluster_id);
}
