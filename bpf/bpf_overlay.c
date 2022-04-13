// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#define IS_BPF_OVERLAY 1

/* Controls the inclusion of the CILIUM_CALL_HANDLE_ICMP6_NS section in the
 * bpf_lxc object file.
 */
#define SKIP_ICMPV6_NS_HANDLING

/* Controls the inclusion of the CILIUM_CALL_SEND_ICMP6_ECHO_REPLY section in
 * the bpf_lxc object file.
 */
#define SKIP_ICMPV6_ECHO_HANDLING

/* Controls the inclusion of the CILIUM_CALL_SRV6 section in the object file.
 */
#define SKIP_SRV6_HANDLING

#include "lib/tailcall.h"
#include "lib/common.h"
#include "lib/edt.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/trace.h"
#include "lib/l3.h"
#include "lib/drop.h"
#include "lib/identity.h"
#include "lib/nodeport.h"

#ifdef ENABLE_VTEP
#include "lib/arp.h"
#include "lib/encap.h"
#include "lib/eps.h"
#endif /* ENABLE_VTEP */

#ifdef ENABLE_IPV6
static __always_inline int handle_ipv6(struct __ctx_buff *ctx,
				       __u32 *identity)
{
	int ret, l3_off = ETH_HLEN, hdrlen;
	void *data_end, *data;
	struct ipv6hdr *ip6;
	struct bpf_tunnel_key key = {};
	struct endpoint_info *ep;
	bool decrypted;

	/* verifier workaround (dereference of modified ctx ptr) */
	if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;
#ifdef ENABLE_NODEPORT
	if (!bpf_skip_nodeport(ctx)) {
		ret = nodeport_lb6(ctx, *identity);
		if (ret < 0)
			return ret;
	}
#endif
	ret = encap_remap_v6_host_address(ctx, false);
	if (unlikely(ret < 0))
		return ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	decrypted = ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);
	if (decrypted) {
		*identity = key.tunnel_id = get_identity(ctx);
	} else {
		if (unlikely(ctx_get_tunnel_key(ctx, &key, sizeof(key), 0) < 0))
			return DROP_NO_TUNNEL_KEY;
		*identity = key.tunnel_id;

		/* Any node encapsulating will map any HOST_ID source to be
		 * presented as REMOTE_NODE_ID, therefore any attempt to signal
		 * HOST_ID as source from a remote node can be dropped.
		 */
		if (*identity == HOST_ID)
			return DROP_INVALID_IDENTITY;

		/* Maybe overwrite the REMOTE_NODE_ID with
		 * KUBE_APISERVER_NODE_ID to support upgrade. After v1.12,
		 * this should be removed.
		 */
		if (identity_is_remote_node(*identity)) {
			struct remote_endpoint_info *info;

			/* Look up the ipcache for the src IP, it will give us
			 * the real identity of that IP.
			 */
			info = ipcache_lookup6(&IPCACHE_MAP,
					       (union v6addr *)&ip6->saddr,
					       V6_CACHE_KEY_LEN);
			if (info)
				*identity = info->sec_label;
		}
	}

	cilium_dbg(ctx, DBG_DECAP, key.tunnel_id, key.tunnel_label);

#ifdef ENABLE_IPSEC
	if (!decrypted) {
		/* IPSec is not currently enforce (feature coming soon)
		 * so for now just handle normally
		 */
		if (ip6->nexthdr != IPPROTO_ESP) {
			update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
				       REASON_PLAINTEXT);
			goto not_esp;
		}

		/* Decrypt "key" is determined by SPI */
		ctx->mark = MARK_MAGIC_DECRYPT;
		set_identity_mark(ctx, *identity);
		/* To IPSec stack on cilium_vxlan we are going to pass
		 * this up the stack but eth_type_trans has already labeled
		 * this as an OTHERHOST type packet. To avoid being dropped
		 * by IP stack before IPSec can be processed mark as a HOST
		 * packet.
		 */
		ctx_change_type(ctx, PACKET_HOST);

		send_trace_notify(ctx, TRACE_TO_STACK, 0, 0, 0,
				  ctx->ingress_ifindex, TRACE_REASON_ENCRYPTED,
				  TRACE_PAYLOAD_LEN);

		return CTX_ACT_OK;
	}
	ctx->mark = 0;
not_esp:
#endif

	/* Lookup IPv6 address in list of local endpoints */
	ep = lookup_ip6_endpoint(ip6);
	if (ep) {
		__u8 nexthdr;

		/* Let through packets to the node-ip so they are processed by
		 * the local ip stack.
		 */
		if (ep->flags & ENDPOINT_F_HOST)
			goto to_host;

		nexthdr = ip6->nexthdr;
		hdrlen = ipv6_hdrlen(ctx, &nexthdr);
		if (hdrlen < 0)
			return hdrlen;

		return ipv6_local_delivery(ctx, l3_off, *identity, ep,
					   METRIC_INGRESS, false);
	}

	/* A packet entering the node from the tunnel and not going to a local
	 * endpoint has to be going to the local host.
	 */
to_host:
#ifdef HOST_IFINDEX
	if (1) {
		union macaddr host_mac = HOST_IFINDEX_MAC;
		union macaddr router_mac = NODE_MAC;

		ret = ipv6_l3(ctx, ETH_HLEN, (__u8 *)&router_mac.addr,
			      (__u8 *)&host_mac.addr, METRIC_INGRESS);
		if (ret != CTX_ACT_OK)
			return ret;

		cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return ctx_redirect(ctx, HOST_IFINDEX, 0);
	}
#else
	return CTX_ACT_OK;
#endif
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_OVERLAY)
int tail_handle_ipv6(struct __ctx_buff *ctx)
{
	__u32 src_identity = 0;
	int ret = handle_ipv6(ctx, &src_identity);

	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, src_identity, ret,
					      CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int handle_ipv4(struct __ctx_buff *ctx, __u32 *identity)
{
	void *data_end, *data;
	struct iphdr *ip4;
	struct endpoint_info *ep;
	struct bpf_tunnel_key key = {};
	bool decrypted;

	/* verifier workaround (dereference of modified ctx ptr) */
	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

/* If IPv4 fragmentation is disabled
 * AND a IPv4 fragmented packet is received,
 * then drop the packet.
 */
#ifndef ENABLE_IPV4_FRAGMENTS
	if (ipv4_is_fragment(ip4))
		return DROP_FRAG_NOSUPPORT;
#endif

#ifdef ENABLE_NODEPORT
	if (!bpf_skip_nodeport(ctx)) {
		int ret = nodeport_lb4(ctx, *identity);

		if (ret < 0)
			return ret;
	}
#endif
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	decrypted = ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);
	/* If packets are decrypted the key has already been pushed into metadata. */
	if (decrypted) {
		*identity = key.tunnel_id = get_identity(ctx);
	} else {
		if (unlikely(ctx_get_tunnel_key(ctx, &key, sizeof(key), 0) < 0))
			return DROP_NO_TUNNEL_KEY;
		*identity = key.tunnel_id;

		if (*identity == HOST_ID)
			return DROP_INVALID_IDENTITY;
#ifdef ENABLE_VTEP
		{
			struct vtep_key vkey = {};
			struct vtep_value *info;

			vkey.vtep_ip = ip4->saddr & VTEP_MASK;
			info = map_lookup_elem(&VTEP_MAP, &vkey);
			if (!info)
				goto skip_vtep;
			if (info->tunnel_endpoint) {
				if (*identity != WORLD_ID)
					return DROP_INVALID_VNI;
			}
		}
skip_vtep:
#endif
		/* See comment at equivalent code in handle_ipv6() */
		if (identity_is_remote_node(*identity)) {
			struct remote_endpoint_info *info;

			info = ipcache_lookup4(&IPCACHE_MAP, ip4->saddr,
					       V4_CACHE_KEY_LEN);
			if (info)
				*identity = info->sec_label;
		}
	}

	cilium_dbg(ctx, DBG_DECAP, key.tunnel_id, key.tunnel_label);

#ifdef ENABLE_IPSEC
	if (!decrypted) {
		/* IPSec is not currently enforce (feature coming soon)
		 * so for now just handle normally
		 */
		if (ip4->protocol != IPPROTO_ESP) {
			update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
				       REASON_PLAINTEXT);
			goto not_esp;
		}

		ctx->mark = MARK_MAGIC_DECRYPT;
		set_identity_mark(ctx, *identity);
		/* To IPSec stack on cilium_vxlan we are going to pass
		 * this up the stack but eth_type_trans has already labeled
		 * this as an OTHERHOST type packet. To avoid being dropped
		 * by IP stack before IPSec can be processed mark as a HOST
		 * packet.
		 */
		ctx_change_type(ctx, PACKET_HOST);

		send_trace_notify(ctx, TRACE_TO_STACK, 0, 0, 0,
				  ctx->ingress_ifindex, TRACE_REASON_ENCRYPTED,
				  TRACE_PAYLOAD_LEN);

		return CTX_ACT_OK;
	}
	ctx->mark = 0;
not_esp:
#endif

	/* Lookup IPv4 address in list of local endpoints */
	ep = lookup_ip4_endpoint(ip4);
	if (ep) {
		/* Let through packets to the node-ip so they are processed by
		 * the local ip stack.
		 */
		if (ep->flags & ENDPOINT_F_HOST)
			goto to_host;

		return ipv4_local_delivery(ctx, ETH_HLEN, *identity, ip4, ep,
					   METRIC_INGRESS, false);
	}

	/* A packet entering the node from the tunnel and not going to a local
	 * endpoint has to be going to the local host.
	 */
to_host:
#ifdef HOST_IFINDEX
	if (1) {
		union macaddr host_mac = HOST_IFINDEX_MAC;
		union macaddr router_mac = NODE_MAC;
		int ret;

		ret = ipv4_l3(ctx, ETH_HLEN, (__u8 *)&router_mac.addr,
			      (__u8 *)&host_mac.addr, ip4);
		if (ret != CTX_ACT_OK)
			return ret;

		cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return ctx_redirect(ctx, HOST_IFINDEX, 0);
	}
#else
	return CTX_ACT_OK;
#endif
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_OVERLAY)
int tail_handle_ipv4(struct __ctx_buff *ctx)
{
	__u32 src_identity = 0;
	int ret = handle_ipv4(ctx, &src_identity);

	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, src_identity, ret,
					      CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}

#ifdef ENABLE_VTEP
/*
 * ARP responder for ARP requests from VTEP
 * Respond to remote VTEP endpoint with cilium_vxlan MAC
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_ARP)
int tail_handle_arp(struct __ctx_buff *ctx)
{
	union macaddr mac = NODE_MAC;
	union macaddr smac;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_CT_REPLY,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	__be32 sip;
	__be32 tip;
	int ret;
	struct bpf_tunnel_key key = {};
	struct vtep_key vkey = {};
	struct vtep_value *info;

	if (unlikely(ctx_get_tunnel_key(ctx, &key, sizeof(key), 0) < 0))
		return send_drop_notify_error(ctx, 0, DROP_NO_TUNNEL_KEY, CTX_ACT_DROP,
										METRIC_INGRESS);

	if (!arp_validate(ctx, &mac, &smac, &sip, &tip) || !__lookup_ip4_endpoint(tip))
		goto pass_to_stack;
	vkey.vtep_ip = sip & VTEP_MASK;
	info = map_lookup_elem(&VTEP_MAP, &vkey);
	if (!info)
		goto pass_to_stack;

	ret = arp_prepare_response(ctx, &mac, tip, &smac, sip);
	if (unlikely(ret != 0))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
	if (info->tunnel_endpoint)
		return __encap_and_redirect_with_nodeid(ctx,
							info->tunnel_endpoint,
							SECLABEL,
							WORLD_ID,
							&trace);

	return send_drop_notify_error(ctx, 0, DROP_UNKNOWN_L3, CTX_ACT_DROP, METRIC_EGRESS);

pass_to_stack:
	send_trace_notify(ctx, TRACE_TO_STACK, 0, 0, 0, ctx->ingress_ifindex,
			  trace.reason, trace.monitor);
	return CTX_ACT_OK;
}
#endif /* ENABLE_VTEP */

#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPSEC
static __always_inline bool is_esp(struct __ctx_buff *ctx, __u16 proto)
{
	void *data, *data_end;
	__u8 protocol = 0;
	struct ipv6hdr *ip6 __maybe_unused;
	struct iphdr *ip4 __maybe_unused;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			return false;
		protocol = ip6->nexthdr;
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return false;
		protocol = ip4->protocol;
		break;
#endif
	default:
		return false;
	}

	return protocol == IPPROTO_ESP;
}
#endif /* ENABLE_IPSEC */

/* Attached to the ingress of cilium_vxlan/cilium_geneve to execute on packets
 * entering the node via the tunnel.
 */
__section("from-overlay")
int from_overlay(struct __ctx_buff *ctx)
{
	__u16 proto;
	int ret;

	bpf_clear_meta(ctx);
	bpf_skip_nodeport_clear(ctx);

	if (!validate_ethertype(ctx, &proto)) {
		/* Pass unknown traffic to the stack */
		ret = CTX_ACT_OK;
		goto out;
	}

/* We need to handle following possible packets come to this program
 *
 * 1. ESP packets coming from overlay (encrypted and not marked)
 * 2. Non-ESP packets coming from overlay (plain and not marked)
 * 3. Non-ESP packets coming from stack re-inserted by xfrm (plain
 *    and marked with MARK_MAGIC_DECRYPT and has an identity as
 *    well, IPSec mode only)
 *
 * 1. will be traced with TRACE_REASON_ENCRYPTED
 * 2. will be traced without TRACE_REASON_ENCRYPTED
 * 3. will be traced without TRACE_REASON_ENCRYPTED, and with identity
 *
 * Note that 1. contains the ESP packets someone else generated.
 * In that case, we trace it as "encrypted", but it doesn't mean
 * "encrypted by Cilium".
 *
 * When IPSec is disabled, we won't use TRACE_REASON_ENCRYPTED even
 * if the packets are ESP, because it doesn't matter for the
 * non-IPSec mode.
 */
#ifdef ENABLE_IPSEC
	if (is_esp(ctx, proto))
		send_trace_notify(ctx, TRACE_FROM_OVERLAY, 0, 0, 0,
				  ctx->ingress_ifindex, TRACE_REASON_ENCRYPTED,
				  TRACE_PAYLOAD_LEN);
	else
#endif
	{
		__u32 identity = 0;
		enum trace_point obs_point = TRACE_FROM_OVERLAY;

		/* Non-ESP packet marked with MARK_MAGIC_DECRYPT is a packet
		 * re-inserted from the stack.
		 */
		if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT) {
			identity = get_identity(ctx);
			obs_point = TRACE_FROM_STACK;
		}

		send_trace_notify(ctx, obs_point, identity, 0, 0,
				  ctx->ingress_ifindex,
				  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);
	}

	switch (proto) {
	case bpf_htons(ETH_P_IPV6):
#ifdef ENABLE_IPV6
		ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_OVERLAY);
		ret = DROP_MISSED_TAIL_CALL;
#else
		ret = DROP_UNKNOWN_L3;
#endif
		break;

	case bpf_htons(ETH_P_IP):
#ifdef ENABLE_IPV4
		ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_OVERLAY);
		ret = DROP_MISSED_TAIL_CALL;
#else
		ret = DROP_UNKNOWN_L3;
#endif
		break;

#ifdef ENABLE_VTEP
	case bpf_htons(ETH_P_ARP):
		ep_tail_call(ctx, CILIUM_CALL_ARP);
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif

	default:
		/* Pass unknown traffic to the stack */
		ret = CTX_ACT_OK;
	}
out:
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}

/* Attached to the egress of cilium_vxlan/cilium_geneve to execute on packets
 * leaving the node via the tunnel.
 */
__section("to-overlay")
int to_overlay(struct __ctx_buff *ctx)
{
	int ret;

	ret = encap_remap_v6_host_address(ctx, true);
	if (unlikely(ret < 0))
		goto out;

#ifdef ENABLE_BANDWIDTH_MANAGER
	/* In tunneling mode, we should do this as close as possible to the
	 * phys dev where FQ runs, but the issue is that the aggregate state
	 * (in queue_mapping) is overridden on tunnel xmit. Hence set the
	 * timestamp already here. The tunnel dev has noqueue qdisc, so as
	 * tradeoff it's close enough.
	 */
	ret = edt_sched_departure(ctx);
	/* No send_drop_notify_error() here given we're rate-limiting. */
	if (ret == CTX_ACT_DROP) {
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
			       -DROP_EDT_HORIZON);
		return CTX_ACT_DROP;
	}
#endif

#ifdef ENABLE_NODEPORT
	if ((ctx->mark & MARK_MAGIC_SNAT_DONE) == MARK_MAGIC_SNAT_DONE) {
		ret = CTX_ACT_OK;
		goto out;
	}
	ret = handle_nat_fwd(ctx);
#endif
out:
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
	return ret;
}

BPF_LICENSE("Dual BSD/GPL");
