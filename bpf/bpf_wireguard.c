// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ETH_HLEN 0
#define IS_BPF_WIREGUARD 1

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <bpf/config/global.h>
#include <bpf/config/node.h>
#include <netdev_config.h>

/* WORLD_IPV{4,6}_ID varies based on dualstack being enabled. Real values are
 * written into node_config.h at runtime. */
#define SECLABEL WORLD_ID
#define SECLABEL_IPV4 WORLD_IPV4_ID
#define SECLABEL_IPV6 WORLD_IPV6_ID

/* Controls the inclusion of the CILIUM_CALL_HANDLE_ICMP6_NS section in the
 * object file.
 */
#define SKIP_ICMPV6_NS_HANDLING

/* Controls the inclusion of the CILIUM_CALL_SRV6 section in the object file.
 */
#define SKIP_SRV6_HANDLING

#include "lib/tailcall.h"
#include "lib/common.h"
#include "lib/encrypt.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/dbg.h"
#include "lib/trace.h"
#include "lib/l3.h"
#include "lib/drop.h"
#include "lib/identity.h"
#include "lib/nodeport.h"
#include "lib/nodeport_egress.h"
#include "lib/local_delivery.h"

#ifdef ENABLE_IPV6
static __always_inline int ipv6_host_delivery(struct __ctx_buff *ctx)
{
	union macaddr host_mac = CONFIG(cilium_host_mac);
	union macaddr router_mac = CONFIG(interface_mac);
	int ret;

	ret = ipv6_l3(ctx, __ETH_HLEN, (__u8 *)&router_mac.addr, (__u8 *)&host_mac.addr, METRIC_INGRESS);
	if (ret != CTX_ACT_OK)
		return ret;

	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, CONFIG(cilium_host_ifindex));
	return ctx_redirect(ctx, CONFIG(cilium_host_ifindex), BPF_F_INGRESS);
}

static __always_inline __u32
resolve_srcid_ipv6(struct __ctx_buff *ctx, struct ipv6hdr *ip6)
{
	__u32 srcid = WORLD_IPV6_ID;
	const struct remote_endpoint_info *info = NULL;
	const union v6addr *src;

	src = (union v6addr *)&ip6->saddr;
	info = lookup_ip6_remote_endpoint(src, 0);
	if (info)
		srcid = info->sec_identity;

	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
		   ((__u32 *)src)[3], srcid);

	return srcid;
}

/* See the equivalent v4 path for comments */
static __always_inline int
handle_ipv6(struct __ctx_buff *ctx, __u32 identity __maybe_unused, __s8 *ext_err __maybe_unused)
{
	void *data_end, *data;
	struct ipv6hdr *ip6;
	const struct endpoint_info *ep;
	fraginfo_t __maybe_unused fraginfo;
	int ret;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

#ifndef ENABLE_IPV6_FRAGMENTS
	fraginfo = ipv6_get_fraginfo(ctx, ip6);
	if (fraginfo < 0)
		return (int)fraginfo;
	if (ipfrag_is_fragment(fraginfo))
		return DROP_FRAG_NOSUPPORT;
#endif

#ifdef ENABLE_NODEPORT
	if (!ctx_skip_nodeport(ctx)) {
		bool punt_to_stack = false;
		bool is_dsr = false;

		ret = nodeport_lb6(ctx, ip6, identity, &punt_to_stack, ext_err, &is_dsr);
		if (ret < 0 || ret == TC_ACT_REDIRECT)
			return ret;
		if (punt_to_stack)
			return ret;
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
	}
#endif

	ep = lookup_ip6_endpoint(ip6);
	if (ep && !(ep->flags & ENDPOINT_MASK_HOST_DELIVERY)) {
#ifdef ENABLE_HOST_ROUTING
		int l3_off = ETH_HLEN;
		bool l2_hdr_required = true;

		ret = maybe_add_l2_hdr(ctx, ep->ifindex, &l2_hdr_required);
		if (ret != 0)
			return ret;
		if (l2_hdr_required)
			l3_off += __ETH_HLEN;

		return ipv6_local_delivery(ctx, l3_off, identity, MARK_MAGIC_IDENTITY, ep,
					   METRIC_INGRESS, false, false);
#else
		return CTX_ACT_OK;
#endif /* ENABLE_HOST_ROUTING */
	}

	ret = add_l2_hdr(ctx);
	if (ret != 0)
		return ret;

#ifdef ENABLE_IDENTITY_MARK
	set_identity_mark(ctx, identity, MARK_MAGIC_DECRYPT);
#endif
	return ipv6_host_delivery(ctx);
}

__declare_tail(CILIUM_CALL_IPV6_FROM_WIREGUARD)
int tail_handle_ipv6(struct __ctx_buff *ctx)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	__s8 ext_err = 0;
	int ret;

	ret = handle_ipv6(ctx, src_sec_identity, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
					METRIC_INGRESS);
	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int ipv4_host_delivery(struct __ctx_buff *ctx, struct iphdr *ip4)
{
	union macaddr host_mac = CONFIG(cilium_host_mac);
	union macaddr router_mac = CONFIG(interface_mac);
	int ret;

	ret = ipv4_l3(ctx, __ETH_HLEN, (__u8 *)&router_mac.addr, (__u8 *)&host_mac.addr, ip4);
	if (ret != CTX_ACT_OK)
		return ret;

	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, CONFIG(cilium_host_ifindex));
	return ctx_redirect(ctx, CONFIG(cilium_host_ifindex), BPF_F_INGRESS);
}

static __always_inline __u32
resolve_srcid_ipv4(struct __ctx_buff *ctx, struct iphdr *ip4)
{
	__u32 srcid = WORLD_IPV4_ID;
	const struct remote_endpoint_info *info = NULL;

	info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
	if (info)
		srcid = info->sec_identity;

	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
		   ip4->saddr, srcid);

	return srcid;
}

static __always_inline int
handle_ipv4(struct __ctx_buff *ctx, __u32 identity __maybe_unused, __s8 *ext_err __maybe_unused)
{
	void *data_end, *data;
	struct iphdr *ip4;
	const struct endpoint_info *ep;
	fraginfo_t __maybe_unused fraginfo;
	int ret;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

/* If IPv4 fragmentation is disabled
 * AND a IPv4 fragmented packet is received,
 * then drop the packet.
 */
#ifndef ENABLE_IPV4_FRAGMENTS
	fraginfo = ipfrag_encode_ipv4(ip4);
	if (ipfrag_is_fragment(fraginfo))
		return DROP_FRAG_NOSUPPORT;
#endif

#ifdef ENABLE_NODEPORT
	if (!ctx_skip_nodeport(ctx)) {
		bool punt_to_stack = false;
		bool is_dsr = false;

		ret = nodeport_lb4(ctx, ip4, ETH_HLEN, identity, &punt_to_stack,
				   ext_err, &is_dsr);
		/* nodeport_lb4() returns with TC_ACT_REDIRECT for
		 * traffic to L7 LB. Policy enforcement needs to take
		 * place after L7 LB has processed the packet, so we
		 * return to stack immediately here with
		 * TC_ACT_REDIRECT.
		 */
		if (ret < 0 || ret == TC_ACT_REDIRECT)
			return ret;
		if (punt_to_stack)
			return ret;
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
	}
#endif

	/* Lookup IPv4 address in the list of local endpoints and host IPs.
	 *
	 * Packet for local Endpoint:
	 * Without bpf_redirect_neigh() helper, we cannot redirect a
	 * packet to a local endpoint in the direct routing mode, as
	 * the redirect bypasses nf_conntrack table. This makes a
	 * second reply from the endpoint to be MASQUERADEd or to be
	 * DROP-ed by k8s's "--ctstate INVALID -j DROP" depending via
	 * which interface it was inputed. With bpf_redirect_neigh()
	 * we bypass request and reply path in the host namespace and
	 * do not run into this issue.
	 * Endpoint policies will be enforced as follows:
	 * - with per-EP routes: the packet reaches the installed
	 *   to-container program, where policies will be enforced.
	 * - without per-EP routes: the packet reaches cilium_host,
	 *   where policies will be enforced via tailcall.
	 * With bpf_redirect_neigh() helper, we redirect to the pod
	 * ingress BPF program to enforce policies and deliver the packet.
	 *
	 * Packet for local Host:
	 * We always add a L2 header and redirect to cilium_host@ingress.
	 * Host policies will be enforced in cilium_host@ingress (HostFw).
	 */
	ep = lookup_ip4_endpoint(ip4);
	if (ep && !(ep->flags & ENDPOINT_MASK_HOST_DELIVERY)) {
#ifdef ENABLE_HOST_ROUTING
		int l3_off = ETH_HLEN;
		bool l2_hdr_required = true;

		ret = maybe_add_l2_hdr(ctx, ep->ifindex, &l2_hdr_required);
		if (ret != 0)
			return ret;
		if (l2_hdr_required) {
			/* l2 header is added */
			l3_off += __ETH_HLEN;
			if (!__revalidate_data_pull(ctx, &data, &data_end,
						    (void **)&ip4, l3_off,
						    sizeof(*ip4), false))
				return DROP_INVALID;
		}

		return ipv4_local_delivery(ctx, l3_off, identity, MARK_MAGIC_IDENTITY, ip4, ep,
					   METRIC_INGRESS, false, false, 0);
#else
		return CTX_ACT_OK;
#endif /* ENABLE_HOST_ROUTING */
	}

	ret = add_l2_hdr(ctx);
	if (ret != 0)
		return ret;
	if (!__revalidate_data_pull(ctx, &data, &data_end,
				    (void **)&ip4, __ETH_HLEN,
				    sizeof(*ip4), false))
		return DROP_INVALID;

#ifdef ENABLE_IDENTITY_MARK
	/* We must use the MARK_MAGIC_DECRYPT rather than MARK_MAGIC_IDENTITY though,
	 * as at the beginning of the from-wireguard program we mark the packet as
	 * decrypted. That has been introduced to support Ingress Strict Mode
	 * (see https://github.com/cilium/cilium/pull/39239).
	 */
	set_identity_mark(ctx, identity, MARK_MAGIC_DECRYPT);
#endif
	return ipv4_host_delivery(ctx, ip4);
}

__declare_tail(CILIUM_CALL_IPV4_FROM_WIREGUARD)
int tail_handle_ipv4(struct __ctx_buff *ctx)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	__s8 ext_err = 0;
	int ret;

	ret = handle_ipv4(ctx, src_sec_identity, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						METRIC_INGRESS);
	return ret;
}
#endif /* ENABLE_IPV4 */

/* from-wireguard is attached as a tc ingress filter to the cilium_wg0 device. */
__section_entry
int cil_from_wireguard(struct __ctx_buff *ctx)
{
	void __maybe_unused *data, *data_end;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	int __maybe_unused ret;
	__u32 __maybe_unused identity = UNKNOWN_ID;
	__s8 __maybe_unused ext_err = 0;
	__be16 proto = ctx_get_protocol(ctx);

	ctx_skip_nodeport_clear(ctx);

	bpf_clear_meta(ctx);
	check_and_store_ip_trace_id(ctx);

#ifdef ENABLE_IDENTITY_MARK
	/* mark packet as decrypted by wireguard */
	set_decrypt_mark(ctx, 0);
#endif

#if defined(TUNNEL_MODE) && !(defined(ENABLE_NODEPORT) && defined(ENABLE_NODE_ENCRYPTION))
	/* In native routing mode we want to deliver packets to local endpoints
	 * straight from BPF, without passing through the stack.
	 * This matches overlay mode (where bpf_overlay would handle the delivery)
	 * and native routing mode without encryption (where bpf_host at the native
	 * device would handle the delivery).
	 *
	 * When WG & encrypt-node are on, a NodePort BPF to-be forwarded request
	 * to a remote node running a selected service endpoint must be encrypted.
	 * To make the NodePort's rev-{S,D}NAT translations to happen for a reply
	 * from the remote node, we need to attach bpf_host to the Cilium's WG
	 * netdev (otherwise, the WG netdev after decrypting the reply will pass
	 * it to the stack which drops the packet).
	 *
	 * Since neither of these conditions are met, we can return CTX_ACT_OK.
	 */
	return CTX_ACT_OK;
#endif

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			return send_drop_notify_error(ctx, identity, DROP_INVALID, METRIC_INGRESS);

		identity = resolve_srcid_ipv6(ctx, ip6);
		ctx_store_meta(ctx, CB_SRC_LABEL, identity);

		send_trace_notify(ctx, TRACE_FROM_CRYPTO, identity, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, ctx->ingress_ifindex,
				  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN, proto);

		ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_FROM_WIREGUARD, &ext_err);
		/* See the equivalent v4 path for comments */
		return send_drop_notify_error_with_exitcode_ext(ctx, identity, ret, ext_err,
								CTX_ACT_OK, METRIC_INGRESS);
#endif

#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return send_drop_notify_error(ctx, identity, DROP_INVALID, METRIC_INGRESS);

		identity = resolve_srcid_ipv4(ctx, ip4);
		ctx_store_meta(ctx, CB_SRC_LABEL, identity);

		send_trace_notify(ctx, TRACE_FROM_CRYPTO, identity, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, ctx->ingress_ifindex,
				  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN, proto);

		ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_FROM_WIREGUARD, &ext_err);
		/* We are not returning an error here to always allow traffic to
		 * the stack in case maps have become unavailable.
		 *
		 * Note: Since drop notification requires a tail call as well,
		 * this notification is unlikely to succeed.
		 */
		return send_drop_notify_error_with_exitcode_ext(ctx, identity, ret, ext_err,
								CTX_ACT_OK, METRIC_INGRESS);
#endif
	}

	send_trace_notify(ctx, TRACE_FROM_CRYPTO, UNKNOWN_ID, UNKNOWN_ID,
			  TRACE_EP_ID_UNKNOWN, ctx->ingress_ifindex,
			  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN, proto);

	/* Pass unknown traffic to the stack */
	return CTX_ACT_OK;
}

/* to-wireguard is attached as a tc egress filter to the cilium_wg0 device. */
__section_entry
int cil_to_wireguard(struct __ctx_buff *ctx)
{
	int __maybe_unused ret;
	__s8 __maybe_unused ext_err = 0;
	__be16 proto = ctx_get_protocol(ctx);
	__u32 src_sec_identity = UNKNOWN_ID;
	__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;

	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	if (magic == MARK_MAGIC_IDENTITY)
		src_sec_identity = get_identity(ctx);

	bpf_clear_meta(ctx);
	check_and_store_ip_trace_id(ctx);

#ifdef ENABLE_NODEPORT
	if (magic == MARK_MAGIC_OVERLAY)
		goto out;

	ret = handle_nat_fwd(ctx, 0, src_sec_identity, proto, true, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  METRIC_EGRESS);

out:
#endif /* ENABLE_NODEPORT */

	send_trace_notify(ctx, TRACE_TO_CRYPTO, src_sec_identity, UNKNOWN_ID,
			  TRACE_EP_ID_UNKNOWN, CONFIG(interface_ifindex),
			  trace.reason, trace.monitor, proto);

	return CTX_ACT_OK;
}

BPF_LICENSE("Dual BSD/GPL");
