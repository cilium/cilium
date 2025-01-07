// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ETH_HLEN 0
#define IS_BPF_WIREGUARD 1

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

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
#include "lib/nodeport_egress.h"
#include "lib/clustermesh.h"
#include "lib/egress_gateway.h"

#define SECCTX_FROM_IPCACHE_OK	2
#ifndef SECCTX_FROM_IPCACHE
# define SECCTX_FROM_IPCACHE	0
#endif

static __always_inline bool identity_from_ipcache_ok(void)
{
	return SECCTX_FROM_IPCACHE == SECCTX_FROM_IPCACHE_OK;
}

#ifdef ENABLE_IPV6
static __always_inline __u32
resolve_srcid_ipv6(struct __ctx_buff *ctx, struct ipv6hdr *ip6, __u32 srcid_from_ipcache)
{
	__u32 src_id = WORLD_IPV6_ID;
	__u32 sec_identity = UNKNOWN_ID;
	struct remote_endpoint_info *info = NULL;
	union v6addr *src;

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(srcid_from_ipcache)) {
		src = (union v6addr *)&ip6->saddr;
		info = lookup_ip6_remote_endpoint(src, 0);
		if (info) {
			sec_identity = info->sec_identity;
			if (sec_identity) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "srcid_from_proxy"
				 * (passed into this function) reports the src as
				 * the host. So we can ignore the ipcache if it
				 * reports the source as HOST_ID.
				 */
				if (sec_identity != HOST_ID)
					srcid_from_ipcache = sec_identity;
			}
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   ((__u32 *)src)[3], srcid_from_ipcache);
	}

	if (identity_from_ipcache_ok())
		src_id = srcid_from_ipcache;
	return src_id;
}

static __always_inline int
handle_ipv6_cont(struct __ctx_buff *ctx, __u32 secctx, __s8 *ext_err __maybe_unused)
{
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	__u32 __maybe_unused from_host_raw;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int l3_off = ETH_HLEN;
	struct endpoint_info *ep;
	int ret;
	bool l2_hdr_required __maybe_unused = true;
	__u8 encrypt_key __maybe_unused = 0;
	__u32 magic = MARK_MAGIC_IDENTITY;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

#ifndef ENABLE_HOST_ROUTING
	/* See the equivalent v4 path for comments */
	return CTX_ACT_OK;
#endif /* !ENABLE_HOST_ROUTING */

	/* Lookup IPv6 address in list of local endpoints */
	ep = lookup_ip6_endpoint(ip6);
	if (ep) {
		/* Let through packets to the node-ip so they are
		 * processed by the local ip stack.
		 */
		if (ep->flags & ENDPOINT_MASK_HOST_DELIVERY)
			return CTX_ACT_OK;

#ifdef ENABLE_HOST_ROUTING
		/* add L2 header for L2-less interface, such as cilium_wg0 */
		ret = maybe_add_l2_hdr(ctx, ep->ifindex, &l2_hdr_required);
		if (ret != 0)
			return ret;
		if (l2_hdr_required && ETH_HLEN == 0) {
			/* l2 header is added */
			l3_off += __ETH_HLEN;
		}
#endif
		return ipv6_local_delivery(ctx, l3_off, secctx, magic, ep,
					   METRIC_INGRESS, false, false);
	}

	return CTX_ACT_OK;
}

static __always_inline int handle_ipv6(struct __ctx_buff *ctx,
				       __u32 identity __maybe_unused,
					   bool *punt_to_stack __maybe_unused,
				       __s8 *ext_err __maybe_unused)
{
	void *data_end, *data;
	struct ipv6hdr *ip6;
	__u8 nexthdr;
	int hdrlen;
	int ret;

	/* verifier workaround (dereference of modified ctx ptr) */
	if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	if (likely(nexthdr == IPPROTO_ICMPV6)) {
		ret = icmp6_host_handle(ctx, ETH_HLEN + hdrlen, ext_err, true);
		if (ret == SKIP_HOST_FIREWALL)
			goto skip_host_firewall;
		if (IS_ERR(ret))
			return ret;
	}

#ifdef ENABLE_NODEPORT
	if (!ctx_skip_nodeport(ctx)) {
		bool is_dsr = false;

		ret = nodeport_lb6(ctx, ip6, identity, punt_to_stack, ext_err, &is_dsr);
		/* nodeport_lb6() returns with TC_ACT_REDIRECT for
		 * traffic to L7 LB. Policy enforcement needs to take
		 * place after L7 LB has processed the packet, so we
		 * return to stack immediately here with
		 * TC_ACT_REDIRECT.
		 */
		if (ret < 0 || ret == TC_ACT_REDIRECT)
			return ret;
		if (*punt_to_stack)
			return ret;
	}
#endif

skip_host_firewall:
	return TC_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_WIREGUARD)
int tail_handle_ipv6(struct __ctx_buff *ctx)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	__s8 ext_err = 0;
	bool punt_to_stack = false;
	int ret;

	ret = handle_ipv6(ctx, src_sec_identity, &punt_to_stack, &ext_err);
	if (ret == CTX_ACT_OK) {
		if (punt_to_stack)
			return ret;
		ret = handle_ipv6_cont(ctx, src_sec_identity, &ext_err);
	}

	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}
#endif

#ifdef ENABLE_IPV4
static __always_inline __u32
resolve_srcid_ipv4(struct __ctx_buff *ctx, struct iphdr *ip4, __u32 srcid_from_proxy)
{
	struct remote_endpoint_info *info = NULL;
	__u32 src_id = WORLD_IPV4_ID;
	__u32 sec_identity = UNKNOWN_ID;
	__u32 srcid_from_ipcache = srcid_from_proxy;

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(srcid_from_ipcache)) {
		info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
		if (info) {
			sec_identity = info->sec_identity;

			if (sec_identity) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "srcid_from_proxy"
				 * (passed into this function) reports the src as
				 * the host. So we can ignore the ipcache if it
				 * reports the source as HOST_ID.
				 */
				if (sec_identity != HOST_ID)
					srcid_from_ipcache = sec_identity;
			}
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->saddr, srcid_from_ipcache);
	}

	/* If we could not derive the secctx from the packet itself but
	 * from the ipcache instead, then use the ipcache identity.
	 */
	if (identity_from_ipcache_ok())
		src_id = srcid_from_ipcache;
	return src_id;
}

static __always_inline int handle_ipv4(struct __ctx_buff *ctx,
				       __u32 identity __maybe_unused,
					   bool *punt_to_stack __maybe_unused,
				       __s8 *ext_err __maybe_unused)
{
	void *data_end, *data;
	struct iphdr *ip4;
	__u32 l3_off = ETH_HLEN;
	int ret;

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
	if (!ctx_skip_nodeport(ctx)) {
		bool is_dsr = false;

		ret = nodeport_lb4(ctx, ip4, l3_off, identity, punt_to_stack,
				   ext_err, &is_dsr);
#ifdef ENABLE_IPV6
			if (ret == NAT_46X64_RECIRC) {
				ctx_store_meta(ctx, CB_SRC_LABEL, identity);
				return tail_call_internal(ctx, CILIUM_CALL_IPV6_FROM_NETDEV,
							  ext_err);
			}
#endif
		/* nodeport_lb4() returns with TC_ACT_REDIRECT for
		 * traffic to L7 LB. Policy enforcement needs to take
		 * place after L7 LB has processed the packet, so we
		 * return to stack immediately here with
		 * TC_ACT_REDIRECT.
		 */
		if (ret < 0 || ret == TC_ACT_REDIRECT)
			return ret;
		if (*punt_to_stack)
			return ret;
	}
#endif

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	return TC_ACT_OK;
}

static __always_inline int
handle_ipv4_cont(struct __ctx_buff *ctx, __u32 secctx, __s8 *ext_err __maybe_unused)
{
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	__u32 __maybe_unused from_host_raw;
	void *data, *data_end;
	struct iphdr *ip4;
	struct endpoint_info *ep;
	int ret;
	__u8 encrypt_key __maybe_unused = 0;
	__u32 magic = MARK_MAGIC_IDENTITY;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

#ifndef ENABLE_HOST_ROUTING
	/* Without bpf_redirect_neigh() helper, we cannot redirect a
	 * packet to a local endpoint in the direct routing mode, as
	 * the redirect bypasses nf_conntrack table. This makes a
	 * second reply from the endpoint to be MASQUERADEd or to be
	 * DROP-ed by k8s's "--ctstate INVALID -j DROP" depending via
	 * which interface it was inputed. With bpf_redirect_neigh()
	 * we bypass request and reply path in the host namespace and
	 * do not run into this issue.
	 */
	return CTX_ACT_OK;
#endif /* !ENABLE_HOST_ROUTING */

	/* Lookup IPv4 address in list of local endpoints and host IPs */
	ep = lookup_ip4_endpoint(ip4);
	if (ep) {
		int l3_off = ETH_HLEN;

		/* Let through packets to the node-ip so they are processed by
		 * the local ip stack.
		 */
		if (ep->flags & ENDPOINT_MASK_HOST_DELIVERY)
			return CTX_ACT_OK;

#ifdef ENABLE_HOST_ROUTING
		{
			/* add L2 header for L2-less interface, such as cilium_wg0 */
			bool l2_hdr_required = true;

			ret = maybe_add_l2_hdr(ctx, ep->ifindex, &l2_hdr_required);
			if (ret != 0)
				return ret;
			if (l2_hdr_required && ETH_HLEN == 0) {
				/* l2 header is added */
				l3_off += __ETH_HLEN;
				if (!____revalidate_data_pull(ctx, &data, &data_end,
							      (void **)&ip4, sizeof(*ip4),
							      false, l3_off))
					return DROP_INVALID;
			}
		}
#endif

		return ipv4_local_delivery(ctx, l3_off, secctx, magic, ip4, ep,
					   METRIC_INGRESS, false, false, 0);
	}

	return CTX_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_WIREGUARD)
int tail_handle_ipv4(struct __ctx_buff *ctx)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	__s8 ext_err = 0;
	bool punt_to_stack = false;
	int ret;

	ret = handle_ipv4(ctx, src_sec_identity, &punt_to_stack, &ext_err);
	if (ret == CTX_ACT_OK) {
		if (punt_to_stack)
			return ret;
		ret = handle_ipv4_cont(ctx, src_sec_identity, &ext_err);
	}

	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}
#endif

/* from-wireguard is attached as a tc ingress filter to the cilium_wg0 device.
 */
__section_entry
int cil_from_wireguard(struct __ctx_buff *ctx)
{
	void __maybe_unused *data, *data_end;
	int ret = TC_ACT_OK;
	__u32 __maybe_unused identity = UNKNOWN_ID;
	__s8 __maybe_unused ext_err = 0;
	__u16 __maybe_unused proto = 0;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;

	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	ctx_skip_nodeport_clear(ctx);

	if (!validate_ethertype(ctx, &proto)) {
		/* Pass unknown traffic to the stack */
		goto out;
	}

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			return send_drop_notify_error(ctx, identity, DROP_INVALID,
						      CTX_ACT_DROP, METRIC_INGRESS);

		identity = resolve_srcid_ipv6(ctx, ip6, identity);
		ctx_store_meta(ctx, CB_SRC_LABEL, identity);
		send_trace_notify(ctx, TRACE_FROM_NETWORK, identity, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, ctx->ingress_ifindex,
				  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_FROM_WIREGUARD, &ext_err);
		break;
#endif

#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return send_drop_notify_error(ctx, identity, DROP_INVALID,
						      CTX_ACT_DROP, METRIC_INGRESS);

		identity = resolve_srcid_ipv4(ctx, ip4, identity);
		ctx_store_meta(ctx, CB_SRC_LABEL, identity);
		send_trace_notify(ctx, TRACE_FROM_NETWORK, identity, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, ctx->ingress_ifindex,
				  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_FROM_WIREGUARD, &ext_err);
		break;
#endif

	default:
		send_trace_notify(ctx, TRACE_FROM_NETWORK, UNKNOWN_ID, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, ctx->ingress_ifindex,
				  trace.reason, trace.monitor);
		/* Pass unknown traffic to the stack */
		ret = CTX_ACT_OK;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret,
						  ext_err, CTX_ACT_DROP,
						  METRIC_INGRESS);
	return ret;
}

/* to-wireguard is attached as a tc egress filter to the cilium_wg0 device.
 */
__section_entry
int cil_to_wireguard(struct __ctx_buff *ctx)
{
	int __maybe_unused ret;
	__s8 __maybe_unused ext_err = 0;
	__u16 __maybe_unused proto = ctx_get_protocol(ctx);
	__u32 __maybe_unused src_sec_identity = UNKNOWN_ID;
	__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;

	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	if (magic == MARK_MAGIC_IDENTITY)
		src_sec_identity = get_identity(ctx);

	bpf_clear_meta(ctx);

#ifdef ENABLE_NODEPORT
	if (magic == MARK_MAGIC_OVERLAY)
		goto out;

	ret = handle_nat_fwd(ctx, 0, proto, true, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);

out:
#endif /* ENABLE_NODEPORT */

	return TC_ACT_OK;
}

BPF_LICENSE("Dual BSD/GPL");
