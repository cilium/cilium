// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <bpf/config/node.h>
#include <bpf/config/global.h>
#include <bpf/config/endpoint.h>
#include <bpf/config/host.h>

#define IS_BPF_HOST 1

#define EFFECTIVE_EP_ID CONFIG(host_ep_id)
#define EVENT_SOURCE CONFIG(host_ep_id)

/* These are configuration options which have a default value in their
 * respective header files and must thus be defined beforehand:
 */
/* Pass unknown ICMPv6 NS to stack */
#define ACTION_UNKNOWN_ICMP6_NS CTX_ACT_OK

#ifndef VLAN_FILTER
# define VLAN_FILTER(ifindex, vlan_id) return false;
#endif

#define	NODEPORT_USE_NAT_46x64		1

#include "lib/common.h"
#include "lib/config_map.h"
#include "lib/edt.h"
#include "lib/arp.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/proxy.h"
#include "lib/policy.h"
#include "lib/trace.h"
#include "lib/identity.h"
#include "lib/l4.h"
#include "lib/local_delivery.h"
#include "lib/drop.h"
#include "lib/encap.h"
#include "lib/nat.h"
#include "lib/lb.h"
#include "lib/nodeport.h"
#include "lib/nodeport_egress.h"
#include "lib/eps.h"
#include "lib/host_firewall.h"
#include "lib/egress_gateway.h"
#include "lib/srv6.h"
#include "lib/tailcall.h"
#include "lib/overloadable.h"
#include "lib/encrypt.h"
#include "lib/ipsec.h"
#include "lib/wireguard.h"
#include "lib/l2_responder.h"
#include "lib/vtep.h"
#include "lib/subnet.h"

 #define host_egress_policy_hook(ctx, src_sec_identity, ext_err) CTX_ACT_OK
 #define host_wg_encrypt_hook(ctx, proto, src_sec_identity)			\
	 wg_maybe_redirect_to_encrypt(ctx, proto, src_sec_identity)

#ifndef tcx_early_hook
#define tcx_early_hook(ctx, proto) CTX_ACT_OK
#endif

/* Bit 0 is skipped for robustness, as it's used in some places to indicate from_host itself. */
#define FROM_HOST_FLAG_NEED_HOSTFW (1 << 1)
#define FROM_HOST_FLAG_HOST_ID (1 << 2)

static __always_inline bool allow_vlan(__u32 __maybe_unused ifindex, __u32 __maybe_unused vlan_id) {
	VLAN_FILTER(ifindex, vlan_id);
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct ct_buffer6);
	__uint(max_entries, 1);
} cilium_tail_call_buffer6 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct ct_buffer4);
	__uint(max_entries, 1);
} cilium_tail_call_buffer4 __section_maps_btf;

#if defined(ENABLE_IPV4) || defined(ENABLE_IPV6)
static __always_inline int rewrite_dmac_to_host(struct __ctx_buff *ctx)
{
	/* When attached to cilium_host, we rewrite the DMAC to the mac of
	 * cilium_host (peer) to ensure the packet is being considered to be
	 * addressed to the host (PACKET_HOST).
	 */
	union macaddr cilium_net_mac = CONFIG(cilium_net_mac);

	/* Rewrite to destination MAC of cilium_net (remote peer) */
	if (eth_store_daddr(ctx, (__u8 *) &cilium_net_mac.addr, 0) < 0)
		return DROP_WRITE_ERROR;

	return CTX_ACT_OK;
}
#endif

#ifdef ENABLE_IPV6
static __always_inline __u32
resolve_srcid_ipv6(struct __ctx_buff *ctx, struct ipv6hdr *ip6,
		   __u32 real_sec_identity, __u32 *ipcache_sec_identity)
{
	const struct remote_endpoint_info *info = NULL;
	union v6addr *src;

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(real_sec_identity)) {
		src = (union v6addr *) &ip6->saddr;
		info = lookup_ip6_remote_endpoint(src, 0);
		if (info) {
			*ipcache_sec_identity = info->sec_identity;

			/* When SNAT is enabled on traffic ingressing
			 * into Cilium, all traffic from the world will
			 * have a source IP of the host. It will only
			 * actually be from the host if "real_sec_identity"
			 * (passed into this function) reports the src as
			 * the host. So we can ignore the ipcache if it
			 * reports the source as HOST_ID.
			 */
			if (*ipcache_sec_identity != HOST_ID)
				real_sec_identity = *ipcache_sec_identity;
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   ((__u32 *)src)[3], real_sec_identity);
	}

	return real_sec_identity;
}

static __always_inline int
handle_ipv6(struct __ctx_buff *ctx, __u32 secctx __maybe_unused,
	    __u32 ipcache_srcid __maybe_unused,
	    const bool from_host,
	    bool *punt_to_stack __maybe_unused,
	    __s8 *ext_err)
{
	struct ct_buffer6 __maybe_unused ct_buffer = {};
	bool __maybe_unused need_hostfw = false;
	bool __maybe_unused is_host_id = false;
	bool __maybe_unused skip_host_firewall = false;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	fraginfo_t fraginfo __maybe_unused;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

#ifndef ENABLE_IPV6_FRAGMENTS
	fraginfo = ipv6_get_fraginfo(ctx, ip6);
	if (fraginfo < 0)
		return (int)fraginfo;
	if (ipfrag_is_fragment(fraginfo))
		return DROP_FRAG_NOSUPPORT;
#endif

	if (is_defined(ENABLE_HOST_FIREWALL) || !from_host) {
		__u8 nexthdr = ip6->nexthdr;
		int hdrlen;

		hdrlen = ipv6_hdrlen(ctx, &nexthdr);
		if (hdrlen < 0)
			return hdrlen;

		if (likely(nexthdr == IPPROTO_ICMPV6)) {
			ret = icmp6_host_handle(ctx, ETH_HLEN + hdrlen, ext_err, !from_host);
			if (ret == SKIP_HOST_FIREWALL) {
#ifdef ENABLE_HOST_FIREWALL
				skip_host_firewall = true;
#endif /* ENABLE_HOST_FIREWALL */
			} else if (IS_ERR(ret)) {
				return ret;
			}
		}
	}

#ifdef ENABLE_NODEPORT
	if (!from_host) {
		if (!ctx_skip_nodeport(ctx)) {
			bool is_dsr = false;

			ret = nodeport_lb6(ctx, ip6, secctx, punt_to_stack, ext_err, &is_dsr);
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
	}
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_HOST_FIREWALL
	if (skip_host_firewall)
		goto skip_host_firewall;

	if (from_host) {
		if (ipv6_host_policy_egress_lookup(ctx, secctx, ipcache_srcid, ip6, &ct_buffer)) {
			if (unlikely(ct_buffer.ret < 0))
				return ct_buffer.ret;
			need_hostfw = true;
			is_host_id = secctx == HOST_ID;
		}
	} else if (!ctx_skip_host_fw(ctx)) {
		/* Verifier workaround: R5 invalid mem access 'scalar'. */
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		if (ipv6_host_policy_ingress_lookup(ctx, ip6, &ct_buffer)) {
			if (unlikely(ct_buffer.ret < 0))
				return ct_buffer.ret;
			need_hostfw = true;
		}
	}
	if (need_hostfw) {
		__u32 zero = 0;

		if (map_update_elem(&cilium_tail_call_buffer6, &zero, &ct_buffer, 0) < 0)
			return DROP_INVALID_TC_BUFFER;
	}
#endif /* ENABLE_HOST_FIREWALL */

#ifdef ENABLE_HOST_FIREWALL
skip_host_firewall:
	ctx_store_meta(ctx, CB_FROM_HOST,
		       (need_hostfw ? FROM_HOST_FLAG_NEED_HOSTFW : 0) |
		       (is_host_id ? FROM_HOST_FLAG_HOST_ID : 0));
#endif /* ENABLE_HOST_FIREWALL */

	return CTX_ACT_OK;
}

static __always_inline int
handle_ipv6_cont(struct __ctx_buff *ctx, __u32 secctx, const bool from_host,
		 __s8 *ext_err __maybe_unused)
{
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	__u32 __maybe_unused from_host_raw;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr *dst;
	int l3_off = ETH_HLEN;
	const struct remote_endpoint_info *info = NULL;
	const struct endpoint_info *ep;
	int ret __maybe_unused;
	__u32 magic = MARK_MAGIC_IDENTITY;
	bool from_proxy = false;

	if (from_host && tc_index_from_ingress_proxy(ctx)) {
		from_proxy = true;
		magic = MARK_MAGIC_PROXY_INGRESS;
	}
	if (from_host && tc_index_from_egress_proxy(ctx)) {
		from_proxy = true;
		magic = MARK_MAGIC_PROXY_EGRESS;
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

#ifdef ENABLE_HOST_FIREWALL
	from_host_raw = ctx_load_and_clear_meta(ctx, CB_FROM_HOST);

	if (from_host_raw & FROM_HOST_FLAG_NEED_HOSTFW) {
		struct ct_buffer6 *ct_buffer;
		__u32 zero = 0;
		__u32 remote_id = WORLD_IPV6_ID;

		ct_buffer = map_lookup_elem(&cilium_tail_call_buffer6, &zero);
		if (!ct_buffer)
			return DROP_INVALID_TC_BUFFER;
		if (ct_buffer->tuple.saddr.d1 == 0 && ct_buffer->tuple.saddr.d2 == 0)
			/* The map value is zeroed so the map update didn't happen somehow. */
			return DROP_INVALID_TC_BUFFER;

		if (from_host) {
			bool is_host_id = from_host_raw & FROM_HOST_FLAG_HOST_ID;

			ret = __ipv6_host_policy_egress(ctx, is_host_id, ip6, ct_buffer, &trace,
							ext_err);
		} else {
			ret = __ipv6_host_policy_ingress(ctx, ip6, ct_buffer, &remote_id, &trace,
							 ext_err);
		}
		if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
			return ret;

		if (from_host) {
			if (!revalidate_data(ctx, &data, &data_end, &ip6))
				return DROP_INVALID;
		}
	}
#endif /* ENABLE_HOST_FIREWALL */

/*
 * Perform SRv6 Decap if incoming skb is a known SID.
 * This must tailcall, as the decap could be for inner ipv6 or ipv4 making
 * the remaining path potentially erroneous.
 *
 * Perform this before the ENABLE_HOST_ROUTING check as the decap is not dependent
 * on this feature being enabled or not.
 */
#ifdef ENABLE_SRV6
	if (!from_host) {
		if (is_srv6_packet(ip6) && srv6_lookup_sid(&ip6->daddr)) {
			/* This packet is destined to an SID so we need to decapsulate it
			 * and forward it.
			 */
			return tail_call_internal(ctx, CILIUM_CALL_SRV6_DECAP, ext_err);
		}
	}
#endif /* ENABLE_SRV6 */

#ifndef ENABLE_HOST_ROUTING
	/* See the equivalent v4 path for comments */
	if (!from_host)
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
		/* add L2 header for L2-less interface: */
		if (!from_host && THIS_IS_L3_DEV) {
			bool l2_hdr_required = true;

			ret = maybe_add_l2_hdr(ctx, ep->ifindex, &l2_hdr_required);
			if (ret != 0)
				return ret;
			if (l2_hdr_required) {
				/* l2 header is added */
				l3_off += __ETH_HLEN;
			}
		}
#endif
		return ipv6_local_delivery(ctx, l3_off, secctx, magic, ep,
					   METRIC_INGRESS, from_host, false);
	}

	/* Below remainder is only relevant when traffic is pushed via cilium_host.
	 * For traffic coming from external, we're done here.
	 */
	if (!from_host)
		return CTX_ACT_OK;

	dst = (union v6addr *) &ip6->daddr;
	info = lookup_ip6_remote_endpoint(dst, 0);

#ifdef TUNNEL_MODE
	/* Check if the source and destination IP has same subnet ID. */
	bool same_subnet_id = false;

	if (CONFIG(hybrid_routing_enabled)) {
		__u32 src_subnet_id = lookup_ip6_subnet_id((union v6addr *)&ip6->saddr);
		__u32 dst_subnet_id = lookup_ip6_subnet_id((union v6addr *)&ip6->daddr);

		same_subnet_id = (src_subnet_id == dst_subnet_id) && (src_subnet_id != 0);
	}
	if ((info && info->flag_skip_tunnel) || same_subnet_id)
		goto skip_tunnel;

	if (info && info->flag_has_tunnel_ep) {
		return encap_and_redirect_with_nodeid(ctx, info, secctx,
						      info->sec_identity,
						      &trace,
						      bpf_htons(ETH_P_IPV6));
	}
skip_tunnel:
#endif

	if (from_proxy) {
		ctx->mark = MARK_MAGIC_SKIP_TPROXY;
		return CTX_ACT_OK;
	}

	if (!info || identity_is_world_ipv6(info->sec_identity)) {
		/* See IPv4 comment. */
		return DROP_UNROUTABLE;
	}

	return CTX_ACT_OK;
}

static __always_inline int
tail_handle_ipv6_cont(struct __ctx_buff *ctx, __u32 src_sec_identity,
		      bool from_host, __s8 *ext_err)
{
	int ret;

	ret = handle_ipv6_cont(ctx, src_sec_identity, from_host, ext_err);
	if (from_host && ret == CTX_ACT_OK) {
		/* If we are attached to cilium_host at egress, this will
		 * rewrite the destination MAC address to the MAC of cilium_net.
		 */
		ret = rewrite_dmac_to_host(ctx);
	}

	return ret;
}

__declare_tail(CILIUM_CALL_IPV6_CONT_FROM_HOST)
static __always_inline
int tail_handle_ipv6_cont_from_host(struct __ctx_buff *ctx)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	__s8 ext_err = 0;
	int ret;

	ret = tail_handle_ipv6_cont(ctx, src_sec_identity, true, &ext_err);

	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  METRIC_INGRESS);

	return ret;
}

__declare_tail(CILIUM_CALL_IPV6_CONT_FROM_NETDEV)
static __always_inline
int tail_handle_ipv6_cont_from_netdev(struct __ctx_buff *ctx)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	__s8 ext_err = 0;
	int ret;

	ret = tail_handle_ipv6_cont(ctx, src_sec_identity, false, &ext_err);

	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  METRIC_INGRESS);

	return ret;
}

static __always_inline int
tail_handle_ipv6(struct __ctx_buff *ctx, __u32 ipcache_srcid, const bool from_host)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	bool punt_to_stack = false;
	int ret;
	__s8 ext_err = 0;

	ret = handle_ipv6(ctx, src_sec_identity, ipcache_srcid, from_host,
			  &punt_to_stack, &ext_err);

	/* TC_ACT_REDIRECT is not an error, but it means we should stop here. */
	if (ret == CTX_ACT_OK) {
		bool use_tailcall = is_defined(ENABLE_HOST_FIREWALL);

		if (punt_to_stack)
			return ret;

		if (use_tailcall) {
			ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);

			ret = tail_call_internal(ctx,
						 from_host ? CILIUM_CALL_IPV6_CONT_FROM_HOST :
							     CILIUM_CALL_IPV6_CONT_FROM_NETDEV,
						 &ext_err);
		} else {
			ret = tail_handle_ipv6_cont(ctx, src_sec_identity,
						    from_host, &ext_err);
		}
	}

	/* Catch errors from both handle_ipv6 and tail_call_internal here. */
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  METRIC_INGRESS);

	return ret;
}

__declare_tail(CILIUM_CALL_IPV6_FROM_HOST)
int tail_handle_ipv6_from_host(struct __ctx_buff *ctx)
{
	__u32 ipcache_srcid = 0;

#if defined(ENABLE_HOST_FIREWALL)
	ipcache_srcid = ctx_load_and_clear_meta(ctx, CB_IPCACHE_SRC_LABEL);
#endif /* defined(ENABLE_HOST_FIREWALL) */

	return tail_handle_ipv6(ctx, ipcache_srcid, true);
}

__declare_tail(CILIUM_CALL_IPV6_FROM_NETDEV)
int tail_handle_ipv6_from_netdev(struct __ctx_buff *ctx)
{
	return tail_handle_ipv6(ctx, 0, false);
}

# ifdef ENABLE_HOST_FIREWALL
static __always_inline int
handle_to_netdev_ipv6(struct __ctx_buff *ctx, __u32 src_sec_identity,
		      struct trace_ctx *trace, __s8 *ext_err)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u32 srcid = 0, ipcache_srcid = 0;
	int hdrlen, ret;
	__u8 nexthdr;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	if (likely(nexthdr == IPPROTO_ICMPV6)) {
		ret = icmp6_host_handle(ctx, ETH_HLEN + hdrlen, ext_err, false);
		if (ret == SKIP_HOST_FIREWALL)
			return CTX_ACT_OK;
		if (IS_ERR(ret))
			return ret;
	}

	/* The code below only cares about host-originating yes/no,
	 * and currently breaks when being passed a fine-grained pod src_sec_identity.
	 *
	 * Restore old behavior for now, and clean it up once we have tests.
	 */
	if (src_sec_identity != HOST_ID)
		src_sec_identity = 0;

	srcid = resolve_srcid_ipv6(ctx, ip6, src_sec_identity, &ipcache_srcid);

	/* to-netdev is attached to the egress path of the native device. */
	return ipv6_host_policy_egress(ctx, srcid, ipcache_srcid, ip6, trace, ext_err);
}
#endif /* ENABLE_HOST_FIREWALL */
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline __u32
resolve_srcid_ipv4(struct __ctx_buff *ctx, struct iphdr *ip4,
		   __u32 real_sec_identity, __u32 *ipcache_sec_identity)
{
	const struct remote_endpoint_info *info = NULL;

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(real_sec_identity)) {
		info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
		if (info != NULL) {
			*ipcache_sec_identity = info->sec_identity;

			/* When SNAT is enabled on traffic ingressing
			 * into Cilium, all traffic from the world will
			 * have a source IP of the host. It will only
			 * actually be from the host if "real_sec_identity"
			 * (passed into this function) reports the src as
			 * the host. So we can ignore the ipcache if it
			 * reports the source as HOST_ID.
			 */
			if (*ipcache_sec_identity != HOST_ID)
				real_sec_identity = *ipcache_sec_identity;
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->saddr, real_sec_identity);
	}

	return real_sec_identity;
}

static __always_inline int
handle_ipv4(struct __ctx_buff *ctx, __u32 secctx __maybe_unused,
	    __u32 ipcache_srcid __maybe_unused,
	    const bool from_host __maybe_unused,
	    bool *punt_to_stack __maybe_unused,
	    __s8 *ext_err __maybe_unused)
{
	struct ct_buffer4 __maybe_unused ct_buffer = {};
	bool __maybe_unused need_hostfw = false;
	bool __maybe_unused is_host_id = false;
	void *data, *data_end;
	struct iphdr *ip4;
	fraginfo_t fraginfo __maybe_unused;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
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
	if (!from_host) {
		if (!ctx_skip_nodeport(ctx)) {
			bool is_dsr = false;

			int ret = nodeport_lb4(ctx, ip4, ETH_HLEN, secctx, punt_to_stack,
					       ext_err, &is_dsr);

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
	}
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_HOST_FIREWALL
	if (from_host) {
		/* We're on the egress path of cilium_host. */
		if (ipv4_host_policy_egress_lookup(ctx, secctx, ipcache_srcid, ip4, &ct_buffer)) {
			if (unlikely(ct_buffer.ret < 0))
				return ct_buffer.ret;
			need_hostfw = true;
			is_host_id = secctx == HOST_ID;
		}
	} else if (!ctx_skip_host_fw(ctx)) {
		/* Verifier workaround: R5 invalid mem access 'scalar'. */
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		/* We're on the ingress path of the native device. */
		if (ipv4_host_policy_ingress_lookup(ctx, ip4, &ct_buffer)) {
			if (unlikely(ct_buffer.ret < 0))
				return ct_buffer.ret;
			need_hostfw = true;
		}
	}
	if (need_hostfw) {
		__u32 zero = 0;

		if (map_update_elem(&cilium_tail_call_buffer4, &zero, &ct_buffer, 0) < 0)
			return DROP_INVALID_TC_BUFFER;
	}

	ctx_store_meta(ctx, CB_FROM_HOST,
		       (need_hostfw ? FROM_HOST_FLAG_NEED_HOSTFW : 0) |
		       (is_host_id ? FROM_HOST_FLAG_HOST_ID : 0));
#endif /* ENABLE_HOST_FIREWALL */

	return CTX_ACT_OK;
}

static __always_inline int
handle_ipv4_cont(struct __ctx_buff *ctx, __u32 secctx, const bool from_host,
		 __s8 *ext_err __maybe_unused)
{
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	__u32 __maybe_unused from_host_raw;
	void *data, *data_end;
	struct iphdr *ip4;
	const struct remote_endpoint_info *info;
	const struct endpoint_info *ep;
	int ret __maybe_unused;
	__u32 magic = MARK_MAGIC_IDENTITY;
	bool from_proxy = false;

	if (from_host && tc_index_from_ingress_proxy(ctx)) {
		from_proxy = true;
		magic = MARK_MAGIC_PROXY_INGRESS;
	}
	if (from_host && tc_index_from_egress_proxy(ctx)) {
		from_proxy = true;
		magic = MARK_MAGIC_PROXY_EGRESS;
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

#ifdef ENABLE_HOST_FIREWALL
	from_host_raw = ctx_load_and_clear_meta(ctx, CB_FROM_HOST);

	if (from_host_raw & FROM_HOST_FLAG_NEED_HOSTFW) {
		struct ct_buffer4 *ct_buffer;
		__u32 zero = 0;
		__u32 remote_id = 0;

		ct_buffer = map_lookup_elem(&cilium_tail_call_buffer4, &zero);
		if (!ct_buffer)
			return DROP_INVALID_TC_BUFFER;
		if (ct_buffer->tuple.saddr == 0)
			/* The map value is zeroed so the map update didn't happen somehow. */
			return DROP_INVALID_TC_BUFFER;

		if (from_host) {
			bool is_host_id = from_host_raw & FROM_HOST_FLAG_HOST_ID;

			ret = __ipv4_host_policy_egress(ctx, is_host_id, ip4, ct_buffer, &trace,
							ext_err);
		} else {
			ret = __ipv4_host_policy_ingress(ctx, ip4, ct_buffer, &remote_id, &trace,
							 ext_err);
		}
		if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
			return ret;

		if (from_host) {
			if (!revalidate_data(ctx, &data, &data_end, &ip4))
				return DROP_INVALID;
		}
	}
#endif /* ENABLE_HOST_FIREWALL */

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
	if (!from_host)
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
		/* add L2 header for L2-less interface: */
		if (!from_host && THIS_IS_L3_DEV) {
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
		}
#endif

		return ipv4_local_delivery(ctx, l3_off, secctx, magic, ip4, ep,
					   METRIC_INGRESS, from_host, false, 0);
	}

	/* Below remainder is only relevant when traffic is pushed via cilium_host.
	 * For traffic coming from external, we're done here.
	 */
	if (!from_host)
		return CTX_ACT_OK;

	/* Handle VTEP integration in bpf_host to support pod L7 PROXY.
	 * It requires route setup to VTEP CIDR via dev cilium_host scope link.
	 */
#ifdef ENABLE_VTEP
	{
		struct remote_endpoint_info fake_info = {0};
		struct vtep_key vkey = {};
		const struct vtep_value *vtep;

		vkey.vtep_ip = ip4->daddr & CONFIG(vtep_mask);
		vtep = map_lookup_elem(&cilium_vtep_map, &vkey);
		if (!vtep)
			goto skip_vtep;

		if (vtep->vtep_mac && vtep->tunnel_endpoint) {
			if (eth_store_daddr(ctx, (__u8 *)&vtep->vtep_mac, 0) < 0)
				return DROP_WRITE_ERROR;
			fake_info.tunnel_endpoint.ip4 = vtep->tunnel_endpoint;
			fake_info.flag_has_tunnel_ep = true;
			return __encap_and_redirect_with_nodeid(ctx, &fake_info,
								secctx, WORLD_IPV4_ID,
								WORLD_IPV4_ID, &trace,
								bpf_htons(ETH_P_IP));
		}
	}
skip_vtep:
#endif

	info = lookup_ip4_remote_endpoint(ip4->daddr, 0);

#ifdef TUNNEL_MODE
	/* Check if the source and destination IP has same subnet ID. */
	bool same_subnet_id = false;
	/* Lookup the subnet IDs for the source and destination IPs in hybrid routing mode. */
	if (CONFIG(hybrid_routing_enabled)) {
		__u32 src_subnet_id = lookup_ip4_subnet_id(ip4->saddr);
		__u32 dst_subnet_id = lookup_ip4_subnet_id(ip4->daddr);

		same_subnet_id = (src_subnet_id == dst_subnet_id) && (src_subnet_id != 0);
	}
	if ((info && info->flag_skip_tunnel) || same_subnet_id)
		goto skip_tunnel;

	if (info && info->flag_has_tunnel_ep) {
		return encap_and_redirect_with_nodeid(ctx, info, secctx,
						      info->sec_identity,
						      &trace,
						      bpf_htons(ETH_P_IP));
	}
skip_tunnel:
#endif

	/* When a proxy's traffic couldn't be delivered by the preceding code,
	 * we let it pass through (for routing by the stack). To prevent
	 * tproxy-matching for transparent connections, we need to explicitly
	 * opt out.
	 *
	 * Traffic that lands here is eg to-world, or to-remote-pod (in native
	 * routing).
	 */
	if (from_proxy) {
		ctx->mark = MARK_MAGIC_SKIP_TPROXY;
		return CTX_ACT_OK;
	}

	if (!info || identity_is_world_ipv4(info->sec_identity)) {
		/* We have received a packet for which no ipcache entry exists,
		 * we do not know what to do with this packet, drop it.
		 *
		 * The info == NULL test is soley to satisfy verifier requirements
		 * as in Cilium case we'll always hit the 0.0.0.0/32 catch-all
		 * entry. Therefore we need to test for WORLD_ID. It is clearly
		 * wrong to route a ctx to cilium_host for which we don't know
		 * anything about it as otherwise we'll run into a routing loop.
		 */
		return DROP_UNROUTABLE;
	}

	return CTX_ACT_OK;
}

static __always_inline int
tail_handle_ipv4_cont(struct __ctx_buff *ctx, __u32 src_sec_identity,
		      bool from_host, __s8 *ext_err)
{
	int ret;

	ret = handle_ipv4_cont(ctx, src_sec_identity, from_host, ext_err);
	if (from_host && ret == CTX_ACT_OK) {
		/* If we are attached to cilium_host at egress, this will
		 * rewrite the destination MAC address to the MAC of cilium_net.
		 */
		ret = rewrite_dmac_to_host(ctx);
	}

	return ret;
}

__declare_tail(CILIUM_CALL_IPV4_CONT_FROM_HOST)
static __always_inline
int tail_handle_ipv4_cont_from_host(struct __ctx_buff *ctx)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	__s8 ext_err = 0;
	int ret;

	ret = tail_handle_ipv4_cont(ctx, src_sec_identity, true, &ext_err);

	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  METRIC_INGRESS);

	return ret;
}

__declare_tail(CILIUM_CALL_IPV4_CONT_FROM_NETDEV)
static __always_inline
int tail_handle_ipv4_cont_from_netdev(struct __ctx_buff *ctx)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	__s8 ext_err = 0;
	int ret;

	ret = tail_handle_ipv4_cont(ctx, src_sec_identity, false, &ext_err);

	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  METRIC_INGRESS);

	return ret;
}

static __always_inline int
tail_handle_ipv4(struct __ctx_buff *ctx, __u32 ipcache_srcid, const bool from_host)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	bool punt_to_stack = false;
	int ret;
	__s8 ext_err = 0;

	ret = handle_ipv4(ctx, src_sec_identity, ipcache_srcid, from_host,
			  &punt_to_stack, &ext_err);

	/* TC_ACT_REDIRECT is not an error, but it means we should stop here. */
	if (ret == CTX_ACT_OK) {
		bool use_tailcall = is_defined(ENABLE_HOST_FIREWALL);

		if (punt_to_stack)
			return ret;

		if (use_tailcall) {
			ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);

			ret = tail_call_internal(ctx,
						 from_host ? CILIUM_CALL_IPV4_CONT_FROM_HOST :
							     CILIUM_CALL_IPV4_CONT_FROM_NETDEV,
						 &ext_err);
		} else {
			ret = tail_handle_ipv4_cont(ctx, src_sec_identity,
						    from_host, &ext_err);
		}
	}

	/* Catch errors from both handle_ipv4 and tail_call_internal here. */
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  METRIC_INGRESS);

	return ret;
}

__declare_tail(CILIUM_CALL_IPV4_FROM_HOST)
int tail_handle_ipv4_from_host(struct __ctx_buff *ctx)
{
	__u32 ipcache_srcid = 0;

#if defined(ENABLE_HOST_FIREWALL)
	ipcache_srcid = ctx_load_and_clear_meta(ctx, CB_IPCACHE_SRC_LABEL);
#endif /* defined(ENABLE_HOST_FIREWALL) */

	return tail_handle_ipv4(ctx, ipcache_srcid, true);
}

__declare_tail(CILIUM_CALL_IPV4_FROM_NETDEV)
int tail_handle_ipv4_from_netdev(struct __ctx_buff *ctx)
{
	return tail_handle_ipv4(ctx, 0, false);
}

#ifdef ENABLE_HOST_FIREWALL
static __always_inline int
handle_to_netdev_ipv4(struct __ctx_buff *ctx, __u32 src_sec_identity,
		      struct trace_ctx *trace, __s8 *ext_err)
{
	void *data, *data_end;
	struct iphdr *ip4;
	__u32 src_id = 0, ipcache_srcid = 0;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* The code below only cares about host-originating yes/no,
	 * and currently breaks when being passed a fine-grained pod src_sec_identity.
	 *
	 * Restore old behavior for now, and clean it up once we have tests.
	 */
	if (src_sec_identity != HOST_ID)
		src_sec_identity = 0;

	src_id = resolve_srcid_ipv4(ctx, ip4, src_sec_identity, &ipcache_srcid);

	/* We need to pass the srcid from ipcache to host firewall. See
	 * comment in ipv4_host_policy_egress() for details.
	 */
	return ipv4_host_policy_egress(ctx, src_id, ipcache_srcid, ip4, trace, ext_err);
}
#endif /* ENABLE_HOST_FIREWALL */
#endif /* ENABLE_IPV4 */

static __always_inline int
do_netdev(struct __ctx_buff *ctx, __be16 proto, __u32 identity,
	  enum trace_point obs_point,  const bool __maybe_unused from_host)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	__u32 __maybe_unused ipcache_srcid = 0;
	enum metric_dir dir = METRIC_INGRESS;
	void __maybe_unused *data, *data_end;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	struct arp_eth __maybe_unused *arp;
	int __maybe_unused hdrlen = 0;
	__u8 __maybe_unused next_proto = 0;
	__s8 __maybe_unused ext_err = 0;
	int ret;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6)) {
			ret = DROP_INVALID;
			goto drop_err_ingress;
		}

		if (CONFIG(enable_l2_announcements) && ip6->nexthdr == NEXTHDR_ICMP) {
			ctx_pull_data(ctx, (__u32)ctx_full_len(ctx));
			if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
				ret = DROP_INVALID;
				goto drop_err_ingress;
			}
			ret = handle_l2_announcement(ctx, ip6);
			if (IS_ERR(ret))
				goto drop_err_egress;

			if (ret != CTX_ACT_OK)
				break;
			/* Verifier invalidates ip6 for some reason.. sigh*/
			if (!revalidate_data_pull(ctx, &data, &data_end, &ip6)) {
				ret = DROP_INVALID;
				goto drop_err_ingress;
			}
		}

		identity = resolve_srcid_ipv6(ctx, ip6, identity, &ipcache_srcid);
		ctx_store_meta(ctx, CB_SRC_LABEL, identity);

# if defined(ENABLE_HOST_FIREWALL)
		if (from_host)
			ctx_store_meta(ctx, CB_IPCACHE_SRC_LABEL, ipcache_srcid);
# endif /* defined(ENABLE_HOST_FIREWALL) */

# ifdef ENABLE_WIREGUARD
		if (!from_host) {
			next_proto = ip6->nexthdr;
			hdrlen = ipv6_hdrlen(ctx, &next_proto);
			if (likely(hdrlen > 0) &&
			    ctx_is_wireguard(ctx, ETH_HLEN + hdrlen, next_proto, identity)) {
				trace.reason = TRACE_REASON_ENCRYPTED;
				set_decrypt_mark(ctx, 0);
			}
		}
# endif /* ENABLE_WIREGUARD */

		send_trace_notify(ctx, obs_point, identity, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
				  ctx->ingress_ifindex, trace.reason, trace.monitor, proto);

		ret = tail_call_internal(ctx, from_host ? CILIUM_CALL_IPV6_FROM_HOST :
							  CILIUM_CALL_IPV6_FROM_NETDEV,
					 &ext_err);
		/* See comment below for IPv4. */
		return send_drop_notify_error_with_exitcode_ext(ctx, identity, ret, ext_err,
								CTX_ACT_OK, METRIC_INGRESS);
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		/* This is the first time revalidate_data() is going to be called.
		 * Make sure that we don't legitimately drop the packet if the skb
		 * arrived with the header not being not in the linear data.
		 */
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto drop_err_ingress;
		}

		identity = resolve_srcid_ipv4(ctx, ip4, identity, &ipcache_srcid);
		ctx_store_meta(ctx, CB_SRC_LABEL, identity);

# if defined(ENABLE_HOST_FIREWALL)
		if (from_host)
			ctx_store_meta(ctx, CB_IPCACHE_SRC_LABEL, ipcache_srcid);
# endif /* defined(ENABLE_HOST_FIREWALL) */

#ifdef ENABLE_WIREGUARD
		if (!from_host) {
			next_proto = ip4->protocol;
			hdrlen = ipv4_hdrlen(ip4);
			if (ctx_is_wireguard(ctx, ETH_HLEN + hdrlen, next_proto, identity)) {
				trace.reason = TRACE_REASON_ENCRYPTED;
				set_decrypt_mark(ctx, 0);
			}
		}
#endif /* ENABLE_WIREGUARD */

		send_trace_notify(ctx, obs_point, identity, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
				  ctx->ingress_ifindex, trace.reason, trace.monitor, proto);

		ret = tail_call_internal(ctx, from_host ? CILIUM_CALL_IPV4_FROM_HOST :
							  CILIUM_CALL_IPV4_FROM_NETDEV,
					 &ext_err);
		/* We are not returning an error here to always allow traffic to
		 * the stack in case maps have become unavailable.
		 *
		 * Note: Since drop notification requires a tail call as well,
		 * this notification is unlikely to succeed.
		 */
		return send_drop_notify_error_with_exitcode_ext(ctx, identity, ret, ext_err,
								CTX_ACT_OK, METRIC_INGRESS);
	case bpf_htons(ETH_P_ARP):
		if (!revalidate_data_arp_pull(ctx, &data, &data_end, &arp)) {
			ret = DROP_INVALID;
			goto drop_err_ingress;
		}

		send_trace_notify(ctx, obs_point, identity, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
				  ctx->ingress_ifindex, trace.reason, trace.monitor, proto);

		if (CONFIG(enable_l2_announcements)) {
			ret = handle_l2_announcement(ctx, NULL);
			if (IS_ERR(ret))
				goto drop_err_egress;
		} else {
			ret = CTX_ACT_OK;
		}

		break;
#endif /* ENABLE_IPV4 */
	default:
		send_trace_notify(ctx, obs_point, identity, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
				  ctx->ingress_ifindex, trace.reason, trace.monitor, proto);
#ifdef ENABLE_HOST_FIREWALL
		ret = DROP_UNKNOWN_L3;
		goto drop_err_ingress;
#else
		/* Pass unknown traffic to the stack */
		ret = CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */
	}

	return ret;

drop_err_egress: __maybe_unused
	dir = METRIC_EGRESS;
drop_err_ingress: __maybe_unused
	return send_drop_notify_error(ctx, identity, ret, dir);
}

/*
 * from-netdev is attached as a tc ingress filter to one or more physical devices
 * managed by Cilium (e.g., eth0).
 */
__section_entry
int cil_from_netdev(struct __ctx_buff *ctx)
{
	__u32 src_id = UNKNOWN_ID;
	__be16 proto = 0;

	bpf_clear_meta(ctx);

	check_and_store_ip_trace_id(ctx);

#ifdef ENABLE_NODEPORT_ACCELERATION
	__u32 flags = ctx_get_xfer(ctx, XFER_FLAGS);
#endif
	int ret;

	/* Filter allowed vlan id's and pass them back to kernel.
	 * We will see the packet again in from-netdev@eth0.vlanXXX.
	 */
	if (ctx->vlan_present) {
		__u32 vlan_id = ctx->vlan_tci & 0xfff;

		if (vlan_id) {
			if (allow_vlan(ctx->ifindex, vlan_id))
				return CTX_ACT_OK;

			ret = DROP_VLAN_FILTERED;
			goto drop_err;
		}
	}

	ctx_skip_nodeport_clear(ctx);

#ifdef ENABLE_NODEPORT_ACCELERATION
	if (flags & XFER_PKT_NO_SVC)
		ctx_skip_nodeport_set(ctx);

#ifdef HAVE_ENCAP
	if (flags & XFER_PKT_SNAT_DONE)
		ctx_snat_done_set(ctx);
#endif
#endif

	if (!validate_ethertype(ctx, &proto)) {
#ifdef ENABLE_HOST_FIREWALL
		ret = DROP_UNSUPPORTED_L2;
		goto drop_err;
#else
		send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, TRACE_IFINDEX_UNKNOWN,
				  TRACE_REASON_UNKNOWN, 0, proto);
		/* Pass unknown traffic to the stack */
		return CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */
	}

#ifdef ENABLE_IPSEC
	/* If the packet needs decryption, we want to send it straight to the
	 * stack. There's no need to run service handling logic, host firewall,
	 * etc. on an encrypted packet.
	 * In all other cases (packet doesn't need decryption or already
	 * decrypted), we want to run all subsequent logic here. We therefore
	 * ignore the return value from do_decrypt.
	 */
	ret = do_decrypt(ctx, proto);
	if (IS_ERR(ret))
		goto drop_err;

	if (ctx_is_decrypt(ctx))
		return CTX_ACT_OK;
#endif
	ret = tcx_early_hook(ctx, proto);
	if (ret != CTX_ACT_OK)
		return ret;

	return do_netdev(ctx, proto, UNKNOWN_ID, TRACE_FROM_NETWORK, false);
drop_err:
	return send_drop_notify_error(ctx, src_id, ret, METRIC_INGRESS);
}

/*
 * from-host is attached as a tc egress filter to the node's 'cilium_host'
 * interface if present.
 */
__section_entry
int cil_from_host(struct __ctx_buff *ctx)
{
	enum trace_point obs_point = TRACE_FROM_HOST;
	__u32 identity = UNKNOWN_ID;
	__be16 proto = 0;
	__u32 magic;

	bpf_clear_meta(ctx);

	check_and_store_ip_trace_id(ctx);

	/* Traffic from the host ns going through cilium_host device must
	 * not be subject to EDT rate-limiting.
	 */
	edt_set_aggregate(ctx, 0);

	if (!validate_ethertype(ctx, &proto)) {
		__u32 dst_sec_identity = UNKNOWN_ID;
		__u32 src_sec_identity = HOST_ID;

#ifdef ENABLE_HOST_FIREWALL
		return send_drop_notify(ctx, src_sec_identity, dst_sec_identity,
					TRACE_EP_ID_UNKNOWN, DROP_UNSUPPORTED_L2,
					METRIC_EGRESS);
#else
		send_trace_notify(ctx, TRACE_TO_STACK, src_sec_identity, dst_sec_identity,
				  TRACE_EP_ID_UNKNOWN, TRACE_IFINDEX_UNKNOWN,
				  TRACE_REASON_UNKNOWN, 0, proto);
		/* Pass unknown traffic to the stack */
		return CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */
	}

#if defined(ENABLE_L7_LB)
	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_PROXY_EGRESS_EPID) {
		__u16 lxc_id = get_epid(ctx);
		int ret;

		ctx->mark = 0;
		ret = tail_call_egress_policy(ctx, lxc_id);
		return send_drop_notify_error(ctx, UNKNOWN_ID, ret, METRIC_EGRESS);
	}
#endif

	magic = inherit_identity_from_host(ctx, &identity);
	if (magic == MARK_MAGIC_PROXY_INGRESS ||  magic == MARK_MAGIC_PROXY_EGRESS)
		obs_point = TRACE_FROM_PROXY;

	return do_netdev(ctx, proto, identity, obs_point, true);
}

/*
 * to-netdev is attached as a tc egress filter to one or more physical devices
 * managed by Cilium (e.g., eth0).
 */
__section_entry
int cil_to_netdev(struct __ctx_buff *ctx)
{
	__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;
	__u32 dst_sec_identity = UNKNOWN_ID;
	__u32 src_sec_identity = UNKNOWN_ID;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__be16 proto = 0;
	__u32 vlan_id;
	int ret = CTX_ACT_OK;
	__s8 ext_err = 0;

	bpf_clear_meta(ctx);
	check_and_store_ip_trace_id(ctx);

	if (magic == MARK_MAGIC_HOST || magic == MARK_MAGIC_OVERLAY || magic == MARK_MAGIC_ENCRYPT)
		src_sec_identity = HOST_ID;
	else if (magic == MARK_MAGIC_PROXY_EGRESS)
		src_sec_identity = get_identity(ctx);
#ifdef ENABLE_IDENTITY_MARK
	else if (magic == MARK_MAGIC_IDENTITY)
		src_sec_identity = get_identity(ctx);
#endif
#ifdef ENABLE_EGRESS_GATEWAY_COMMON
	else if (magic == MARK_MAGIC_EGW_DONE)
		src_sec_identity = get_identity(ctx);
#endif

	/* Load the ethertype just once: */
	validate_ethertype(ctx, &proto);

#ifdef ENABLE_IPSEC
	if (magic == MARK_MAGIC_ENCRYPT)
		send_trace_notify(ctx, TRACE_FROM_STACK,
				  get_encrypt_identity_meta(ctx), UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, ctx->ingress_ifindex,
				  TRACE_REASON_ENCRYPTED, 0, proto);
#endif /* ENABLE_IPSEC */

	/* Filter allowed vlan id's and pass them back to kernel.
	 */
	if (ctx->vlan_present) {
		vlan_id = ctx->vlan_tci & 0xfff;
		if (vlan_id) {
			if (allow_vlan(ctx->ifindex, vlan_id))
				return CTX_ACT_OK;

			ret = DROP_VLAN_FILTERED;
			goto drop_err;
		}
	}

#if defined(ENABLE_L7_LB)
	if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
		__u32 lxc_id = get_epid(ctx);

		ctx->mark = 0;
		ret = tail_call_egress_policy(ctx, (__u16)lxc_id);
		goto drop_err;
	}
#endif

#ifdef ENABLE_HOST_FIREWALL
	/* This was initially added for Egress GW. There it's no longer needed,
	 * but it potentially also helps other paths (LB-to-remote-backend ?).
	 */
	if (ctx_snat_done(ctx))
		goto skip_host_firewall;

	if (!eth_is_supported_ethertype(proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto drop_err;
	}

	switch (proto) {
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = handle_to_netdev_ipv6(ctx, src_sec_identity,
					    &trace, &ext_err);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		ret = handle_to_netdev_ipv4(ctx, src_sec_identity,
					    &trace, &ext_err);
		break;
	}
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

	if (ret == CTX_ACT_REDIRECT)
		return ret;

	if (IS_ERR(ret))
		goto drop_err;

skip_host_firewall:
#endif /* ENABLE_HOST_FIREWALL */

	ret = host_egress_policy_hook(ctx, src_sec_identity, &ext_err);
	if (IS_ERR(ret))
		goto drop_err;

#ifdef ENABLE_EGRESS_GATEWAY_COMMON
	/* If request arrived via from-overlay, don't redirect it again: */
	if (!ctx_egw_done(ctx)) {
		ret = egress_gw_handle_request(ctx, proto,
					       src_sec_identity, dst_sec_identity,
					       &trace);
		if (IS_ERR(ret))
			goto drop_err;

		if (ret != CTX_ACT_OK)
			return ret;
	}
#endif

#if defined(ENABLE_BANDWIDTH_MANAGER)
	ret = edt_sched_departure(ctx, proto);
	/* No send_drop_notify_error() here given we're rate-limiting. */
	if (ret < 0) {
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS, (__u8)-ret);
		return CTX_ACT_DROP;
	}
#endif

#if defined(ENABLE_IPSEC)
	if (!ctx_is_encrypt(ctx)) {
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto,
						      src_sec_identity);
		if (ret == CTX_ACT_REDIRECT)
			return ret;
		else if (IS_ERR(ret))
			goto drop_err;
	} else {
		trace.reason |= TRACE_REASON_ENCRYPTED;
	}
#endif /* ENABLE_IPSEC */

#ifdef ENABLE_WIREGUARD
	/* Redirect the packet to the WireGuard tunnel device for encryption
	 * if needed.
	 * We assume that a packet, which is a subject to the encryption, is
	 * NOT a subject to the BPF SNAT (happening below), as the former's
	 * destination resides in the cluster, while the latter - outside the
	 * cluster.
	 * Once the assumption is no longer true, we will need to recirculate
	 * the packet back to the "to-netdev" section for the SNAT instead of
	 * returning TC_ACT_REDIRECT.
	 *
	 * Skip redirect to the WireGuard tunnel device if the pkt has been
	 * already encrypted.
	 * After the packet has been encrypted, the WG tunnel device
	 * will set the MARK_MAGIC_ENCRYPT skb mark. So, to avoid
	 * looping forever (e.g., bpf_host@eth0 => cilium_wg0 =>
	 * bpf_host@eth0 => ...; this happens when eth0 is used to send
	 * encrypted WireGuard UDP packets), we check whether the mark
	 * is set before the redirect.
	 */
	if (!ctx_is_encrypt(ctx)) {
		ret = host_wg_encrypt_hook(ctx, proto, src_sec_identity);
		if (ret == CTX_ACT_REDIRECT)
			return ret;
		else if (IS_ERR(ret))
			goto drop_err;
	} else {
		trace.reason |= TRACE_REASON_ENCRYPTED;
	}
#endif /* ENABLE_WIREGUARD */

#if (defined(ENABLE_IPSEC) || defined(ENABLE_WIREGUARD)) &&		\
     defined(ENCRYPTION_STRICT_MODE_EGRESS)
	if (!strict_allow(ctx, proto)) {
		ret = DROP_UNENCRYPTED_TRAFFIC;
		goto drop_err;
	}
#endif /* ENCRYPTION_STRICT_MODE_EGRESS */

#ifdef ENABLE_HEALTH_CHECK
	ret = lb_handle_health(ctx, proto);
	if (ret != CTX_ACT_OK)
		goto exit;
#endif

#ifdef ENABLE_NODEPORT
	if (!ctx_snat_done(ctx) && !ctx_is_overlay(ctx) && !ctx_is_encrypt(ctx)) {
		/*
		 * handle_nat_fwd tail calls in the majority of cases,
		 * so control might never return to this program.
		 */
		ret = handle_nat_fwd(ctx, 0, src_sec_identity, proto, false, &trace, &ext_err);
		if (ret == CTX_ACT_REDIRECT)
			return ret;
	}
#endif

#ifdef ENABLE_HEALTH_CHECK
exit:
#endif
	if (IS_ERR(ret))
		goto drop_err;

	send_trace_notify(ctx, TRACE_TO_NETWORK, src_sec_identity, dst_sec_identity,
			  TRACE_EP_ID_UNKNOWN, CONFIG(interface_ifindex),
			  trace.reason, trace.monitor, proto);

	return ret;

drop_err:
	return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
					  METRIC_EGRESS);
}

#if defined(ENABLE_HOST_FIREWALL)
#ifdef ENABLE_IPV6
__declare_tail(CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY)
static __always_inline
int tail_ipv6_host_policy_ingress(struct __ctx_buff *ctx)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 src_id = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool traced = ctx_load_meta(ctx, CB_TRACED);
	__s8 ext_err = 0;
	int ret;

	ret = ipv6_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
						  METRIC_INGRESS);

	if (!traced)
		send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, CONFIG(cilium_host_ifindex),
				  trace.reason, trace.monitor, bpf_htons(ETH_P_IPV6));

	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
__declare_tail(CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY)
static __always_inline
int tail_ipv4_host_policy_ingress(struct __ctx_buff *ctx)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 src_id = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool traced = ctx_load_meta(ctx, CB_TRACED);
	__s8 ext_err = 0;
	int ret;

	ret = ipv4_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
						  METRIC_INGRESS);

	if (!traced)
		send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, CONFIG(cilium_host_ifindex),
				  trace.reason, trace.monitor, bpf_htons(ETH_P_IP));

	return ret;
}
#endif /* ENABLE_IPV4 */

static __always_inline
int host_ingress_policy(struct __ctx_buff *ctx, __be16 proto,
			__u32 src_sec_identity, bool traced, bool use_tailcall,
			__s8 *ext_err)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	int ret;

	switch (proto) {
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (use_tailcall) {
			ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
			ctx_store_meta(ctx, CB_TRACED, traced);
			ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY,
						 ext_err);
		} else {
			ret = ipv6_host_policy_ingress(ctx, &src_sec_identity,
						       &trace, ext_err);
		}

		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (use_tailcall) {
			ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
			ctx_store_meta(ctx, CB_TRACED, traced);
			ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY,
						 ext_err);
		} else {
			ret = ipv4_host_policy_ingress(ctx, &src_sec_identity,
						       &trace, ext_err);
		}

		break;
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

	if (IS_ERR(ret))
		return ret;

	if (!traced)
		send_trace_notify(ctx, TRACE_TO_STACK, src_sec_identity, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, CONFIG(cilium_host_ifindex),
				  trace.reason, trace.monitor, bpf_htons(proto));

	return ret;
}
#endif /* ENABLE_HOST_FIREWALL */

/*
 * to-host is attached as a tc ingress filter to both the 'cilium_host' and
 * 'cilium_net' devices if present.
 */
__section_entry
int cil_to_host(struct __ctx_buff *ctx)
{
	__u32 magic = ctx_load_meta(ctx, CB_PROXY_MAGIC);
	__be16 proto = 0;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	int ret = CTX_ACT_OK;
	bool traced = false;
	__u32 src_id = 0;
	__s8 ext_err = 0;

	check_and_store_ip_trace_id(ctx);

	/* Retrieve values carried only via ctx->mark. */
#ifdef ENABLE_IDENTITY_MARK
	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_IDENTITY)
		src_id = get_identity(ctx);
# ifdef ENABLE_WIREGUARD
	else if (ctx_is_decrypt(ctx))
		src_id = get_identity(ctx);
# endif
#endif

	/* Retrieve values carried either via ctx->mark or ctx->cb.
	 * Prefer ctx->mark when it is set to one of the expected values.
	 * Also see https://github.com/cilium/cilium/issues/36329.
	 */
	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_TO_PROXY)
		magic = ctx->mark;
#ifdef ENABLE_IPSEC
	else if (ctx_is_encrypt(ctx))
		magic = ctx->mark;
#endif

	if ((magic & 0xFFFF) == MARK_MAGIC_TO_PROXY) {
		/* Upper 16 bits may carry proxy port number */
		__be16 port = magic >> 16;
		/* We already traced this in the previous prog with more
		 * background context, skip trace here.
		 */
		traced = true;

		ctx_store_meta(ctx, CB_PROXY_MAGIC, 0);
		ret = ctx_redirect_to_proxy_first(ctx, port);
		goto out;
	}
#ifdef ENABLE_IPSEC
	else if ((magic & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT) {
		ctx->mark = magic; /* CB_ENCRYPT_MAGIC */
		src_id = get_encrypt_identity_meta(ctx);
	}
#endif

#ifdef ENABLE_IPSEC
#if !defined(TUNNEL_MODE)
	/* Since v1.18 Cilium performs IPsec encryption at the native device,
	 * before the packet leaves the host.
	 *
	 * A special case exists for L7 egress proxy packets when native routing
	 * mode is enabled.
	 *
	 * Because L7 egress proxy packets are generated in the host-namespace
	 * and generated packets MUST adjust their MTU for ESP encapsulation
	 * an IP route MTU adjustment exists for L7 egress proxy packets.
	 *
	 * When the L7 egress proxy generates packets an 'ip rule' in the host
	 * namespace routes these packets into table 2005 which has a route
	 * toward 'cilium_host' and adjusts the MTU correctly for ESP encap.
	 *
	 * When 'cil_from_host@cilium_host' is reached the skb's mark is zeroed
	 * and the packet is pushed toward 'cil_to_host@cilium_net'.
	 *
	 * If we simply let this packet drop to the stack, an iptables rule
	 * exists which will mark the packet with 0x200 and trigger a local
	 * delivery as part of L7 Proxy TPROXY mechanism.
	 *
	 * This iptables rule, created by
	 * iptables.Manager.inboundProxyRedirectRule() is ignored by the mark
	 * MARK_MAGIC_SKIP_TPROXY, in the control plane.
	 * Technically, it is also ignored by MARK_MAGIC_ENCRYPT but reusing
	 * this mark breaks further processing as its used in the XFRM subsystem.
	 *
	 * Therefore, if the packet's mark is zero, indicating it was forwarded
	 * from 'cilium_host', mark the packet with MARK_MAGIC_SKIP_TPROXY
	 * and allow it to enter the foward path once punted to stack.
	 */
	if (ctx->mark == 0 && CONFIG(interface_ifindex) == CONFIG(cilium_net_ifindex))
		ctx->mark = MARK_MAGIC_SKIP_TPROXY;
#endif /* !TUNNEL_MODE */

# ifdef ENABLE_NODEPORT
	if (!ctx_is_encrypt(ctx))
		goto skip_ipsec_nodeport_revdnat;

	if (!validate_ethertype(ctx, &proto))
		goto skip_ipsec_nodeport_revdnat;

	/* handle_nat_fwd() tail calls in the majority of cases, so control
	 * might never return to this program. Since IPsec is not compatible
	 * iwth Host Firewall, this won't be an issue.
	 */
	ret = handle_nat_fwd(ctx, 0, src_id, proto, true, &trace, &ext_err);
	if (IS_ERR(ret))
		goto out;

skip_ipsec_nodeport_revdnat:
# endif /* ENABLE_NODEPORT */

#endif /* ENABLE_IPSEC */
#ifdef ENABLE_HOST_FIREWALL
	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	ret = host_ingress_policy(ctx, proto, src_id, traced, true, &ext_err);
#else
	ret = CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */

out:
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
						  METRIC_INGRESS);

	if (!traced)
		send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN, CONFIG(cilium_host_ifindex),
				  trace.reason, trace.monitor, proto);

	return ret;
}

#ifdef ENABLE_HOST_FIREWALL
/* Handles packets that left the host namespace and will enter a local
 * endpoint's namespace. Applies egress host policies before handling
 * control back to bpf_lxc.
 */
static __always_inline int
from_host_to_lxc(struct __ctx_buff *ctx, __be16 proto, __s8 *ext_err)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	int ret = CTX_ACT_OK;
	void *data, *data_end;
	struct iphdr *ip4 __maybe_unused;
	struct ipv6hdr *ip6 __maybe_unused;

	switch (proto) {
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		ret = ipv6_host_policy_egress(ctx, HOST_ID, 0, ip6, &trace, ext_err);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		/* The third parameter, ipcache_srcid, is only required when
		 * the src_id is not HOST_ID.
		 * We only arrive here from bpf_lxc if we know the
		 * src_id is HOST_ID. Therefore, we don't need to pass a value
		 * for the last parameter. That avoids an ipcache lookup.
		 */
		ret = ipv4_host_policy_egress(ctx, HOST_ID, 0, ip4, &trace, ext_err);
		break;
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

	return ret;
}
#endif /* ENABLE_HOST_FIREWALL */

/* When per-endpoint routes are enabled, packets to and from local endpoints
 * will tail call into this program to enforce egress and ingress host policies.
 * Packets to the local endpoints will then tail call back to the original
 * bpf_lxc program.
 *
 * This program is not attached to a bpf hook directly, but instead inserted
 * into the global policy tail call map at a fixed index. It is marked as an
 * entry point since it can be invoked by bpf_lxc as soon as it's inserted into
 * the map, effectively making this object's code reachable from other parts of
 * the datapath.
 *
 * Care must be taken to insert it at a specific time in the host datapath setup
 * sequence to ensure no missed tail calls or policy bypass occurs. It is not
 * marked as a tail call since those programs are inserted automatically in
 * random order.
 */
__section_entry
int cil_host_policy(struct __ctx_buff *ctx __maybe_unused)
{
#ifdef ENABLE_HOST_FIREWALL
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	__u32 src_sec_identity;
	enum metric_dir dir;
	__be16 proto = 0;
	__s8 ext_err = 0;
	int ret;

	if (from_host) {
		src_sec_identity = HOST_ID;
		dir = METRIC_EGRESS;
	} else {
		src_sec_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
		dir = METRIC_INGRESS;
	}

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto drop_err;
	}

	if (from_host) {
		__u32 lxc_id = ctx_load_meta(ctx, CB_DST_ENDPOINT_ID);

		ret = from_host_to_lxc(ctx, proto, &ext_err);
		if (IS_ERR(ret))
			goto drop_err;

		local_delivery_fill_meta(ctx, src_sec_identity, false,
					 true, false, 0);
		ret = tail_call_policy(ctx, (__u16)lxc_id);
	} else {
		bool use_tailcall = (is_defined(ENABLE_IPV4) && is_defined(ENABLE_IPV6)) ||
				    is_defined(DEBUG);

		ret = host_ingress_policy(ctx, proto, src_sec_identity,
					  true, use_tailcall, &ext_err);
	}

drop_err:
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity,
						  ret, ext_err, dir);

	return ret;
#else
	return 0;
#endif /* ENABLE_HOST_FIREWALL */
}

BPF_LICENSE("Dual BSD/GPL");
