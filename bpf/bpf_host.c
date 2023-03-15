// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <ep_config.h>

#define IS_BPF_HOST 1

#define EVENT_SOURCE HOST_EP_ID

/* Host endpoint ID for the template bpf_host object file. Will be replaced
 * at compile-time with the proper host endpoint ID.
 */
#define TEMPLATE_HOST_EP_ID 0xffff

/* These are configuration options which have a default value in their
 * respective header files and must thus be defined beforehand:
 */
/* Pass unknown ICMPv6 NS to stack */
#define ACTION_UNKNOWN_ICMP6_NS CTX_ACT_OK

#ifndef VLAN_FILTER
# define VLAN_FILTER(ifindex, vlan_id) return false;
#endif

#include "lib/common.h"
#include "lib/edt.h"
#include "lib/arp.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/proxy.h"
#include "lib/trace.h"
#include "lib/identity.h"
#include "lib/l3.h"
#include "lib/l4.h"
#include "lib/drop.h"
#include "lib/encap.h"
#include "lib/nat.h"
#include "lib/lb.h"
#include "lib/nodeport.h"
#include "lib/eps.h"
#include "lib/host_firewall.h"
#include "lib/egress_policies.h"
#include "lib/overloadable.h"
#include "lib/encrypt.h"
#include "lib/wireguard.h"

/* Bit 0 is skipped for robustness, as it's used in some places to indicate from_host itself. */
#define FROM_HOST_FLAG_NEED_HOSTFW (1 << 1)
#define FROM_HOST_FLAG_HOST_ID (1 << 2)

static __always_inline bool allow_vlan(__u32 __maybe_unused ifindex, __u32 __maybe_unused vlan_id) {
	VLAN_FILTER(ifindex, vlan_id);
}

#if defined(ENABLE_IPV4) || defined(ENABLE_IPV6)
static __always_inline int rewrite_dmac_to_host(struct __ctx_buff *ctx,
						__u32 src_sec_identity)
{
	/* When attached to cilium_host, we rewrite the DMAC to the mac of
	 * cilium_host (peer) to ensure the packet is being considered to be
	 * addressed to the host (PACKET_HOST).
	 */
	union macaddr cilium_net_mac = CILIUM_NET_MAC;

	/* Rewrite to destination MAC of cilium_net (remote peer) */
	if (eth_store_daddr(ctx, (__u8 *) &cilium_net_mac.addr, 0) < 0)
		return send_drop_notify_error(ctx, src_sec_identity, DROP_WRITE_ERROR,
					      CTX_ACT_OK, METRIC_INGRESS);

	return CTX_ACT_OK;
}

#define SECCTX_FROM_IPCACHE_OK	2
#ifndef SECCTX_FROM_IPCACHE
# define SECCTX_FROM_IPCACHE	0
#endif

static __always_inline bool identity_from_ipcache_ok(void)
{
	return SECCTX_FROM_IPCACHE == SECCTX_FROM_IPCACHE_OK;
}
#endif

#ifdef ENABLE_IPV6
static __always_inline __u32
resolve_srcid_ipv6(struct __ctx_buff *ctx, struct ipv6hdr *ip6,
		   __u32 srcid_from_proxy, const bool from_host)
{
	__u32 src_id = WORLD_ID, srcid_from_ipcache = srcid_from_proxy;
	struct remote_endpoint_info *info = NULL;
	union v6addr *src;

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(srcid_from_ipcache)) {
		src = (union v6addr *) &ip6->saddr;
		info = lookup_ip6_remote_endpoint(src, 0);
		if (info) {
			if (info->sec_identity) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "srcid_from_proxy"
				 * (passed into this function) reports the src as
				 * the host. So we can ignore the ipcache if it
				 * reports the source as HOST_ID.
				 */
				if (info->sec_identity != HOST_ID)
					srcid_from_ipcache = info->sec_identity;
			}
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   ((__u32 *) src)[3], srcid_from_ipcache);
	}

	if (from_host)
		src_id = srcid_from_ipcache;
	else if (identity_from_ipcache_ok())
		src_id = srcid_from_ipcache;
	return src_id;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct ct_buffer6);
	__uint(max_entries, 1);
} CT_TAIL_CALL_BUFFER6 __section_maps_btf;

static __always_inline int
handle_ipv6(struct __ctx_buff *ctx, __u32 secctx __maybe_unused,
	    const bool from_host __maybe_unused,
	    __s8 *ext_err __maybe_unused)
{
	struct ct_buffer6 __maybe_unused ct_buffer = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int __maybe_unused ret;
	int hdrlen;
	__u8 nexthdr;
#ifdef ENABLE_HOST_FIREWALL
	bool need_hostfw = false;
#endif /* ENABLE_HOST_FIREWALL */

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

#ifdef ENABLE_HOST_FIREWALL
	if (likely(nexthdr == IPPROTO_ICMPV6)) {
		ret = icmp6_host_handle(ctx);
		if (ret == SKIP_HOST_FIREWALL)
			goto skip_host_firewall;
		if (IS_ERR(ret))
			return ret;
	}
#endif /* ENABLE_HOST_FIREWALL */

#ifdef ENABLE_NODEPORT
	if (!from_host) {
		if (!ctx_skip_nodeport(ctx)) {
			ret = nodeport_lb6(ctx, secctx, ext_err);
			/* nodeport_lb6() returns with TC_ACT_REDIRECT for
			 * traffic to L7 LB. Policy enforcement needs to take
			 * place after L7 LB has processed the packet, so we
			 * return to stack immediately here with
			 * TC_ACT_REDIRECT.
			 */
			if (ret < 0 || ret == TC_ACT_REDIRECT)
				return ret;
		}
	}
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_HOST_FIREWALL
	if (from_host) {
		if (ipv6_host_policy_egress_lookup(ctx, secctx, ip6, &ct_buffer)) {
			if (unlikely(ct_buffer.ret < 0))
				return ct_buffer.ret;
			need_hostfw = true;
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

		if (map_update_elem(&CT_TAIL_CALL_BUFFER6, &zero, &ct_buffer, 0) < 0)
			return DROP_INVALID_TC_BUFFER;
	}
#endif /* ENABLE_HOST_FIREWALL */

#ifdef ENABLE_HOST_FIREWALL
skip_host_firewall:
	ctx_store_meta(ctx, CB_FROM_HOST,
		       (need_hostfw ? FROM_HOST_FLAG_NEED_HOSTFW : 0));
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
	struct ct_buffer6 __maybe_unused *ct_buffer;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr *dst;
	int l3_off = ETH_HLEN;
	struct remote_endpoint_info *info = NULL;
	struct endpoint_info *ep;
	int ret;

#ifdef ENABLE_HOST_FIREWALL
	from_host_raw = ctx_load_meta(ctx, CB_FROM_HOST);
	ctx_store_meta(ctx, CB_FROM_HOST, 0);
#endif /* ENABLE_HOST_FIREWALL */

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

#ifdef ENABLE_HOST_FIREWALL
	if (from_host_raw & FROM_HOST_FLAG_NEED_HOSTFW) {
		__u32 zero = 0;
		__u32 remote_id = WORLD_ID;

		ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER6, &zero);
		if (!ct_buffer)
			return DROP_INVALID_TC_BUFFER;
		if (ct_buffer->tuple.saddr.d1 == 0 && ct_buffer->tuple.saddr.d2 == 0)
			/* The map value is zeroed so the map update didn't happen somehow. */
			return DROP_INVALID_TC_BUFFER;

		if (from_host)
			ret = __ipv6_host_policy_egress(ctx, ip6, ct_buffer, &trace, ext_err);
		else
			ret = __ipv6_host_policy_ingress(ctx, ip6, ct_buffer, &remote_id, &trace,
							 ext_err);
		if (IS_ERR(ret))
			return ret;
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
			ep_tail_call(ctx, CILIUM_CALL_SRV6_DECAP);
			return DROP_MISSED_TAIL_CALL;
		}
	}
#endif /* ENABLE_SRV6 */

#ifndef ENABLE_HOST_ROUTING
	/* See the equivalent v4 path for comments */
	if (!from_host)
		return CTX_ACT_OK;
#endif /* !ENABLE_HOST_ROUTING */

	if (from_host) {
		/* If we are attached to cilium_host at egress, this will
		 * rewrite the destination MAC address to the MAC of cilium_net.
		 */
		ret = rewrite_dmac_to_host(ctx, secctx);
		/* DIRECT PACKET READ INVALID */
		if (IS_ERR(ret))
			return ret;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
	}

	/* Lookup IPv6 address in list of local endpoints */
	ep = lookup_ip6_endpoint(ip6);
	if (ep) {
		bool l2_hdr_required __maybe_unused = true;

		/* Let through packets to the node-ip so they are
		 * processed by the local ip stack.
		 */
		if (ep->flags & ENDPOINT_F_HOST)
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
		return ipv6_local_delivery(ctx, l3_off, secctx, ep,
					   METRIC_INGRESS, from_host, false);
	}

	/* Below remainder is only relevant when traffic is pushed via cilium_host.
	 * For traffic coming from external, we're done here.
	 */
	if (!from_host)
		return CTX_ACT_OK;

	dst = (union v6addr *) &ip6->daddr;
	info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN, 0);

#ifdef TUNNEL_MODE
	if (info != NULL && info->tunnel_endpoint != 0) {
		return encap_and_redirect_with_nodeid(ctx, info->tunnel_endpoint,
						      info->node_id, secctx,
						      info->sec_identity,
						      &trace);
	} else {
		struct tunnel_key key = {};

		/* IPv6 lookup key: daddr/96 */
		key.ip6.p1 = dst->p1;
		key.ip6.p2 = dst->p2;
		key.ip6.p3 = dst->p3;
		key.ip6.p4 = 0;
		key.family = ENDPOINT_KEY_IPV6;

		ret = encap_and_redirect_netdev(ctx, &key, secctx, &trace);
		if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif

	if (!info || info->sec_identity == WORLD_ID) {
		/* See IPv4 comment. */
		return DROP_UNROUTABLE;
	}
	return CTX_ACT_OK;
}

static __always_inline int
tail_handle_ipv6_cont(struct __ctx_buff *ctx, bool from_host)
{
	__u32 proxy_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
	int ret;
	__s8 ext_err = 0;

	ctx_store_meta(ctx, CB_SRC_LABEL, 0);

	ret = handle_ipv6_cont(ctx, proxy_identity, from_host, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, proxy_identity, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}

declare_tailcall_if(is_defined(ENABLE_HOST_FIREWALL), CILIUM_CALL_IPV6_CONT_FROM_HOST)
int tail_handle_ipv6_cont_from_host(struct __ctx_buff *ctx)
{
	return tail_handle_ipv6_cont(ctx, true);
}

declare_tailcall_if(is_defined(ENABLE_HOST_FIREWALL), CILIUM_CALL_IPV6_CONT_FROM_NETDEV)
int tail_handle_ipv6_cont_from_netdev(struct __ctx_buff *ctx)
{
	return tail_handle_ipv6_cont(ctx, false);
}

static __always_inline int
tail_handle_ipv6(struct __ctx_buff *ctx, const bool from_host)
{
	__u32 proxy_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
	int ret;
	__s8 ext_err = 0;

	ctx_store_meta(ctx, CB_SRC_LABEL, 0);

	ret = handle_ipv6(ctx, proxy_identity, from_host, &ext_err);

	/* TC_ACT_REDIRECT is not an error, but it means we should stop here. */
	if (ret == CTX_ACT_OK) {
		ctx_store_meta(ctx, CB_SRC_LABEL, proxy_identity);
		if (from_host)
			invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
					   CILIUM_CALL_IPV6_CONT_FROM_HOST,
					   tail_handle_ipv6_cont_from_host);
		else
			invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
					   CILIUM_CALL_IPV6_CONT_FROM_NETDEV,
					   tail_handle_ipv6_cont_from_netdev);
	}

	/* Catch errors from both handle_ipv6 and invoke_tailcall_if here. */
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, proxy_identity, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_HOST)
int tail_handle_ipv6_from_host(struct __ctx_buff *ctx __maybe_unused)
{
	return tail_handle_ipv6(ctx, true);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_NETDEV)
int tail_handle_ipv6_from_netdev(struct __ctx_buff *ctx)
{
	return tail_handle_ipv6(ctx, false);
}

# ifdef ENABLE_HOST_FIREWALL
static __always_inline int
handle_to_netdev_ipv6(struct __ctx_buff *ctx, struct trace_ctx *trace, __s8 *ext_err)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u32 src_id = 0;
	int hdrlen, ret;
	__u8 nexthdr;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

#ifdef ENABLE_HOST_FIREWALL
	if (likely(nexthdr == IPPROTO_ICMPV6)) {
		ret = icmp6_host_handle(ctx);
		if (ret == SKIP_HOST_FIREWALL)
			return CTX_ACT_OK;
		if (IS_ERR(ret))
			return ret;
	}
#endif /* ENABLE_HOST_FIREWALL */

	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_HOST)
		src_id = HOST_ID;
	src_id = resolve_srcid_ipv6(ctx, ip6, src_id, true);

	/* to-netdev is attached to the egress path of the native device. */
	return ipv6_host_policy_egress(ctx, src_id, ip6, trace, ext_err);
}
#endif /* ENABLE_HOST_FIREWALL */
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline __u32
resolve_srcid_ipv4(struct __ctx_buff *ctx, struct iphdr *ip4,
		   __u32 srcid_from_proxy, __u32 *sec_identity,
		   const bool from_host)
{
	__u32 src_id = WORLD_ID, srcid_from_ipcache = srcid_from_proxy;
	struct remote_endpoint_info *info = NULL;

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(srcid_from_ipcache)) {
		info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
		if (info != NULL) {
			*sec_identity = info->sec_identity;

			if (*sec_identity) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "srcid_from_proxy"
				 * (passed into this function) reports the src as
				 * the host. So we can ignore the ipcache if it
				 * reports the source as HOST_ID.
				 */
				if (*sec_identity != HOST_ID)
					srcid_from_ipcache = *sec_identity;
			}
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->saddr, srcid_from_ipcache);
	}

	if (from_host)
		src_id = srcid_from_ipcache;
	/* If we could not derive the secctx from the packet itself but
	 * from the ipcache instead, then use the ipcache identity.
	 */
	else if (identity_from_ipcache_ok())
		src_id = srcid_from_ipcache;
	return src_id;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct ct_buffer4);
	__uint(max_entries, 1);
} CT_TAIL_CALL_BUFFER4 __section_maps_btf;

static __always_inline int
handle_ipv4(struct __ctx_buff *ctx, __u32 secctx __maybe_unused,
	    __u32 ipcache_srcid __maybe_unused,
	    const bool from_host __maybe_unused,
	    __s8 *ext_err __maybe_unused)
{
	struct ct_buffer4 __maybe_unused ct_buffer = {};
	void *data, *data_end;
	struct iphdr *ip4;
#ifdef ENABLE_HOST_FIREWALL
	bool need_hostfw = false;
	bool is_host_id = false;
#endif /* ENABLE_HOST_FIREWALL */

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
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
	if (!from_host) {
		if (!ctx_skip_nodeport(ctx)) {
			int ret = nodeport_lb4(ctx, secctx, ext_err);

			if (ret == NAT_46X64_RECIRC) {
				ctx_store_meta(ctx, CB_SRC_LABEL, secctx);
				ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
				return DROP_MISSED_TAIL_CALL;
			}

			/* nodeport_lb4() returns with TC_ACT_REDIRECT for
			 * traffic to L7 LB. Policy enforcement needs to take
			 * place after L7 LB has processed the packet, so we
			 * return to stack immediately here with
			 * TC_ACT_REDIRECT.
			 */
			if (ret < 0 || ret == TC_ACT_REDIRECT)
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

		if (map_update_elem(&CT_TAIL_CALL_BUFFER4, &zero, &ct_buffer, 0) < 0)
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
	struct ct_buffer4 __maybe_unused *ct_buffer = NULL;
	void *data, *data_end;
	struct iphdr *ip4;
	struct remote_endpoint_info *info;
	struct endpoint_info *ep;
	int ret;

#ifdef ENABLE_HOST_FIREWALL
	from_host_raw = ctx_load_meta(ctx, CB_FROM_HOST);
	ctx_store_meta(ctx, CB_FROM_HOST, 0);
#endif /* ENABLE_HOST_FIREWALL */

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

#ifdef ENABLE_HOST_FIREWALL
	if (from_host_raw & FROM_HOST_FLAG_NEED_HOSTFW) {
		__u32 zero = 0;
		__u32 remote_id = 0;

		ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER4, &zero);
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
		if (IS_ERR(ret))
			return ret;
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

	if (from_host) {
		/* If we are attached to cilium_host at egress, this will
		 * rewrite the destination MAC address to the MAC of cilium_net.
		 */
		ret = rewrite_dmac_to_host(ctx, secctx);
		/* DIRECT PACKET READ INVALID */
		if (IS_ERR(ret))
			return ret;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
	}

	/* Lookup IPv4 address in list of local endpoints and host IPs */
	ep = lookup_ip4_endpoint(ip4);
	if (ep) {
		bool l2_hdr_required __maybe_unused = true;
		int l3_off __maybe_unused = ETH_HLEN;

		/* Let through packets to the node-ip so they are processed by
		 * the local ip stack.
		 */
		if (ep->flags & ENDPOINT_F_HOST)
			return CTX_ACT_OK;

#ifdef ENABLE_HOST_ROUTING
		/* add L2 header for L2-less interface, such as cilium_wg0 */
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
#endif

		return ipv4_local_delivery(ctx, l3_off, secctx, ip4, ep,
					   METRIC_INGRESS, from_host, false,
					   false, 0);
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
		struct vtep_key vkey = {};
		struct vtep_value *vtep;

		vkey.vtep_ip = ip4->daddr & VTEP_MASK;
		vtep = map_lookup_elem(&VTEP_MAP, &vkey);
		if (!vtep)
			goto skip_vtep;

		if (vtep->vtep_mac && vtep->tunnel_endpoint) {
			if (eth_store_daddr(ctx, (__u8 *)&vtep->vtep_mac, 0) < 0)
				return DROP_WRITE_ERROR;
			return __encap_and_redirect_with_nodeid(ctx, 0, vtep->tunnel_endpoint,
								secctx, WORLD_ID, WORLD_ID, &trace);
		}
	}
skip_vtep:
#endif

	info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN, 0);

#ifdef TUNNEL_MODE
	if (info != NULL && info->tunnel_endpoint != 0) {
		return encap_and_redirect_with_nodeid(ctx, info->tunnel_endpoint,
						      info->node_id, secctx,
						      info->sec_identity,
						      &trace);
	} else {
		/* IPv4 lookup key: daddr & IPV4_MASK */
		struct tunnel_key key = {};

		key.ip4 = ip4->daddr & IPV4_MASK;
		key.family = ENDPOINT_KEY_IPV4;

		cilium_dbg(ctx, DBG_NETDEV_ENCAP4, key.ip4, secctx);
		ret = encap_and_redirect_netdev(ctx, &key, secctx, &trace);
		if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif

	if (!info || info->sec_identity == WORLD_ID) {
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
tail_handle_ipv4_cont(struct __ctx_buff *ctx, bool from_host)
{
	__u32 proxy_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
	int ret;
	__s8 ext_err = 0;

	ctx_store_meta(ctx, CB_SRC_LABEL, 0);

	ret = handle_ipv4_cont(ctx, proxy_identity, from_host, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, proxy_identity, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}

declare_tailcall_if(is_defined(ENABLE_HOST_FIREWALL), CILIUM_CALL_IPV4_CONT_FROM_HOST)
int tail_handle_ipv4_cont_from_host(struct __ctx_buff *ctx)
{
	return tail_handle_ipv4_cont(ctx, true);
}

declare_tailcall_if(is_defined(ENABLE_HOST_FIREWALL), CILIUM_CALL_IPV4_CONT_FROM_NETDEV)
int tail_handle_ipv4_cont_from_netdev(struct __ctx_buff *ctx)
{
	return tail_handle_ipv4_cont(ctx, false);
}

static __always_inline int
tail_handle_ipv4(struct __ctx_buff *ctx, __u32 ipcache_srcid, const bool from_host)
{
	__u32 proxy_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
	int ret;
	__s8 ext_err = 0;

	ctx_store_meta(ctx, CB_SRC_LABEL, 0);

	ret = handle_ipv4(ctx, proxy_identity, ipcache_srcid, from_host, &ext_err);

	/* TC_ACT_REDIRECT is not an error, but it means we should stop here. */
	if (ret == CTX_ACT_OK) {
		ctx_store_meta(ctx, CB_SRC_LABEL, proxy_identity);
		if (from_host)
			invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
					   CILIUM_CALL_IPV4_CONT_FROM_HOST,
					   tail_handle_ipv4_cont_from_host);
		else
			invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
					   CILIUM_CALL_IPV4_CONT_FROM_NETDEV,
					   tail_handle_ipv4_cont_from_netdev);
	}

	/* Catch errors from both handle_ipv4 and invoke_tailcall_if here. */
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, proxy_identity, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_HOST)
int tail_handle_ipv4_from_host(struct __ctx_buff *ctx)
{
	__u32 ipcache_srcid = 0;

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE)
	ipcache_srcid = ctx_load_meta(ctx, CB_IPCACHE_SRC_LABEL);
	ctx_store_meta(ctx, CB_IPCACHE_SRC_LABEL, 0);
#endif

	return tail_handle_ipv4(ctx, ipcache_srcid, true);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_NETDEV)
int tail_handle_ipv4_from_netdev(struct __ctx_buff *ctx)
{
	return tail_handle_ipv4(ctx, 0, false);
}

#ifdef ENABLE_HOST_FIREWALL
static __always_inline int
handle_to_netdev_ipv4(struct __ctx_buff *ctx, struct trace_ctx *trace, __s8 *ext_err)
{
	void *data, *data_end;
	struct iphdr *ip4;
	__u32 src_id = 0, ipcache_srcid = 0;

	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_HOST)
		src_id = HOST_ID;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	src_id = resolve_srcid_ipv4(ctx, ip4, src_id, &ipcache_srcid, true);

	/* We need to pass the srcid from ipcache to host firewall. See
	 * comment in ipv4_host_policy_egress() for details.
	 */
	return ipv4_host_policy_egress(ctx, src_id, ipcache_srcid, ip4, trace, ext_err);
}
#endif /* ENABLE_HOST_FIREWALL */
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPSEC
#ifndef TUNNEL_MODE
static __always_inline int
do_netdev_encrypt(struct __ctx_buff *ctx __maybe_unused,
		  __u32 src_id __maybe_unused)
{
	return CTX_ACT_OK;
}

#else /* TUNNEL_MODE */
static __always_inline int do_netdev_encrypt_encap(struct __ctx_buff *ctx, __u32 src_id)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_ENCRYPTED,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	struct remote_endpoint_info *ep = NULL;
	void *data, *data_end;
	struct ipv6hdr *ip6 __maybe_unused;
	struct iphdr *ip4 __maybe_unused;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
		ep = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
		break;
# endif /* ENABLE_IPV6 */
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		ep = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		break;
# endif /* ENABLE_IPV4 */
	}
	if (!ep || !ep->tunnel_endpoint)
		return DROP_NO_TUNNEL_ENDPOINT;

	ctx->mark = 0;
	bpf_clear_meta(ctx);
	return __encap_and_redirect_with_nodeid(ctx, 0, ep->tunnel_endpoint,
						src_id, 0, NOT_VTEP_DST,
						&trace);
}

static __always_inline int do_netdev_encrypt(struct __ctx_buff *ctx,
					     __u32 src_id)
{
	return do_netdev_encrypt_encap(ctx, src_id);
}
#endif /* TUNNEL_MODE */
#endif /* ENABLE_IPSEC */

static __always_inline int
do_netdev(struct __ctx_buff *ctx, __u16 proto, const bool from_host)
{
	__u32 __maybe_unused identity = 0;
	__u32 __maybe_unused ipcache_srcid = 0;
	void __maybe_unused *data, *data_end;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	int ret;

#if defined(ENABLE_L7_LB)
	if (from_host) {
		__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;

		if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
			__u32 lxc_id = get_epid(ctx);

			ctx->mark = 0;
			tail_call_dynamic(ctx, &POLICY_EGRESSCALL_MAP, lxc_id);
			return send_drop_notify_error(ctx, identity, DROP_MISSED_TAIL_CALL,
						      CTX_ACT_DROP, METRIC_EGRESS);
		}
	}
#endif

#ifdef ENABLE_IPSEC
	if (!from_host && !do_decrypt(ctx, proto))
		return CTX_ACT_OK;
#endif

	if (from_host) {
		__u32 magic;
		enum trace_point trace = TRACE_FROM_HOST;

		magic = inherit_identity_from_host(ctx, &identity);
		if (magic == MARK_MAGIC_PROXY_INGRESS ||  magic == MARK_MAGIC_PROXY_EGRESS)
			trace = TRACE_FROM_PROXY;

#ifdef ENABLE_IPSEC
		if (magic == MARK_MAGIC_ENCRYPT) {
			send_trace_notify(ctx, TRACE_FROM_STACK, identity, 0, 0,
					  ctx->ingress_ifindex, TRACE_REASON_ENCRYPTED,
					  TRACE_PAYLOAD_LEN);
			ret = do_netdev_encrypt(ctx, identity);
			if (IS_ERR(ret))
				return send_drop_notify_error(ctx, identity, ret,
							      CTX_ACT_DROP, METRIC_EGRESS);
			return ret;
		}
#endif

		send_trace_notify(ctx, trace, identity, 0, 0,
				  ctx->ingress_ifindex,
				  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);
	} else {
		send_trace_notify(ctx, TRACE_FROM_NETWORK, 0, 0, 0,
				  ctx->ingress_ifindex,
				  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);
	}

	bpf_clear_meta(ctx);

	switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			return send_drop_notify_error(ctx, identity, DROP_INVALID,
						      CTX_ACT_DROP, METRIC_INGRESS);

		identity = resolve_srcid_ipv6(ctx, ip6, identity, from_host);
		ctx_store_meta(ctx, CB_SRC_LABEL, identity);
		if (from_host)
			ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_HOST);
		else
			ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
		/* See comment below for IPv4. */
		return send_drop_notify_error(ctx, identity, DROP_MISSED_TAIL_CALL,
					      CTX_ACT_OK, METRIC_INGRESS);
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		/* This is the first time revalidate_data() is going to be called.
		 * Make sure that we don't legitimately drop the packet if the skb
		 * arrived with the header not being not in the linear data.
		 */
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return send_drop_notify_error(ctx, identity, DROP_INVALID,
						      CTX_ACT_DROP, METRIC_INGRESS);

		identity = resolve_srcid_ipv4(ctx, ip4, identity, &ipcache_srcid,
					      from_host);
		ctx_store_meta(ctx, CB_SRC_LABEL, identity);
		if (from_host) {
# if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE)
			/* If we don't rely on BPF-based masquerading, we need
			 * to pass the srcid from ipcache to host firewall. See
			 * comment in ipv4_host_policy_egress() for details.
			 */
			ctx_store_meta(ctx, CB_IPCACHE_SRC_LABEL, ipcache_srcid);
# endif
			ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_HOST);
		} else {
			ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_NETDEV);
		}
		/* We are not returning an error here to always allow traffic to
		 * the stack in case maps have become unavailable.
		 *
		 * Note: Since drop notification requires a tail call as well,
		 * this notification is unlikely to succeed.
		 */
		return send_drop_notify_error(ctx, identity, DROP_MISSED_TAIL_CALL,
					      CTX_ACT_OK, METRIC_INGRESS);
#endif
	default:
#ifdef ENABLE_HOST_FIREWALL
		ret = send_drop_notify_error(ctx, identity, DROP_UNKNOWN_L3,
					     CTX_ACT_DROP, METRIC_INGRESS);
#else
		/* Pass unknown traffic to the stack */
		ret = CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */
	}

	return ret;
}

/**
 * handle_netdev
 * @ctx		The packet context for this program
 * @from_host	True if the packet is from the local host
 *
 * Handle netdev traffic coming towards the Cilium-managed network.
 */
static __always_inline int
handle_netdev(struct __ctx_buff *ctx, const bool from_host)
{
	__u16 proto;

	if (!validate_ethertype(ctx, &proto)) {
#ifdef ENABLE_HOST_FIREWALL
		int ret = DROP_UNSUPPORTED_L2;

		return send_drop_notify(ctx, SECLABEL, WORLD_ID, 0, ret,
					CTX_ACT_DROP, METRIC_EGRESS);
#else
		send_trace_notify(ctx, TRACE_TO_STACK, HOST_ID, 0, 0, 0,
				  TRACE_REASON_UNKNOWN, 0);
		/* Pass unknown traffic to the stack */
		return CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */
	}

	return do_netdev(ctx, proto, from_host);
}

#ifdef ENABLE_SRV6
static __always_inline int
handle_srv6(struct __ctx_buff *ctx)
{
	__u32 *vrf_id, dst_sec_identity;
	struct srv6_ipv6_2tuple *outer_ips;
	struct iphdr *ip4 __maybe_unused;
	struct remote_endpoint_info *ep;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr *sid;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		outer_ips = srv6_lookup_state_entry6(ip6);
		if (outer_ips) {
			ep_tail_call(ctx, CILIUM_CALL_SRV6_REPLY);
			return DROP_MISSED_TAIL_CALL;
		}

		ep = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
		if (ep) {
			dst_sec_identity = ep->sec_identity;
		} else {
			dst_sec_identity = WORLD_ID;
		}

		if (identity_is_cluster(dst_sec_identity))
			return CTX_ACT_OK;

		vrf_id = srv6_lookup_vrf6(&ip6->saddr, &ip6->daddr);
		if (!vrf_id)
			return CTX_ACT_OK;

		sid = srv6_lookup_policy6(*vrf_id, &ip6->daddr);
		if (!sid)
			return CTX_ACT_OK;

		srv6_store_meta_sid(ctx, sid);
		ctx_store_meta(ctx, CB_SRV6_VRF_ID, *vrf_id);
		ep_tail_call(ctx, CILIUM_CALL_SRV6_ENCAP);
		return DROP_MISSED_TAIL_CALL;
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		outer_ips = srv6_lookup_state_entry4(ip4);
		if (outer_ips) {
			ep_tail_call(ctx, CILIUM_CALL_SRV6_REPLY);
			return DROP_MISSED_TAIL_CALL;
		}

		ep = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (ep) {
			dst_sec_identity = ep->sec_identity;
		} else {
			dst_sec_identity = WORLD_ID;
		}

		if (identity_is_cluster(dst_sec_identity))
			return CTX_ACT_OK;

		vrf_id = srv6_lookup_vrf4(ip4->saddr, ip4->daddr);
		if (!vrf_id)
			return CTX_ACT_OK;

		sid = srv6_lookup_policy4(*vrf_id, ip4->daddr);
		if (!sid)
			return CTX_ACT_OK;

		srv6_store_meta_sid(ctx, sid);
		ctx_store_meta(ctx, CB_SRV6_VRF_ID, *vrf_id);
		ep_tail_call(ctx, CILIUM_CALL_SRV6_ENCAP);
		return DROP_MISSED_TAIL_CALL;
		break;
# endif
	}

	return CTX_ACT_OK;
}
#endif /* ENABLE_SRV6 */

/*
 * from-netdev is attached as a tc ingress filter to one or more physical devices
 * managed by Cilium (e.g., eth0). This program is only attached when:
 * - the host firewall is enabled, or
 * - BPF NodePort is enabled, or
 * - WireGuard's host-to-host encryption and BPF NodePort are enabled
 */
__section("from-netdev")
int cil_from_netdev(struct __ctx_buff *ctx)
{
	__u32 __maybe_unused src_id = 0;

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

#ifdef ENABLE_HIGH_SCALE_IPCACHE
	ret = decapsulate_overlay(ctx, &src_id);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, src_id, ret, CTX_ACT_DROP,
				       METRIC_INGRESS);
	if (ret == CTX_ACT_REDIRECT)
		return ret;
#endif /* ENABLE_HIGH_SCALE_IPCACHE */

	return handle_netdev(ctx, false);

drop_err:
	return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_INGRESS);
}

/*
 * from-host is attached as a tc egress filter to the node's 'cilium_host'
 * interface if present.
 */
__section("from-host")
int cil_from_host(struct __ctx_buff *ctx)
{
	/* Traffic from the host ns going through cilium_host device must
	 * not be subject to EDT rate-limiting.
	 */
	edt_set_aggregate(ctx, 0);
	return handle_netdev(ctx, true);
}

/*
 * to-netdev is attached as a tc egress filter to one or more physical devices
 * managed by Cilium (e.g., eth0). This program is only attached when:
 * - the host firewall is enabled, or
 * - BPF NodePort is enabled
 */
__section("to-netdev")
int cil_to_netdev(struct __ctx_buff *ctx __maybe_unused)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u16 __maybe_unused proto = 0;
	__u32 __maybe_unused vlan_id;
	int ret = CTX_ACT_OK;
#ifdef ENABLE_HOST_FIREWALL
	__s8 ext_err = 0;
#endif

	/* Filter allowed vlan id's and pass them back to kernel.
	 */
	if (ctx->vlan_present) {
		vlan_id = ctx->vlan_tci & 0xfff;
		if (vlan_id) {
			if (allow_vlan(ctx->ifindex, vlan_id))
				return CTX_ACT_OK;
			else
				return send_drop_notify_error(ctx, 0, DROP_VLAN_FILTERED,
							      CTX_ACT_DROP, METRIC_EGRESS);
		}
	}

#if defined(ENABLE_L7_LB)
	{
		__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;

		if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
			__u32 lxc_id = get_epid(ctx);

			ctx->mark = 0;
			tail_call_dynamic(ctx, &POLICY_EGRESSCALL_MAP, lxc_id);
			return send_drop_notify_error(ctx, 0, DROP_MISSED_TAIL_CALL,
						      CTX_ACT_DROP, METRIC_EGRESS);
		}
	}
#endif

#ifdef ENABLE_HOST_FIREWALL
	if (!proto && !validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	policy_clear_mark(ctx);

	switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = handle_to_netdev_ipv6(ctx, &trace, &ext_err);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		ret = handle_to_netdev_ipv4(ctx, &trace, &ext_err);
		break;
	}
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}
out:
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, 0, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);
#endif /* ENABLE_HOST_FIREWALL */

#if defined(ENABLE_BANDWIDTH_MANAGER)
	ret = edt_sched_departure(ctx);
	/* No send_drop_notify_error() here given we're rate-limiting. */
	if (ret == CTX_ACT_DROP) {
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
			       -DROP_EDT_HORIZON);
		return ret;
	}
#endif

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
	 */
	ret = wg_maybe_redirect_to_encrypt(ctx);
	if (ret == CTX_ACT_REDIRECT)
		return ret;
	else if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);
#endif /* ENABLE_WIREGUARD */

#ifdef ENABLE_SRV6
	ret = handle_srv6(ctx);
	if (ret != CTX_ACT_OK)
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);
#endif /* ENABLE_SRV6 */

#ifdef ENABLE_NODEPORT
	if (!ctx_snat_done(ctx)) {
		/*
		 * handle_nat_fwd tail calls in the majority of cases,
		 * so control might never return to this program.
		 */
		ret = handle_nat_fwd(ctx, 0);
		if (IS_ERR(ret))
			return send_drop_notify_error(ctx, 0, ret,
						      CTX_ACT_DROP,
						      METRIC_EGRESS);
	}
#endif
#ifdef ENABLE_HEALTH_CHECK
	ret = lb_handle_health(ctx);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);
#endif
	send_trace_notify(ctx, TRACE_TO_NETWORK, 0, 0, 0,
			  0, trace.reason, trace.monitor);

	return ret;
}

/*
 * to-host is attached as a tc ingress filter to both the 'cilium_host' and
 * 'cilium_net' devices if present.
 */
__section("to-host")
int cil_to_host(struct __ctx_buff *ctx)
{
	__u32 magic = ctx_load_meta(ctx, CB_PROXY_MAGIC);
	__u16 __maybe_unused proto = 0;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	int ret = CTX_ACT_OK;
	bool traced = false;
	__u32 src_id = 0;
	__s8 ext_err = 0;

	if ((magic & 0xFFFF) == MARK_MAGIC_TO_PROXY) {
		/* Upper 16 bits may carry proxy port number */
		__be16 port = magic >> 16;

		ctx_store_meta(ctx, CB_PROXY_MAGIC, 0);
		ret = ctx_redirect_to_proxy_first(ctx, port);
		if (IS_ERR(ret))
			goto out;
		/* We already traced this in the previous prog with more
		 * background context, skip trace here.
		 */
		traced = true;
	}

#ifdef ENABLE_IPSEC
	/* Encryption stack needs this when IPSec headers are
	 * rewritten without FIB helper because we do not yet
	 * know correct MAC address which will cause the stack
	 * to mark as PACKET_OTHERHOST and drop.
	 */
	ctx_change_type(ctx, PACKET_HOST);
#endif
#ifdef ENABLE_HOST_FIREWALL
	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	policy_clear_mark(ctx);

	switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = ipv6_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = ipv4_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
		break;
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}
#else
	ret = CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */

out:
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);

	if (!traced)
		send_trace_notify(ctx, TRACE_TO_STACK, src_id, 0, 0,
				  CILIUM_IFINDEX, trace.reason, trace.monitor);

	return ret;
}

#if defined(ENABLE_HOST_FIREWALL)
#ifdef ENABLE_IPV6
declare_tailcall_if(__or(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
			 is_defined(DEBUG)), CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY)
int tail_ipv6_host_policy_ingress(struct __ctx_buff *ctx)
{
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 src_id = 0;
	int ret;
	__s8 ext_err = 0;

	ret = ipv6_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
declare_tailcall_if(__or(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
			 is_defined(DEBUG)), CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY)
int tail_ipv4_host_policy_ingress(struct __ctx_buff *ctx)
{
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	__u32 src_id = 0;
	int ret;
	__s8 ext_err = 0;

	ret = ipv4_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}
#endif /* ENABLE_IPV4 */

static __always_inline int
/* Handles packet from a local endpoint entering the host namespace. Applies
 * ingress host policies.
 */
to_host_from_lxc(struct __ctx_buff *ctx __maybe_unused)
{
	int ret = CTX_ACT_OK;
	__u16 proto = 0;

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
					      is_defined(ENABLE_IPV6)),
					is_defined(DEBUG)),
				   CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY,
				   tail_ipv6_host_policy_ingress);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
					      is_defined(ENABLE_IPV6)),
					is_defined(DEBUG)),
				   CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY,
				   tail_ipv4_host_policy_ingress);
		break;
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
					      METRIC_INGRESS);
	return ret;
}

/* Handles packets that left the host namespace and will enter a local
 * endpoint's namespace. Applies egress host policies before handling
 * control back to bpf_lxc.
 */
static __always_inline int
from_host_to_lxc(struct __ctx_buff *ctx, __s8 *ext_err)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	int ret = CTX_ACT_OK;
	void *data, *data_end;
	struct iphdr *ip4 __maybe_unused;
	struct ipv6hdr *ip6 __maybe_unused;
	__u16 proto = 0;

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		ret = ipv6_host_policy_egress(ctx, HOST_ID, ip6, &trace, ext_err);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		/* The third parameter, ipcache_srcid, is only required when
		 * the src_id is not HOST_ID. For details, see
		 * whitelist_snated_egress_connections.
		 * We only arrive here from bpf_lxc if we know the
		 * src_id is HOST_ID. Therefore, we don't need to pass a value
		 * for the last parameter. That avoids an ipcache lookup.
		 */
		ret = ipv4_host_policy_egress(ctx, HOST_ID, 0, ip4, &trace, ext_err);
		break;
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

	return ret;
}

/* When per-endpoint routes are enabled, packets to and from local endpoints
 * will tail call into this program to enforce egress and ingress host policies.
 * Packets to the local endpoints will then tail call back to the original
 * bpf_lxc program.
 */
__section_tail(CILIUM_MAP_POLICY, TEMPLATE_HOST_EP_ID)
int handle_lxc_traffic(struct __ctx_buff *ctx)
{
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	__u32 lxc_id;
	int ret;
	__s8 ext_err = 0;

	if (from_host) {
		ret = from_host_to_lxc(ctx, &ext_err);
		if (IS_ERR(ret))
			return send_drop_notify_error_ext(ctx, HOST_ID, ret, ext_err,
							  CTX_ACT_DROP, METRIC_EGRESS);

		lxc_id = ctx_load_meta(ctx, CB_DST_ENDPOINT_ID);
		ctx_store_meta(ctx, CB_SRC_LABEL, HOST_ID);
		tail_call_dynamic(ctx, &POLICY_CALL_MAP, lxc_id);
		return DROP_MISSED_TAIL_CALL;
	}

	return to_host_from_lxc(ctx);
}
#endif /* ENABLE_HOST_FIREWALL */

BPF_LICENSE("Dual BSD/GPL");
