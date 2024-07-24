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
#include "lib/encrypt.h"
#include "lib/nat.h"
#include "lib/lb.h"
#include "lib/nodeport.h"
#include "lib/eps.h"
#include "lib/host_firewall.h"
#include "lib/egress_gateway.h"
#include "lib/srv6.h"
#include "lib/overloadable.h"
#include "lib/encrypt.h"
#include "lib/wireguard.h"
#include "lib/vxlan.h"

 #define host_egress_policy_hook(ctx, src_sec_identity, ext_err) CTX_ACT_OK

/* Bit 0 is skipped for robustness, as it's used in some places to indicate from_host itself. */
#define FROM_HOST_FLAG_NEED_HOSTFW (1 << 1)
#define FROM_HOST_FLAG_HOST_ID (1 << 2)

static __always_inline bool allow_vlan(__u32 __maybe_unused ifindex, __u32 __maybe_unused vlan_id) {
	VLAN_FILTER(ifindex, vlan_id);
}

#if defined(ENABLE_IPV4) || defined(ENABLE_IPV6)
static __always_inline int rewrite_dmac_to_host(struct __ctx_buff *ctx)
{
	/* When attached to cilium_host, we rewrite the DMAC to the mac of
	 * cilium_host (peer) to ensure the packet is being considered to be
	 * addressed to the host (PACKET_HOST).
	 */
	union macaddr cilium_net_mac = CILIUM_NET_MAC;

	/* Rewrite to destination MAC of cilium_net (remote peer) */
	if (eth_store_daddr(ctx, (__u8 *) &cilium_net_mac.addr, 0) < 0)
		return DROP_WRITE_ERROR;

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
		   __u32 srcid_from_ipcache, __u32 *sec_identity,
		   const bool from_host)
{
	__u32 src_id = WORLD_IPV6_ID;
	struct remote_endpoint_info *info = NULL;
	union v6addr *src;

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(srcid_from_ipcache)) {
		src = (union v6addr *) &ip6->saddr;
		info = lookup_ip6_remote_endpoint(src, 0);
		if (info) {
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
	    __u32 ipcache_srcid __maybe_unused,
	    const bool from_host __maybe_unused,
	    __s8 *ext_err __maybe_unused)
{
#ifdef ENABLE_HOST_FIREWALL
	struct ct_buffer6 ct_buffer = {};
	bool need_hostfw = false;
	bool is_host_id = false;
#endif /* ENABLE_HOST_FIREWALL */
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	if (is_defined(ENABLE_HOST_FIREWALL) || !from_host) {
		__u8 nexthdr = ip6->nexthdr;
		int hdrlen;

		hdrlen = ipv6_hdrlen(ctx, &nexthdr);
		if (hdrlen < 0)
			return hdrlen;

		if (likely(nexthdr == IPPROTO_ICMPV6)) {
			ret = icmp6_host_handle(ctx, ETH_HLEN + hdrlen, ext_err, !from_host);
			if (ret == SKIP_HOST_FIREWALL)
				goto skip_host_firewall;
			if (IS_ERR(ret))
				return ret;
		}
	}

#ifdef ENABLE_NODEPORT
	if (!from_host) {
		if (!ctx_skip_nodeport(ctx)) {
			bool is_dsr = false;

			ret = nodeport_lb6(ctx, ip6, secctx, ext_err, &is_dsr);
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

		if (map_update_elem(&CT_TAIL_CALL_BUFFER6, &zero, &ct_buffer, 0) < 0)
			return DROP_INVALID_TC_BUFFER;
	}
#endif /* ENABLE_HOST_FIREWALL */

skip_host_firewall:
#ifdef ENABLE_HOST_FIREWALL
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
	struct remote_endpoint_info *info = NULL;
	struct endpoint_info *ep;
	int ret;
	__u8 encrypt_key __maybe_unused = 0;
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

		ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER6, &zero);
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

	if (from_host) {
		/* If we are attached to cilium_host at egress, this will
		 * rewrite the destination MAC address to the MAC of cilium_net.
		 */
		ret = rewrite_dmac_to_host(ctx);
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

#ifdef ENABLE_IPSEC
	/* See IPv4 comment. */
	if (from_proxy && info)
		encrypt_key = get_min_encrypt_key(info->key);
#endif

#ifdef TUNNEL_MODE
	if (info && info->flag_skip_tunnel)
		goto skip_tunnel;

	if (info && info->tunnel_endpoint != 0) {
		return encap_and_redirect_with_nodeid(ctx, info->tunnel_endpoint,
						      encrypt_key, secctx, info->sec_identity,
						      &trace);
	} else {
		struct tunnel_key key = {};

		/* IPv6 lookup key: daddr/96 */
		ipv6_addr_copy(&key.ip6, dst);
		key.ip6.p4 = 0;
		key.family = ENDPOINT_KEY_IPV6;

		ret = encap_and_redirect_netdev(ctx, &key, encrypt_key, secctx, &trace);
		if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
skip_tunnel:
#endif

	if (!info || (!from_proxy &&
		      identity_is_world_ipv6(info->sec_identity))) {
		/* See IPv4 comment. */
		return DROP_UNROUTABLE;
	}

#if defined(ENABLE_IPSEC) && !defined(TUNNEL_MODE)
	/* See IPv4 comment. */
	if (from_proxy && info->tunnel_endpoint && encrypt_key)
		return set_ipsec_encrypt(ctx, encrypt_key, info->tunnel_endpoint,
					 info->sec_identity, true, false);

	if (from_proxy &&
	    (!info || !identity_is_cluster(info->sec_identity)))
		ctx->mark = MARK_MAGIC_PROXY_TO_WORLD;
#endif /* ENABLE_IPSEC && !TUNNEL_MODE */

	return CTX_ACT_OK;
}

static __always_inline int
tail_handle_ipv6_cont(struct __ctx_buff *ctx, bool from_host)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	int ret;
	__s8 ext_err = 0;

	ret = handle_ipv6_cont(ctx, src_sec_identity, from_host, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_CONT_FROM_HOST)
static __always_inline
int tail_handle_ipv6_cont_from_host(struct __ctx_buff *ctx)
{
	return tail_handle_ipv6_cont(ctx, true);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_CONT_FROM_NETDEV)
static __always_inline
int tail_handle_ipv6_cont_from_netdev(struct __ctx_buff *ctx)
{
	return tail_handle_ipv6_cont(ctx, false);
}

static __always_inline int
tail_handle_ipv6(struct __ctx_buff *ctx, __u32 ipcache_srcid, const bool from_host)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	int ret;
	__s8 ext_err = 0;

	ret = handle_ipv6(ctx, src_sec_identity, ipcache_srcid, from_host, &ext_err);

	/* TC_ACT_REDIRECT is not an error, but it means we should stop here. */
	if (ret == CTX_ACT_OK) {
		ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
		if (from_host)
			ret = invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
						 CILIUM_CALL_IPV6_CONT_FROM_HOST,
						 tail_handle_ipv6_cont_from_host,
						 &ext_err);
		else
			ret = invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
						 CILIUM_CALL_IPV6_CONT_FROM_NETDEV,
						 tail_handle_ipv6_cont_from_netdev,
						 &ext_err);
	}

	/* Catch errors from both handle_ipv6 and invoke_tailcall_if here. */
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_HOST)
int tail_handle_ipv6_from_host(struct __ctx_buff *ctx __maybe_unused)
{
	__u32 ipcache_srcid = 0;

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV6)
	ipcache_srcid = ctx_load_and_clear_meta(ctx, CB_IPCACHE_SRC_LABEL);
#endif /* defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV6) */

	return tail_handle_ipv6(ctx, ipcache_srcid, true);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_NETDEV)
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

	srcid = resolve_srcid_ipv6(ctx, ip6, src_sec_identity,
				   &ipcache_srcid, true);

	/* to-netdev is attached to the egress path of the native device. */
	return ipv6_host_policy_egress(ctx, srcid, ipcache_srcid, ip6, trace, ext_err);
}
#endif /* ENABLE_HOST_FIREWALL */
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline __u32
resolve_srcid_ipv4(struct __ctx_buff *ctx, struct iphdr *ip4,
		   __u32 srcid_from_proxy, __u32 *sec_identity,
		   const bool from_host)
{
	__u32 src_id = WORLD_IPV4_ID, srcid_from_ipcache = srcid_from_proxy;
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
#ifdef ENABLE_HOST_FIREWALL
	struct ct_buffer4 ct_buffer = {};
	bool need_hostfw = false;
	bool is_host_id = false;
#endif /* ENABLE_HOST_FIREWALL */
	void *data, *data_end;
	struct iphdr *ip4;

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
			bool __maybe_unused is_dsr = false;

			int ret = nodeport_lb4(ctx, ip4, ETH_HLEN, secctx, ext_err, &is_dsr);
#ifdef ENABLE_IPV6
			if (ret == NAT_46X64_RECIRC) {
				ctx_store_meta(ctx, CB_SRC_LABEL, secctx);
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
	void *data, *data_end;
	struct iphdr *ip4;
	struct remote_endpoint_info *info;
	struct endpoint_info *ep;
	int ret;
	__u8 encrypt_key __maybe_unused = 0;
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
		if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
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
		ret = rewrite_dmac_to_host(ctx);
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
								secctx, WORLD_IPV4_ID,
								WORLD_IPV4_ID, &trace);
		}
	}
skip_vtep:
#endif

	info = lookup_ip4_remote_endpoint(ip4->daddr, 0);

#ifdef ENABLE_IPSEC
	/* We encrypt host to remote pod packets only if they are from proxy. */
	if (from_proxy && info)
		encrypt_key = get_min_encrypt_key(info->key);
#endif

#ifdef TUNNEL_MODE
	if (info && info->flag_skip_tunnel)
		goto skip_tunnel;

	if (info && info->tunnel_endpoint != 0) {
		return encap_and_redirect_with_nodeid(ctx, info->tunnel_endpoint,
						      encrypt_key, secctx, info->sec_identity,
						      &trace);
	} else {
		/* IPv4 lookup key: daddr & IPV4_MASK */
		struct tunnel_key key = {};

		key.ip4 = ip4->daddr & IPV4_MASK;
		key.family = ENDPOINT_KEY_IPV4;

		cilium_dbg(ctx, DBG_NETDEV_ENCAP4, key.ip4, secctx);
		ret = encap_and_redirect_netdev(ctx, &key, encrypt_key, secctx, &trace);
		if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
skip_tunnel:
#endif

	if (!info || (!from_proxy &&
		      identity_is_world_ipv4(info->sec_identity))) {
		/* We have received a packet for which no ipcache entry exists,
		 * we do not know what to do with this packet, drop it.
		 *
		 * The info == NULL test is soley to satisfy verifier requirements
		 * as in Cilium case we'll always hit the 0.0.0.0/32 catch-all
		 * entry. Therefore we need to test for WORLD_ID. It is clearly
		 * wrong to route a ctx to cilium_host for which we don't know
		 * anything about it as otherwise we'll run into a routing loop.
		 *
		 * Note that we do not drop packets from proxy even if
		 * they are going to WORLD_ID. This is to avoid
		 * https://github.com/cilium/cilium/issues/21954.
		 */
		return DROP_UNROUTABLE;
	}

#if defined(ENABLE_IPSEC) && !defined(TUNNEL_MODE)
	/* We encrypt host to remote pod packets only if they are from proxy. */
	if (from_proxy && info->tunnel_endpoint && encrypt_key)
		return set_ipsec_encrypt(ctx, encrypt_key, info->tunnel_endpoint,
					 info->sec_identity, true, false);

	if (from_proxy &&
	    (!info || !identity_is_cluster(info->sec_identity)))
		ctx->mark = MARK_MAGIC_PROXY_TO_WORLD;
#endif /* ENABLE_IPSEC && !TUNNEL_MODE */

	return CTX_ACT_OK;
}

static __always_inline int
tail_handle_ipv4_cont(struct __ctx_buff *ctx, bool from_host)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	int ret;
	__s8 ext_err = 0;

	ret = handle_ipv4_cont(ctx, src_sec_identity, from_host, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_CONT_FROM_HOST)
static __always_inline
int tail_handle_ipv4_cont_from_host(struct __ctx_buff *ctx)
{
	return tail_handle_ipv4_cont(ctx, true);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_CONT_FROM_NETDEV)
static __always_inline
int tail_handle_ipv4_cont_from_netdev(struct __ctx_buff *ctx)
{
	return tail_handle_ipv4_cont(ctx, false);
}

static __always_inline int
tail_handle_ipv4(struct __ctx_buff *ctx, __u32 ipcache_srcid, const bool from_host)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	int ret;
	__s8 ext_err = 0;

	ret = handle_ipv4(ctx, src_sec_identity, ipcache_srcid, from_host, &ext_err);

	/* TC_ACT_REDIRECT is not an error, but it means we should stop here. */
	if (ret == CTX_ACT_OK) {
		ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
		if (from_host)
			ret = invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
						 CILIUM_CALL_IPV4_CONT_FROM_HOST,
						 tail_handle_ipv4_cont_from_host,
						 &ext_err);
		else
			ret = invoke_tailcall_if(is_defined(ENABLE_HOST_FIREWALL),
						 CILIUM_CALL_IPV4_CONT_FROM_NETDEV,
						 tail_handle_ipv4_cont_from_netdev,
						 &ext_err);
	}

	/* Catch errors from both handle_ipv4 and invoke_tailcall_if here. */
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_HOST)
int tail_handle_ipv4_from_host(struct __ctx_buff *ctx)
{
	__u32 ipcache_srcid = 0;

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV4)
	ipcache_srcid = ctx_load_and_clear_meta(ctx, CB_IPCACHE_SRC_LABEL);
#endif /* defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV4) */

	return tail_handle_ipv4(ctx, ipcache_srcid, true);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_NETDEV)
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

	src_id = resolve_srcid_ipv4(ctx, ip4, src_sec_identity,
				    &ipcache_srcid, true);

	/* We need to pass the srcid from ipcache to host firewall. See
	 * comment in ipv4_host_policy_egress() for details.
	 */
	return ipv4_host_policy_egress(ctx, src_id, ipcache_srcid, ip4, trace, ext_err);
}
#endif /* ENABLE_HOST_FIREWALL */
#endif /* ENABLE_IPV4 */

#if defined(ENABLE_IPSEC) && defined(TUNNEL_MODE)
static __always_inline int do_netdev_encrypt_encap(struct __ctx_buff *ctx, __u32 src_id)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_ENCRYPTED,
		.monitor = 0,
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
	return encap_and_redirect_with_nodeid(ctx, ep->tunnel_endpoint, 0,
					      src_id, 0, &trace);
}
#endif /* ENABLE_IPSEC && TUNNEL_MODE */

#ifdef ENABLE_L2_ANNOUNCEMENTS
static __always_inline int handle_l2_announcement(struct __ctx_buff *ctx)
{
	union macaddr mac = THIS_INTERFACE_MAC;
	union macaddr smac;
	__be32 sip;
	__be32 tip;
	struct l2_responder_v4_key key;
	struct l2_responder_v4_stats *stats;
	int ret;
	__u32 index = RUNTIME_CONFIG_AGENT_LIVENESS;
	__u64 *time;

	time = map_lookup_elem(&CONFIG_MAP, &index);
	if (!time)
		return CTX_ACT_OK;

	/* If the agent is not active for X seconds, we can't trust the contents
	 * of the responder map anymore. So stop responding, assuming other nodes
	 * will take over for a node without an active agent.
	 */
	if (ktime_get_ns() - (*time) > L2_ANNOUNCEMENTS_MAX_LIVENESS)
		return CTX_ACT_OK;

	if (!arp_validate(ctx, &mac, &smac, &sip, &tip))
		return CTX_ACT_OK;

	key.ip4 = tip;
	key.ifindex = ctx->ingress_ifindex;
	stats = map_lookup_elem(&L2_RESPONDER_MAP4, &key);
	if (!stats)
		return CTX_ACT_OK;

	ret = arp_respond(ctx, &mac, tip, &smac, sip, 0);

	if (ret == CTX_ACT_REDIRECT)
		__sync_fetch_and_add(&stats->responses_sent, 1);

	return ret;
};
#endif

static __always_inline int
do_netdev(struct __ctx_buff *ctx, __u16 proto, const bool from_host)
{
	enum trace_point trace = from_host ? TRACE_FROM_HOST :
					     TRACE_FROM_NETWORK;
	__u32 __maybe_unused identity = 0;
	__u32 __maybe_unused ipcache_srcid = 0;
	void __maybe_unused *data, *data_end;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	__s8 __maybe_unused ext_err = 0;
	int ret;

#ifdef ENABLE_IPSEC
	if (!from_host) {
#ifdef ENABLE_ENCRYPTED_OVERLAY
		/* EncryptedOverlay XFRM policies set the output mark to the literal
		 * MARK_MAGIC_DECRYPTED_OVERLAY value.
		 *
		 * If we see this here, its decrypted overlay traffic from these
		 * XFRM policies. We can punt this directly to ingress side of vxlan
		 * interface for decap.
		 */
		if (ctx->mark == MARK_MAGIC_DECRYPTED_OVERLAY) {
			ret = ctx_redirect(ctx, ENCAP_IFINDEX, BPF_F_INGRESS);
			return ret;
		}
#endif /* ENABLED_ENCRYPTED_OVERLAY */
		/* If the packet needs decryption, we want to send it straight to the
		 * stack. There's no need to run service handling logic, host firewall,
		 * etc. on an encrypted packet.
		 * In all other cases (packet doesn't need decryption or already
		 * decrypted), we want to run all subsequent logic here. We therefore
		 * ignore the return value from do_decrypt.
		 */
		do_decrypt(ctx, proto);
		if (ctx->mark == MARK_MAGIC_DECRYPT)
			return CTX_ACT_OK;
	}
#endif

	if (from_host) {
		__u32 magic;

		magic = inherit_identity_from_host(ctx, &identity);
		if (magic == MARK_MAGIC_PROXY_INGRESS ||  magic == MARK_MAGIC_PROXY_EGRESS)
			trace = TRACE_FROM_PROXY;

#if defined(ENABLE_L7_LB)
		if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
			/* extracted identity is actually the endpoint ID */
			ret = tail_call_egress_policy(ctx, (__u16)identity);
			return send_drop_notify_error(ctx, UNKNOWN_ID, ret, CTX_ACT_DROP,
						      METRIC_EGRESS);
		}
#endif

#ifdef ENABLE_IPSEC
		if (magic == MARK_MAGIC_ENCRYPT) {
			send_trace_notify(ctx, TRACE_FROM_STACK, identity, UNKNOWN_ID,
					  TRACE_EP_ID_UNKNOWN,
					  ctx->ingress_ifindex, TRACE_REASON_ENCRYPTED, 0);
			ret = CTX_ACT_OK;
# ifdef TUNNEL_MODE
			ret = do_netdev_encrypt_encap(ctx, identity);
			if (IS_ERR(ret))
				return send_drop_notify_error(ctx, identity, ret,
							      CTX_ACT_DROP, METRIC_EGRESS);
# endif /* TUNNEL_MODE */
			return ret;
		}
#endif /* ENABLE_IPSEC */
	}

	send_trace_notify(ctx, trace, identity, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
			  ctx->ingress_ifindex, TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);

	bpf_clear_meta(ctx);

	switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER || \
     defined ENABLE_L2_ANNOUNCEMENTS
	case bpf_htons(ETH_P_ARP):
		#ifdef ENABLE_L2_ANNOUNCEMENTS
			ret = handle_l2_announcement(ctx);
		#else
			ret = CTX_ACT_OK;
		#endif
		break;
# endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			return send_drop_notify_error(ctx, identity, DROP_INVALID,
						      CTX_ACT_DROP, METRIC_INGRESS);

		identity = resolve_srcid_ipv6(ctx, ip6, identity, &ipcache_srcid, from_host);
		ctx_store_meta(ctx, CB_SRC_LABEL, identity);
		if (from_host) {
# if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV6)
			/* If we don't rely on BPF-based masquerading, we need
			 * to pass the srcid from ipcache to host firewall. See
			 * comment in ipv6_host_policy_egress() for details.
			 */
			ctx_store_meta(ctx, CB_IPCACHE_SRC_LABEL, ipcache_srcid);
# endif /* defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV6) */
		}

		ret = tail_call_internal(ctx, from_host ? CILIUM_CALL_IPV6_FROM_HOST :
							  CILIUM_CALL_IPV6_FROM_NETDEV,
					 &ext_err);
		/* See comment below for IPv4. */
		return send_drop_notify_error_ext(ctx, identity, ret, ext_err,
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
# if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV4)
			/* If we don't rely on BPF-based masquerading, we need
			 * to pass the srcid from ipcache to host firewall. See
			 * comment in ipv4_host_policy_egress() for details.
			 */
			ctx_store_meta(ctx, CB_IPCACHE_SRC_LABEL, ipcache_srcid);
# endif /* defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE_IPV4) */
		}

		ret = tail_call_internal(ctx, from_host ? CILIUM_CALL_IPV4_FROM_HOST :
							  CILIUM_CALL_IPV4_FROM_NETDEV,
					 &ext_err);
		/* We are not returning an error here to always allow traffic to
		 * the stack in case maps have become unavailable.
		 *
		 * Note: Since drop notification requires a tail call as well,
		 * this notification is unlikely to succeed.
		 */
		return send_drop_notify_error_ext(ctx, identity, ret, ext_err,
						  CTX_ACT_OK, METRIC_INGRESS);
#endif /* ENABLE_IPV4 */
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
		__u32 id = WORLD_ID;
		__u32 sec_label = SECLABEL;
#if defined ENABLE_IPV4 && defined ENABLE_IPV6
		switch (proto) {
		case bpf_htons(ETH_P_IP):
			id = WORLD_IPV4_ID;
			sec_label = SECLABEL_IPV4;
			break;
		case bpf_htons(ETH_P_IPV6):
			id = WORLD_IPV6_ID;
			sec_label = SECLABEL_IPV6;
			break;
		}
#endif
		return send_drop_notify(ctx, sec_label, id, TRACE_EP_ID_UNKNOWN, ret,
					CTX_ACT_DROP, METRIC_EGRESS);
#else
		send_trace_notify(ctx, TRACE_TO_STACK, HOST_ID, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN,
				  TRACE_IFINDEX_UNKNOWN, TRACE_REASON_UNKNOWN, 0);
		/* Pass unknown traffic to the stack */
		return CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */
	}

	return do_netdev(ctx, proto, from_host);
}

/*
 * from-netdev is attached as a tc ingress filter to one or more physical devices
 * managed by Cilium (e.g., eth0). This program is only attached when:
 * - the host firewall is enabled, or
 * - BPF NodePort is enabled, or
 * - L2 announcements are enabled, or
 * - WireGuard's host-to-host encryption and BPF NodePort are enabled
 */
__section_entry
int cil_from_netdev(struct __ctx_buff *ctx)
{
	__u32 src_id = 0;

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
		goto drop_err;

	if (ret == CTX_ACT_REDIRECT)
		return ret;
#endif /* ENABLE_HIGH_SCALE_IPCACHE */

	return handle_netdev(ctx, false);

drop_err:
	return send_drop_notify_error(ctx, src_id, ret, CTX_ACT_DROP, METRIC_INGRESS);
}

/*
 * from-host is attached as a tc egress filter to the node's 'cilium_host'
 * interface if present.
 */
__section_entry
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
 * managed by Cilium (e.g., eth0).
 */
__section_entry
int cil_to_netdev(struct __ctx_buff *ctx __maybe_unused)
{
	__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;
	__u32 dst_sec_identity = UNKNOWN_ID;
	__u32 src_sec_identity = UNKNOWN_ID;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__be16 __maybe_unused proto = 0;
	__u32 __maybe_unused vlan_id;
	int ret = CTX_ACT_OK;
	__s8 ext_err = 0;

	bpf_clear_meta(ctx);

	if (magic == MARK_MAGIC_HOST || magic == MARK_MAGIC_OVERLAY)
		src_sec_identity = HOST_ID;
	else if (magic == MARK_MAGIC_IDENTITY)
		src_sec_identity = get_identity(ctx);

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

	/* Load the ethertype just once: */
	validate_ethertype(ctx, &proto);

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
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
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
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

	if (IS_ERR(ret))
		goto drop_err;

	if (ret == CTX_ACT_REDIRECT)
	{
		/* perhaps it's better to move part of the redirectio code here? */	
		return ret;
	}

skip_host_firewall:
#endif /* ENABLE_HOST_FIREWALL */

	ret = host_egress_policy_hook(ctx, src_sec_identity, &ext_err);
	if (IS_ERR(ret))
		goto drop_err;

#if defined(ENABLE_BANDWIDTH_MANAGER)
	ret = edt_sched_departure(ctx, proto);
	/* No send_drop_notify_error() here given we're rate-limiting. */
	if (ret == CTX_ACT_DROP) {
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
			       -DROP_EDT_HORIZON);
		return ret;
	}
#endif

#if defined(ENABLE_ENCRYPTED_OVERLAY)
	if (ctx_is_overlay(ctx) && get_identity(ctx) == ENCRYPTED_OVERLAY_ID) {
		/* This is overlay traffic that should be recirculated
		 * to the stack for XFRM encryption.
		 */
		ret = encrypt_overlay_and_redirect(ctx);
		if (ret == CTX_ACT_REDIRECT) {
			/* we are redirecting back into the stack, so TRACE_TO_STACK
			 * for tracepoint
			 */
			send_trace_notify(ctx, TRACE_TO_STACK, src_sec_identity,
					  dst_sec_identity,
					  TRACE_EP_ID_UNKNOWN, NATIVE_DEV_IFINDEX,
					  TRACE_REASON_ENCRYPT_OVERLAY, 0);
			return ret;
		}
		if (IS_ERR(ret))
			goto drop_err;
	}
#endif /* ENABLE_ENCRYPTED_OVERLAY */

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
	 * will set the MARK_MAGIC_WG_ENCRYPTED skb mark. So, to avoid
	 * looping forever (e.g., bpf_host@eth0 => cilium_wg0 =>
	 * bpf_host@eth0 => ...; this happens when eth0 is used to send
	 * encrypted WireGuard UDP packets), we check whether the mark
	 * is set before the redirect.
	 */
	if ((ctx->mark & MARK_MAGIC_WG_ENCRYPTED) != MARK_MAGIC_WG_ENCRYPTED) {
		ret = wg_maybe_redirect_to_encrypt(ctx, proto);
		if (ret == CTX_ACT_REDIRECT)
			return ret;
		else if (IS_ERR(ret))
			goto drop_err;
	}

#if defined(ENCRYPTION_STRICT_MODE)
	if (!strict_allow(ctx, proto)) {
		ret = DROP_UNENCRYPTED_TRAFFIC;
		goto drop_err;
	}
#endif /* ENCRYPTION_STRICT_MODE */
#endif /* ENABLE_WIREGUARD */

#ifdef ENABLE_HEALTH_CHECK
	ret = lb_handle_health(ctx, proto);
	if (ret != CTX_ACT_OK)
		goto exit;
#endif

#ifdef ENABLE_EGRESS_GATEWAY_COMMON
	{
		void *data, *data_end;
		struct iphdr *ip4;
		struct ipv4_ct_tuple tuple = {};
		struct ct_state ct_state = {};
		enum ct_status ct_status;
		bool has_l4_header = true;
		int l4_off;
		struct remote_endpoint_info *info;
		struct endpoint_info *src_ep;

		if (src_sec_identity == HOST_ID)
			goto skip_egress_gateway;

		if (proto != bpf_htons(ETH_P_IP))
			goto skip_egress_gateway;

		if (ctx_egw_done(ctx))
			goto skip_egress_gateway;

		if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto drop_err;
		}

		tuple.nexthdr = ip4->protocol;
		tuple.daddr = ip4->daddr;
		tuple.saddr = ip4->saddr;

		l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
		ret = ct_extract_ports4(ctx, ip4, l4_off, CT_EGRESS, &tuple,
					&has_l4_header);
		if (IS_ERR(ret)) {
			if (ret == DROP_CT_UNKNOWN_PROTO)
				goto skip_egress_gateway;

			goto drop_err;
		}

		__ipv4_ct_tuple_reverse(&tuple);
		ret = ct_lazy_lookup4(get_ct_map4(&tuple),
				      &tuple, ctx, ipv4_is_fragment(ip4),
				      l4_off, has_l4_header, CT_EGRESS,
				      SCOPE_FORWARD, CT_ENTRY_ANY,
				      &ct_state, &trace.monitor);
		if (IS_ERR(ret))
			goto drop_err;

		ct_status = (enum ct_status)ret;

		src_ep = __lookup_ip4_endpoint(ip4->saddr);
		if (src_ep)
			src_sec_identity = src_ep->sec_id;

		info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (info && info->sec_identity)
			dst_sec_identity = info->sec_identity;

		ret = egress_gw_handle_packet(ctx, &tuple, ct_status,
					      src_sec_identity, dst_sec_identity,
					      &trace);
		if (IS_ERR(ret))
			goto drop_err;

		if (ret != CTX_ACT_OK)
			return ret;
	}
skip_egress_gateway:
#endif

#ifdef ENABLE_NODEPORT
	if (!ctx_snat_done(ctx) && !ctx_is_overlay(ctx)) {
		/*
		 * handle_nat_fwd tail calls in the majority of cases,
		 * so control might never return to this program.
		 */
		ret = handle_nat_fwd(ctx, 0, proto, &trace, &ext_err);
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
			  TRACE_EP_ID_UNKNOWN,
			  NATIVE_DEV_IFINDEX, trace.reason, trace.monitor);

	return ret;

drop_err:
	return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
					  CTX_ACT_DROP, METRIC_EGRESS);
}

/*
 * to-host is attached as a tc ingress filter to both the 'cilium_host' and
 * 'cilium_net' devices if present.
 */
__section_entry
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

	if ((magic & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT) {
		ctx->mark = magic; /* CB_ENCRYPT_MAGIC */
		src_id = ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY);
	} else if ((magic & 0xFFFF) == MARK_MAGIC_TO_PROXY) {
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
		ctx_store_meta(ctx, CB_SRC_LABEL, src_id);
		ctx_store_meta(ctx, CB_TRACED, traced);
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY, &ext_err);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ctx_store_meta(ctx, CB_SRC_LABEL, src_id);
		ctx_store_meta(ctx, CB_TRACED, traced);
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY, &ext_err);
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
		send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN,
				  CILIUM_IFINDEX, trace.reason, trace.monitor);

	return ret;
}

#if defined(ENABLE_HOST_FIREWALL)
#ifdef ENABLE_IPV6
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY)
static __always_inline
int tail_ipv6_host_policy_ingress(struct __ctx_buff *ctx)
{
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 src_id = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool traced = ctx_load_meta(ctx, CB_TRACED);
	int ret;
	__s8 ext_err = 0;

	ret = ipv6_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);

	if (!traced)
		send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN,
				  CILIUM_IFINDEX, trace.reason, trace.monitor);

	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY)
static __always_inline
int tail_ipv4_host_policy_ingress(struct __ctx_buff *ctx)
{
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	__u32 src_id = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool traced = ctx_load_meta(ctx, CB_TRACED);
	int ret;
	__s8 ext_err = 0;

	ret = ipv4_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);

	if (!traced)
		send_trace_notify(ctx, TRACE_TO_STACK, src_id, UNKNOWN_ID,
				  TRACE_EP_ID_UNKNOWN,
				  CILIUM_IFINDEX, trace.reason, trace.monitor);

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
	__s8 ext_err = 0;
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
		ctx_store_meta(ctx, CB_SRC_LABEL, 0);
		ctx_store_meta(ctx, CB_TRACED, 1);
		ret = invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
						    is_defined(ENABLE_IPV6)),
					      is_defined(DEBUG)),
					 CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY,
					 tail_ipv6_host_policy_ingress,
					 &ext_err);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ctx_store_meta(ctx, CB_SRC_LABEL, 0);
		ctx_store_meta(ctx, CB_TRACED, 1);
		ret = invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
						    is_defined(ENABLE_IPV6)),
					      is_defined(DEBUG)),
					 CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY,
					 tail_ipv4_host_policy_ingress,
					 &ext_err);
		break;
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);
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

		ret = ipv6_host_policy_egress(ctx, HOST_ID, 0, ip6, &trace, ext_err);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		/* The third parameter, ipcache_srcid, is only required when
		 * the src_id is not HOST_ID. For details, see
		 * ipv4_whitelist_snated_egress_connections().
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
		ret = tail_call_policy(ctx, (__u16)lxc_id);
		return send_drop_notify_error(ctx, HOST_ID, ret,
					      CTX_ACT_DROP, METRIC_EGRESS);
	}

	return to_host_from_lxc(ctx);
}
#endif /* ENABLE_HOST_FIREWALL */

BPF_LICENSE("Dual BSD/GPL");
