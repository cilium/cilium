/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_ENCAP_H_
#define __LIB_ENCAP_H_

#include "common.h"
#include "dbg.h"
#include "trace.h"
#include "l3.h"

#if __ctx_is == __ctx_skb
#include "encrypt.h"
#endif /* __ctx_is == __ctx_skb */

#ifdef ENCAP_IFINDEX
/* NOT_VTEP_DST is passed to an encapsulation function when the
 * destination of the tunnel is not a VTEP.
 */
#define NOT_VTEP_DST 0

static __always_inline int
encap_remap_v6_host_address(struct __ctx_buff *ctx __maybe_unused,
			    const bool egress __maybe_unused)
{
#ifdef ENABLE_ENCAP_HOST_REMAP
	struct csum_offset csum = {};
	union v6addr host_ip;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr *which;
	__u8 nexthdr;
	__u16 proto;
	__be32 sum;
	__u32 noff;
	__u64 off;
	int ret;

	validate_ethertype(ctx, &proto);
	if (proto != bpf_htons(ETH_P_IPV6))
		return 0;
	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;
	/* For requests routed via tunnel with external v6 node IP
	 * we need to remap their source address to the router address
	 * as otherwise replies are not routed via tunnel but public
	 * address instead.
	 */
	if (egress) {
		BPF_V6(host_ip, HOST_IP);
		which = (union v6addr *)&ip6->saddr;
	} else {
		BPF_V6(host_ip, ROUTER_IP);
		which = (union v6addr *)&ip6->daddr;
	}
	if (ipv6_addrcmp(which, &host_ip))
		return 0;
	nexthdr = ip6->nexthdr;
	ret = ipv6_hdrlen(ctx, &nexthdr);
	if (ret < 0)
		return ret;
	off = ((void *)ip6 - data) + ret;
	if (egress) {
		BPF_V6(host_ip, ROUTER_IP);
		noff = ETH_HLEN + offsetof(struct ipv6hdr, saddr);
	} else {
		BPF_V6(host_ip, HOST_IP);
		noff = ETH_HLEN + offsetof(struct ipv6hdr, daddr);
	}
	sum = csum_diff(which, 16, &host_ip, 16, 0);
	csum_l4_offset_and_flags(nexthdr, &csum);
	if (ctx_store_bytes(ctx, noff, &host_ip, 16, 0) < 0)
		return DROP_WRITE_ERROR;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;
#endif /* ENABLE_ENCAP_HOST_REMAP */
	return 0;
}

static __always_inline int
__encap_with_nodeid(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
		    __u32 seclabel, __u32 vni __maybe_unused,
		    enum trace_reason ct_reason, __u32 monitor)
{
	struct bpf_tunnel_key key = {};
	__u32 node_id;
	int ret;

	/* When encapsulating, a packet originating from the local host is
	 * being considered as a packet from a remote node as it is being
	 * received.
	 */
	if (seclabel == HOST_ID)
		seclabel = LOCAL_NODE_ID;

	node_id = bpf_htonl(tunnel_endpoint);
#ifdef ENABLE_VTEP
	if (vni != NOT_VTEP_DST)
		key.tunnel_id = vni;
	else
#endif /* ENABLE_VTEP */
		key.tunnel_id = seclabel;
	key.remote_ipv4 = node_id;
	key.tunnel_ttl = 64;

	cilium_dbg(ctx, DBG_ENCAP, node_id, seclabel);

	ret = ctx_set_tunnel_key(ctx, &key, sizeof(key), BPF_F_ZERO_CSUM_TX);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;

	send_trace_notify(ctx, TRACE_TO_OVERLAY, seclabel, 0, 0, ENCAP_IFINDEX,
			  ct_reason, monitor);
	return 0;
}

static __always_inline int
__encap_and_redirect_with_nodeid(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
				 __u32 seclabel, __u32 vni,
				 const struct trace_ctx *trace)
{
	int ret = __encap_with_nodeid(ctx, tunnel_endpoint, seclabel,
				      vni, trace->reason, trace->monitor);
	if (ret != 0)
		return ret;

	return ctx_redirect(ctx, ENCAP_IFINDEX, 0);
}

/* encap_and_redirect_with_nodeid returns CTX_ACT_OK after ctx meta-data is
 * set. Caller should pass the ctx to the stack at this point. Otherwise
 * returns CTX_ACT_REDIRECT on successful redirect to tunnel device.
 * On error returns CTX_ACT_DROP or DROP_WRITE_ERROR.
 */
static __always_inline int
encap_and_redirect_with_nodeid(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
			       __u32 seclabel, const struct trace_ctx *trace)
{
	return __encap_and_redirect_with_nodeid(ctx, tunnel_endpoint, seclabel, NOT_VTEP_DST,
						trace);
}

/* encap_and_redirect based on ENABLE_IPSEC flag and from_host bool will decide
 * which version of code to call. With IPSec enabled and from_host set use the
 * IPSec branch which configures metadata for IPSec kernel stack. Otherwise
 * packet is redirected to output tunnel device and ctx will not be seen by
 * IP stack.
 *
 * Returns IPSEC_ENDPOINT when ctx needs to be handed to IP stack for IPSec
 * handling, CTX_ACT_DROP, DROP_NO_TUNNEL_ENDPOINT or DROP_WRITE_ERROR on error,
 * and finally on successful redirect returns CTX_ACT_TX.
 */
static __always_inline int
encap_and_redirect_lxc(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
		       __u8 encrypt_key __maybe_unused,
		       struct tunnel_key *key, __u32 seclabel,
		       const struct trace_ctx *trace)
{
	struct tunnel_value *tunnel;

	if (tunnel_endpoint) {
#ifdef ENABLE_IPSEC
		if (encrypt_key)
			return set_ipsec_encrypt(ctx, encrypt_key,
						 tunnel_endpoint, seclabel);
#endif
#if !defined(ENABLE_NODEPORT) && defined(ENABLE_HOST_FIREWALL)
		/* For the host firewall, traffic from a pod to a remote node
		 * is sent through the tunnel. In the case of node --> VIP@remote pod,
		 * packets may be DNATed when they enter the remote node. If kube-proxy
		 * is used, the response needs to go through the stack on the way to
		 * the tunnel, to apply the correct reverse DNAT.
		 * See #14674 for details.
		 */
		return __encap_with_nodeid(ctx, tunnel_endpoint, seclabel, NOT_VTEP_DST,
					   trace->reason, trace->monitor);
#else
		return __encap_and_redirect_with_nodeid(ctx, tunnel_endpoint,
							seclabel, NOT_VTEP_DST, trace);
#endif /* !ENABLE_NODEPORT && ENABLE_HOST_FIREWALL */
	}

	tunnel = map_lookup_elem(&TUNNEL_MAP, key);
	if (!tunnel)
		return DROP_NO_TUNNEL_ENDPOINT;

#ifdef ENABLE_IPSEC
	if (tunnel->key) {
		__u8 min_encrypt_key = get_min_encrypt_key(tunnel->key);

		return set_ipsec_encrypt(ctx, min_encrypt_key, tunnel->ip4,
					 seclabel);
	}
#endif
	return __encap_and_redirect_with_nodeid(ctx, tunnel->ip4, seclabel,
						NOT_VTEP_DST, trace);
}

static __always_inline int
encap_and_redirect_netdev(struct __ctx_buff *ctx, struct tunnel_key *k,
			  __u32 seclabel, const struct trace_ctx *trace)
{
	struct tunnel_value *tunnel;

	tunnel = map_lookup_elem(&TUNNEL_MAP, k);
	if (!tunnel)
		return DROP_NO_TUNNEL_ENDPOINT;

	return __encap_and_redirect_with_nodeid(ctx, tunnel->ip4, seclabel,
						NOT_VTEP_DST, trace);
}
#endif /* ENCAP_IFINDEX */
#endif /* __LIB_ENCAP_H_ */
