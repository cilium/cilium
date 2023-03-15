/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_ENCAP_H_
#define __LIB_ENCAP_H_

#include "common.h"
#include "dbg.h"
#include "trace.h"
#include "l3.h"
#include "lib/wireguard.h"
#include "high_scale_ipcache.h"

#ifdef HAVE_ENCAP
#ifdef ENABLE_IPSEC
static __always_inline int
encap_and_redirect_ipsec(struct __ctx_buff *ctx, __u8 key, __u16 node_id,
			 __u32 seclabel)
{
	/* IPSec is performed by the stack on any packets with the
	 * MARK_MAGIC_ENCRYPT bit set. During the process though we
	 * lose the lxc context (seclabel and tunnel endpoint). The
	 * tunnel endpoint can be looked up from daddr but the sec
	 * label is stashed in the mark and extracted in bpf_host
	 * to send ctx onto tunnel for encap.
	 */
	set_encrypt_key_mark(ctx, key, node_id);
	set_identity_meta(ctx, seclabel);
	return CTX_ACT_OK;
}
#endif /* ENABLE_IPSEC */

static __always_inline int
__encap_with_nodeid(struct __ctx_buff *ctx, __u32 src_ip, __be16 src_port,
		    __be32 tunnel_endpoint,
		    __u32 seclabel, __u32 dstid, __u32 vni __maybe_unused,
		    enum trace_reason ct_reason, __u32 monitor, int *ifindex)
{
	__u32 node_id;
	int ret;

	/* When encapsulating, a packet originating from the local host is
	 * being considered as a packet from a remote node as it is being
	 * received.
	 */
	if (seclabel == HOST_ID)
		seclabel = LOCAL_NODE_ID;

	node_id = bpf_ntohl(tunnel_endpoint);

	cilium_dbg(ctx, DBG_ENCAP, node_id, seclabel);

	ret = ctx_set_encap_info(ctx, src_ip, src_port, node_id, seclabel, vni,
				 NULL, 0, ifindex);
	if (ret == CTX_ACT_REDIRECT)
		send_trace_notify(ctx, TRACE_TO_OVERLAY, seclabel, dstid, 0, *ifindex,
				  ct_reason, monitor);

	return ret;
}

static __always_inline int
__encap_and_redirect_with_nodeid(struct __ctx_buff *ctx, __u32 src_ip __maybe_unused,
				 __be32 tunnel_endpoint,
				 __u32 seclabel, __u32 dstid, __u32 vni,
				 const struct trace_ctx *trace)
{
	int ifindex;
	int ret = 0;

#ifdef ENABLE_WIREGUARD
	/* Redirect the packet to the WireGuard tunnel device for encryption
	 * if needed.
	 *
	 * A packet which previously was a subject to VXLAN/Geneve
	 * encapsulation (e.g., pod2pod) is going to be encapsulated only once,
	 * i.e., by the WireGuard tunnel netdev. This is so just to be
	 * compatible with < the v1.13 behavior in which the pod2pod bypassed
	 * VXLAN/Geneve encapsulation when the WG feature was on.
	 */
	ret = wg_maybe_redirect_to_encrypt(ctx);
	if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
		return ret;
#endif /* ENABLE_WIREGUARD */

	ret = __encap_with_nodeid(ctx, src_ip, 0, tunnel_endpoint, seclabel, dstid,
				  vni, trace->reason, trace->monitor,
				  &ifindex);
	if (ret != CTX_ACT_REDIRECT)
		return ret;

	return ctx_redirect(ctx, ifindex, 0);
}

/* encap_and_redirect_with_nodeid returns CTX_ACT_OK after ctx meta-data is
 * set. Caller should pass the ctx to the stack at this point. Otherwise
 * returns CTX_ACT_REDIRECT on successful redirect to tunnel device.
 * On error returns CTX_ACT_DROP or DROP_WRITE_ERROR.
 */
static __always_inline int
encap_and_redirect_with_nodeid(struct __ctx_buff *ctx, __be32 tunnel_endpoint,
			       __u16 node_id __maybe_unused,
			       __u32 seclabel, __u32 dstid,
			       const struct trace_ctx *trace)
{
	return __encap_and_redirect_with_nodeid(ctx, 0, tunnel_endpoint,
						seclabel, dstid, NOT_VTEP_DST,
						trace);
}

/* __encap_and_redirect_lxc() is a variant of encap_and_redirect_lxc()
 * that requires a valid tunnel_endpoint.
 */
static __always_inline int
__encap_and_redirect_lxc(struct __ctx_buff *ctx, __be32 tunnel_endpoint,
			 __u8 encrypt_key __maybe_unused,
			 __u16 node_id __maybe_unused, __u32 seclabel,
			 __u32 dstid, const struct trace_ctx *trace)
{
	int ifindex __maybe_unused;
	int ret __maybe_unused;

#ifdef ENABLE_IPSEC
	if (encrypt_key)
		return encap_and_redirect_ipsec(ctx, encrypt_key, node_id,
						seclabel);
#endif

#if !defined(ENABLE_NODEPORT) && (defined(ENABLE_IPSEC) || defined(ENABLE_HOST_FIREWALL))
	/* For IPSec and the host firewall, traffic from a pod to a remote node
	 * is sent through the tunnel. In the case of node --> VIP@remote pod,
	 * packets may be DNATed when they enter the remote node. If kube-proxy
	 * is used, the response needs to go through the stack on the way to
	 * the tunnel, to apply the correct reverse DNAT.
	 * See #14674 for details.
	 */
	ret = __encap_with_nodeid(ctx, 0, 0, tunnel_endpoint, seclabel, dstid,
				  NOT_VTEP_DST, trace->reason, trace->monitor,
				  &ifindex);
	if (ret != CTX_ACT_REDIRECT)
		return ret;

	/* tell caller that this packet needs to go through the stack: */
	return CTX_ACT_OK;
#else
	return __encap_and_redirect_with_nodeid(ctx, 0, tunnel_endpoint,
						seclabel, dstid, NOT_VTEP_DST, trace);
#endif /* !ENABLE_NODEPORT && (ENABLE_IPSEC || ENABLE_HOST_FIREWALL) */
}

#if defined(TUNNEL_MODE) || defined(ENABLE_HIGH_SCALE_IPCACHE)
/* encap_and_redirect_lxc adds IPSec metadata (if enabled) and returns the packet
 * so that it can be passed to the IP stack. Without IPSec the packet is
 * typically redirected to the output tunnel device and ctx will not be seen by
 * the IP stack.
 *
 * Returns CTX_ACT_OK when ctx needs to be handed to IP stack (eg. for IPSec
 * handling), CTX_ACT_DROP, DROP_NO_TUNNEL_ENDPOINT or DROP_WRITE_ERROR on error,
 * and finally on successful redirect returns CTX_ACT_REDIRECT.
 */
static __always_inline int
encap_and_redirect_lxc(struct __ctx_buff *ctx,
		       __be32 tunnel_endpoint __maybe_unused,
		       __u32 src_ip __maybe_unused,
		       __u32 dst_ip __maybe_unused,
		       __u8 encrypt_key __maybe_unused,
		       struct tunnel_key *key __maybe_unused,
		       __u16 node_id __maybe_unused,
		       __u32 seclabel, __u32 dstid,
		       const struct trace_ctx *trace)
{
	struct tunnel_value *tunnel __maybe_unused;

#ifdef ENABLE_HIGH_SCALE_IPCACHE
	if (needs_encapsulation(dst_ip))
		return __encap_and_redirect_with_nodeid(ctx, src_ip, dst_ip,
							seclabel, dstid,
							NOT_VTEP_DST, trace);
	return DROP_NO_TUNNEL_ENDPOINT;
#else /* ENABLE_HIGH_SCALE_IPCACHE */
	if (tunnel_endpoint)
		return __encap_and_redirect_lxc(ctx, tunnel_endpoint,
						encrypt_key, node_id, seclabel,
						dstid, trace);

	tunnel = map_lookup_elem(&TUNNEL_MAP, key);
	if (!tunnel)
		return DROP_NO_TUNNEL_ENDPOINT;

# ifdef ENABLE_IPSEC
	if (tunnel->key) {
		__u8 min_encrypt_key = get_min_encrypt_key(tunnel->key);

		return encap_and_redirect_ipsec(ctx, min_encrypt_key, node_id,
						seclabel);
	}
# endif
	return __encap_and_redirect_with_nodeid(ctx, 0, tunnel->ip4, seclabel,
						dstid, NOT_VTEP_DST, trace);
#endif /* ENABLE_HIGH_SCALE_IPCACHE */
}

static __always_inline int
encap_and_redirect_netdev(struct __ctx_buff *ctx, struct tunnel_key *k,
			  __u32 seclabel, const struct trace_ctx *trace)
{
	struct tunnel_value *tunnel;

	tunnel = map_lookup_elem(&TUNNEL_MAP, k);
	if (!tunnel)
		return DROP_NO_TUNNEL_ENDPOINT;

	return __encap_and_redirect_with_nodeid(ctx, 0, tunnel->ip4, seclabel,
						0, NOT_VTEP_DST, trace);
}
#endif /* TUNNEL_MODE || ENABLE_HIGH_SCALE_IPCACHE */

static __always_inline __be16 tunnel_gen_src_port_v4(void)
{
#if __ctx_is == __ctx_xdp
	/* TODO hash, based on CT tuple */
	return bpf_htons(TUNNEL_PORT);
#else
	return 0;
#endif
}

static __always_inline __be16 tunnel_gen_src_port_v6(void)
{
#if __ctx_is == __ctx_xdp
	/* TODO hash, based on CT tuple */
	return bpf_htons(TUNNEL_PORT);
#else
	return 0;
#endif
}

#if defined(ENABLE_DSR) && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
static __always_inline int
__encap_with_nodeid_opt(struct __ctx_buff *ctx, __u32 src_ip, __be16 src_port,
			__u32 tunnel_endpoint,
			__u32 seclabel, __u32 dstid, __u32 vni,
			void *opt, __u32 opt_len,
			enum trace_reason ct_reason,
			__u32 monitor, int *ifindex)
{
	__u32 node_id;
	int ret;

	/* When encapsulating, a packet originating from the local host is
	 * being considered as a packet from a remote node as it is being
	 * received.
	 */
	if (seclabel == HOST_ID)
		seclabel = LOCAL_NODE_ID;

	node_id = bpf_ntohl(tunnel_endpoint);

	cilium_dbg(ctx, DBG_ENCAP, node_id, seclabel);

	ret = ctx_set_encap_info(ctx, src_ip, src_port, node_id, seclabel, vni, opt,
				 opt_len, ifindex);
	if (ret == CTX_ACT_REDIRECT)
		send_trace_notify(ctx, TRACE_TO_OVERLAY, seclabel, dstid, 0, *ifindex,
				  ct_reason, monitor);

	return ret;
}

static __always_inline void
set_geneve_dsr_opt4(__be16 port, __be32 addr, struct geneve_dsr_opt4 *gopt)
{
	memset(gopt, 0, sizeof(*gopt));
	gopt->hdr.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS);
	gopt->hdr.type = DSR_GENEVE_OPT_TYPE;
	gopt->hdr.length = DSR_IPV4_GENEVE_OPT_LEN;
	gopt->addr = addr;
	gopt->port = port;
}

static __always_inline void
set_geneve_dsr_opt6(__be16 port, const union v6addr *addr,
		    struct geneve_dsr_opt6 *gopt)
{
	memset(gopt, 0, sizeof(*gopt));
	gopt->hdr.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS);
	gopt->hdr.type = DSR_GENEVE_OPT_TYPE;
	gopt->hdr.length = DSR_IPV6_GENEVE_OPT_LEN;
	ipv6_addr_copy(&gopt->addr, addr);
	gopt->port = port;
}
#endif
#endif /* HAVE_ENCAP */
#endif /* __LIB_ENCAP_H_ */
