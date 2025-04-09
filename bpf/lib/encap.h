/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "dbg.h"
#include "hash.h"
#include "trace.h"

#if __ctx_is == __ctx_skb
#include "encrypt.h"
#endif /* __ctx_is == __ctx_skb */

#ifdef HAVE_ENCAP
static __always_inline int
__encap_with_nodeid4(struct __ctx_buff *ctx, __u32 src_ip, __be16 src_port,
		     __be32 tunnel_endpoint,
		     __u32 seclabel, __u32 dstid, __u32 vni,
		     enum trace_reason ct_reason, __u32 monitor, int *ifindex)
{
	/* When encapsulating, a packet originating from the local host is
	 * being considered as a packet from a remote node as it is being
	 * received.
	 */
	if (seclabel == HOST_ID)
		seclabel = LOCAL_NODE_ID;

	cilium_dbg(ctx, DBG_ENCAP, tunnel_endpoint, seclabel);

#if __ctx_is == __ctx_skb
	*ifindex = ENCAP_IFINDEX;
#else
	*ifindex = 0;
#endif

	send_trace_notify(ctx, TRACE_TO_OVERLAY, seclabel, dstid, TRACE_EP_ID_UNKNOWN,
			  *ifindex, ct_reason, monitor);

	return ctx_set_encap_info4(ctx, src_ip, src_port, tunnel_endpoint, seclabel, vni,
				   NULL, 0);
}

static __always_inline int
__encap_with_nodeid6(struct __ctx_buff *ctx, const union v6addr *tunnel_endpoint,
		     __u32 seclabel, __u32 dstid, enum trace_reason ct_reason,
		     __u32 monitor, int *ifindex)
{
	/* When encapsulating, a packet originating from the local host is
	 * being considered as a packet from a remote node as it is being
	 * received.
	 */
	if (seclabel == HOST_ID)
		seclabel = LOCAL_NODE_ID;

#if __ctx_is == __ctx_skb
	*ifindex = ENCAP_IFINDEX;
#else
	*ifindex = 0;
#endif

	send_trace_notify(ctx, TRACE_TO_OVERLAY, seclabel, dstid, TRACE_EP_ID_UNKNOWN,
			  *ifindex, ct_reason, monitor);

	return ctx_set_encap_info6(ctx, tunnel_endpoint, seclabel);
}

static __always_inline int
__encap_and_redirect_with_nodeid(struct __ctx_buff *ctx,
				 const struct remote_endpoint_info *info,
				 __u32 seclabel, __u32 dstid, __u32 vni,
				 const struct trace_ctx *trace)
{
	int ifindex;
	int ret = 0;

	if (info->flag_ipv6_tunnel_ep)
		ret = __encap_with_nodeid6(ctx, &info->tunnel_endpoint.ip6,
					   seclabel, dstid, trace->reason,
					   trace->monitor, &ifindex);
	else
		ret = __encap_with_nodeid4(ctx, 0, 0,
					   info->tunnel_endpoint.ip4, seclabel,
					   dstid, vni, trace->reason,
					   trace->monitor, &ifindex);
	if (ret != CTX_ACT_REDIRECT)
		return ret;

	return ctx_redirect(ctx, ifindex, 0);
}

/* encap_and_redirect_with_nodeid returns CTX_ACT_OK after ctx meta-data is
 * set. Caller should pass the ctx to the stack at this point. Otherwise
 * returns CTX_ACT_REDIRECT on successful redirect to tunnel device.
 * On error returns a DROP_* reason.
 */
static __always_inline int
encap_and_redirect_with_nodeid(struct __ctx_buff *ctx,
			       struct remote_endpoint_info *info,
			       __u8 encrypt_key __maybe_unused,
			       __u32 seclabel, __u32 dstid,
			       const struct trace_ctx *trace)
{
	return __encap_and_redirect_with_nodeid(ctx, info, seclabel, dstid,
						NOT_VTEP_DST, trace);
}

#if defined(TUNNEL_MODE)
/* encap_and_redirect_lxc adds IPSec metadata (if enabled) and returns the packet
 * so that it can be passed to the IP stack. Without IPSec the packet is
 * typically redirected to the output tunnel device and ctx will not be seen by
 * the IP stack.
 *
 * Returns CTX_ACT_OK when ctx needs to be handed to IP stack (eg. for IPSec
 * handling), a DROP_* reason on error, and finally on successful redirect returns
 * CTX_ACT_REDIRECT.
 */
static __always_inline int
encap_and_redirect_lxc(struct __ctx_buff *ctx,
		       struct remote_endpoint_info *info, __u8 encrypt_key,
		       __u32 seclabel, __u32 dstid,
		       const struct trace_ctx *trace)
{
	return encap_and_redirect_with_nodeid(ctx, info, encrypt_key, seclabel,
					      dstid, trace);
}
#endif /* TUNNEL_MODE */

static __always_inline __be16
tunnel_gen_src_port_v4(struct ipv4_ct_tuple *tuple __maybe_unused)
{
#if __ctx_is == __ctx_xdp
	__be32 hash = hash_from_tuple_v4(tuple);

	return (hash >> 16)  ^ (__be16)hash;
#else
	return 0;
#endif
}

static __always_inline __be16
tunnel_gen_src_port_v6(struct ipv6_ct_tuple *tuple __maybe_unused)
{
#if __ctx_is == __ctx_xdp
	__be32 hash = hash_from_tuple_v6(tuple);

	return (hash >> 16)  ^ (__be16)hash;
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
	/* When encapsulating, a packet originating from the local host is
	 * being considered as a packet from a remote node as it is being
	 * received.
	 */
	if (seclabel == HOST_ID)
		seclabel = LOCAL_NODE_ID;

	cilium_dbg(ctx, DBG_ENCAP, tunnel_endpoint, seclabel);

#if __ctx_is == __ctx_skb
	*ifindex = ENCAP_IFINDEX;
#else
	*ifindex = 0;
#endif

	send_trace_notify(ctx, TRACE_TO_OVERLAY, seclabel, dstid, TRACE_EP_ID_UNKNOWN,
			  *ifindex, ct_reason, monitor);

	return ctx_set_encap_info4(ctx, src_ip, src_port, tunnel_endpoint, seclabel, vni, opt,
				   opt_len);
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
	ipv6_addr_copy_unaligned((union v6addr *)&gopt->addr, addr);

	gopt->port = port;
}
#endif

# if defined(ENABLE_IPV4) || defined(ENABLE_IPV6)
static __always_inline int
get_tunnel_key(struct __ctx_buff *ctx, struct bpf_tunnel_key *key)
{
	__u32 key_size __maybe_unused = TUNNEL_KEY_WITHOUT_SRC_IP;
	int ret __maybe_unused;

#  ifdef ENABLE_IPV4
	ret = ctx_get_tunnel_key(ctx, key, key_size, 0);
	if (!ret)
		return ret;
#  endif /* ENABLE_IPV4 */
#  ifdef ENABLE_IPV6
	ret = ctx_get_tunnel_key(ctx, key, key_size, BPF_F_TUNINFO_IPV6);
	if (!ret)
		return ret;
#  endif /* ENABLE_IPV6 */

	return DROP_NO_TUNNEL_KEY;
}
# endif /* ENABLE_IPV4 || ENABLE_IPV6 */
#endif /* HAVE_ENCAP */
