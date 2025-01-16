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
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct tunnel_key);
	__type(value, struct tunnel_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, TUNNEL_ENDPOINT_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} TUNNEL_MAP __section_maps_btf;

static __always_inline int
__encap_with_nodeid(struct __ctx_buff *ctx, __u32 src_ip, __be16 src_port,
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

	return ctx_set_encap_info(ctx, src_ip, src_port, tunnel_endpoint, seclabel, vni,
				  NULL, 0);
}

static __always_inline int
__encap_and_redirect_with_nodeid(struct __ctx_buff *ctx,
				 __be32 tunnel_endpoint,
				 __u32 seclabel, __u32 dstid, __u32 vni,
				 const struct trace_ctx *trace)
{
	int ifindex;
	int ret = 0;

	ret = __encap_with_nodeid(ctx, 0, 0, tunnel_endpoint, seclabel, dstid,
				  vni, trace->reason, trace->monitor,
				  &ifindex);
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
encap_and_redirect_with_nodeid(struct __ctx_buff *ctx, __be32 tunnel_endpoint,
			       __u8 encrypt_key __maybe_unused,
			       __u32 seclabel, __u32 dstid,
			       const struct trace_ctx *trace)
{
	return __encap_and_redirect_with_nodeid(ctx, tunnel_endpoint,
						seclabel, dstid, NOT_VTEP_DST,
						trace);
}

/* __encap_and_redirect_lxc() is a variant of encap_and_redirect_lxc()
 * that requires a valid tunnel_endpoint.
 */
static __always_inline int
__encap_and_redirect_lxc(struct __ctx_buff *ctx, __be32 tunnel_endpoint,
			 __u8 encrypt_key, __u32 seclabel, __u32 dstid,
			 const struct trace_ctx *trace)
{
	return encap_and_redirect_with_nodeid(ctx, tunnel_endpoint,
					      encrypt_key, seclabel, dstid,
					      trace);
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
		       __be32 tunnel_endpoint __maybe_unused,
		       __u32 src_ip __maybe_unused,
		       __u32 dst_ip __maybe_unused,
		       __u8 encrypt_key __maybe_unused,
		       struct tunnel_key *key __maybe_unused,
		       __u32 seclabel, __u32 dstid,
		       const struct trace_ctx *trace)
{
	struct tunnel_value *tunnel __maybe_unused;

	if (tunnel_endpoint)
		return __encap_and_redirect_lxc(ctx, tunnel_endpoint,
						encrypt_key, seclabel, dstid,
						trace);

	tunnel = map_lookup_elem(&TUNNEL_MAP, key);
	if (!tunnel)
		return DROP_NO_TUNNEL_ENDPOINT;

	return __encap_and_redirect_with_nodeid(ctx, tunnel->ip4, seclabel,
						dstid, NOT_VTEP_DST, trace);
}

static __always_inline int
encap_and_redirect_netdev(struct __ctx_buff *ctx, struct tunnel_key *k,
			  __u8 encrypt_key, __u32 seclabel,
			  const struct trace_ctx *trace)
{
	struct tunnel_value *tunnel;

	tunnel = map_lookup_elem(&TUNNEL_MAP, k);
	if (!tunnel)
		return DROP_NO_TUNNEL_ENDPOINT;

	return encap_and_redirect_with_nodeid(ctx, tunnel->ip4, encrypt_key,
					      seclabel, 0, trace);
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

	return ctx_set_encap_info(ctx, src_ip, src_port, tunnel_endpoint, seclabel, vni, opt,
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
#endif /* HAVE_ENCAP */
