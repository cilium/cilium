/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "dbg.h"
#include "eps.h"
#include "hash.h"
#include "trace.h"
#include "vtep.h"
#include "geneve_encap.h"

#ifndef ENCAP_IFINDEX
#define ENCAP_IFINDEX 0
#endif

#if defined(ENABLE_BPF_GENEVE)
static __always_inline int
__geneve_encap_and_redirect(struct __ctx_buff *ctx,
			    const struct remote_endpoint_info *info,
			    __u32 seclabel, __u32 vni __maybe_unused,
			    const void *opt, __u32 opt_len)
{
	__u32 tunnel_id;

	if (seclabel == HOST_ID)
		seclabel = LOCAL_NODE_ID;

	if (CONFIG(enable_vtep) && vni != NOT_VTEP_DST)
		tunnel_id = get_tunnel_id(vni);
	else
		tunnel_id = get_tunnel_id(seclabel);

	if (info->flag_ipv6_tunnel_ep) {
#ifdef BPF_TEST
		struct bpf_tunnel_key key = {};

		key.tunnel_id = tunnel_id;
		key.remote_ipv6[0] = info->tunnel_endpoint.ip6.p1;
		key.remote_ipv6[1] = info->tunnel_endpoint.ip6.p2;
		key.remote_ipv6[2] = info->tunnel_endpoint.ip6.p3;
		key.remote_ipv6[3] = info->tunnel_endpoint.ip6.p4;
		ctx_set_tunnel_key(ctx, &key, sizeof(key), BPF_F_TUNINFO_IPV6);
		if (opt && opt_len > 0)
			ctx_set_tunnel_opt(ctx, (void *)opt, opt_len);
#else
		struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);

		if (meta) {
			if (opt && opt_len > 0 && opt_len <= BPF_GENEVE_OPT_MAX_LEN) {
				__bpf_memcpy_builtin(meta->raw_opts, opt, opt_len);
				meta->opt_len = (__u8)opt_len;
			} else if (meta->magic != BPF_GENEVE_META_MAGIC) {
				meta->opt_len = 0;
			}
			meta->magic = BPF_GENEVE_META_MAGIC;
			meta->vni = tunnel_id;
			meta->family = AF_INET6;
			meta->ip6.daddr = info->tunnel_endpoint.ip6;
		}
#endif
		return tail_call_internal(ctx, CILIUM_CALL_GENEVE_ENCAP6, NULL);
	} else {
#ifdef BPF_TEST
		struct bpf_tunnel_key key = {};

		key.tunnel_id = tunnel_id;
		key.remote_ipv4 = bpf_ntohl(info->tunnel_endpoint.ip4.be32);
		ctx_set_tunnel_key(ctx, &key, sizeof(key), BPF_F_ZERO_CSUM_TX);
		if (opt && opt_len > 0)
			ctx_set_tunnel_opt(ctx, (void *)opt, opt_len);
#else
		struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);

		if (meta) {
			if (opt && opt_len > 0 && opt_len <= BPF_GENEVE_OPT_MAX_LEN) {
				__bpf_memcpy_builtin(meta->raw_opts, opt, opt_len);
				meta->opt_len = (__u8)opt_len;
			} else if (meta->magic != BPF_GENEVE_META_MAGIC) {
				meta->opt_len = 0;
			}
			meta->magic = BPF_GENEVE_META_MAGIC;
			meta->vni = tunnel_id;
			meta->family = AF_INET;
			meta->ip4.daddr = info->tunnel_endpoint.ip4.be32;
		}
#endif
		return tail_call_internal(ctx, CILIUM_CALL_GENEVE_ENCAP4, NULL);
	}
}
#endif /* ENABLE_BPF_GENEVE */

static __always_inline int
__encap_with_nodeid(struct __ctx_buff *ctx, __u32 src_ip __maybe_unused,
		    __be16 src_port __maybe_unused,
		    const struct remote_endpoint_info *info, __u32 seclabel,
		    __u32 dstid, __u32 vni, void *opt, __u32 opt_len,
		    enum trace_reason ct_reason, __u32 monitor, int *ifindex,
		    __be16 proto)
{
	/* When encapsulating, a packet originating from the local host is
	 * being considered as a packet from a remote node as it is being
	 * received.
	 */
	if (seclabel == HOST_ID)
		seclabel = LOCAL_NODE_ID;

#if defined(ENABLE_BPF_GENEVE) && __ctx_is == __ctx_skb
# ifdef BPF_TEST
	*ifindex = ENCAP_IFINDEX;
# else
	*ifindex = 0;
# endif
	send_trace_notify(ctx, TRACE_TO_OVERLAY, seclabel, dstid, TRACE_EP_ID_UNKNOWN,
			  *ifindex, ct_reason, monitor, proto);
	return __geneve_encap_and_redirect(ctx, info, seclabel, vni, opt, opt_len);
#else
#if __ctx_is == __ctx_skb
	*ifindex = ENCAP_IFINDEX;
#else
	*ifindex = 0;
#endif

	send_trace_notify(ctx, TRACE_TO_OVERLAY, seclabel, dstid, TRACE_EP_ID_UNKNOWN,
			  *ifindex, ct_reason, monitor, proto);

	if (info->flag_ipv6_tunnel_ep)
		return ctx_set_encap_info6(ctx, &info->tunnel_endpoint.ip6,
					   seclabel, opt, opt_len);

	cilium_dbg(ctx, DBG_ENCAP, info->tunnel_endpoint.ip4.be32, seclabel);

	return ctx_set_encap_info4(ctx, src_ip, src_port,
				   info->tunnel_endpoint.ip4.be32,
				   seclabel, vni, opt, opt_len);
#endif
}

static __always_inline int
__encap_and_redirect_with_nodeid(struct __ctx_buff *ctx,
				 const struct remote_endpoint_info *info,
				 __u32 seclabel, __u32 dstid, __u32 vni,
				 const struct trace_ctx *trace, __be16 proto)
{
#if defined(ENABLE_BPF_GENEVE) && __ctx_is == __ctx_skb
	send_trace_notify(ctx, TRACE_TO_OVERLAY, seclabel, dstid, TRACE_EP_ID_UNKNOWN,
			  0, trace->reason, trace->monitor, proto);
	return __geneve_encap_and_redirect(ctx, info, seclabel, vni, NULL, 0);
#else
	int ifindex;
	int ret = 0;

	ret = __encap_with_nodeid(ctx, 0, 0, info, seclabel,
				  dstid, vni, NULL, 0, trace->reason,
				  trace->monitor, &ifindex, proto);
	if (ret != CTX_ACT_REDIRECT)
		return ret;

	return ctx_redirect(ctx, ifindex, 0);
#endif
}

/* encap_and_redirect_with_nodeid returns CTX_ACT_REDIRECT on successful
 * redirect to tunnel device. On error returns a DROP_* reason.
 */
static __always_inline int
encap_and_redirect_with_nodeid(struct __ctx_buff *ctx,
			       const struct remote_endpoint_info *info,
			       __u32 seclabel, __u32 dstid,
			       const struct trace_ctx *trace,
			       __be16 proto)
{
	return __encap_and_redirect_with_nodeid(ctx, info, seclabel, dstid,
						NOT_VTEP_DST, trace, proto);
}

#if defined(TUNNEL_MODE)
/* encap_and_redirect_lxc returns CTX_ACT_REDIRECT on successful redirect, and
 * a DROP_* reason on error.
 */
static __always_inline int
encap_and_redirect_lxc(struct __ctx_buff *ctx, const struct remote_endpoint_info *info,
		       __u32 seclabel, __u32 dstid, const struct trace_ctx *trace, __be16 proto)
{
	return encap_and_redirect_with_nodeid(ctx, info, seclabel, dstid, trace, proto);
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

# if defined(ENABLE_IPV4) || defined(ENABLE_IPV6)
static __always_inline int
get_tunnel_key(struct __ctx_buff *ctx, struct bpf_tunnel_key *key)
{
	__u32 key_size __maybe_unused = TUNNEL_KEY_WITHOUT_SRC_IP;
	int ret __maybe_unused;

#if __ctx_is == __ctx_skb
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_INGRESS);

	if (meta && meta->magic == BPF_GENEVE_META_MAGIC && meta->vni) {
		key->tunnel_id = meta->vni;
		if (meta->family == AF_INET) {
			key->remote_ipv4 = bpf_ntohl(meta->ip4.saddr);
		} else {
			key->remote_ipv6[0] = meta->ip6.saddr.p1;
			key->remote_ipv6[1] = meta->ip6.saddr.p2;
			key->remote_ipv6[2] = meta->ip6.saddr.p3;
			key->remote_ipv6[3] = meta->ip6.saddr.p4;
		}
		return 0;
	}
#endif

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
