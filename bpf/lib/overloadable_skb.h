/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"
#include "linux/ip.h"


static __always_inline __maybe_unused void
bpf_clear_meta(struct __sk_buff *ctx)
{
	__u32 zero = 0;

	WRITE_ONCE(ctx->cb[0], zero);
	WRITE_ONCE(ctx->cb[1], zero);
	WRITE_ONCE(ctx->cb[2], zero);
	WRITE_ONCE(ctx->cb[3], zero);
	WRITE_ONCE(ctx->cb[4], zero);

	/* This needs to be cleared mainly for tcx. */
	WRITE_ONCE(ctx->tc_classid, zero);
}

static __always_inline __maybe_unused void
ctx_store_meta_ipv6(struct __sk_buff *ctx, const __u32 off, const union v6addr *addr)
{
	ctx_store_meta(ctx, off, addr->p1);
	ctx_store_meta(ctx, off + 1, addr->p2);
	ctx_store_meta(ctx, off + 2, addr->p3);
	ctx_store_meta(ctx, off + 3, addr->p4);
}

static __always_inline __maybe_unused void
ctx_load_meta_ipv6(const struct __sk_buff *ctx, union v6addr *addr, const __u32 off)
{
	addr->p1 = ctx_load_meta(ctx, off);
	addr->p2 = ctx_load_meta(ctx, off + 1);
	addr->p3 = ctx_load_meta(ctx, off + 2);
	addr->p4 = ctx_load_meta(ctx, off + 3);
}

/**
 * get_epid - returns endpoint identifier from the mark field
 */
static __always_inline __maybe_unused __u16
get_epid(const struct __sk_buff *ctx)
{
	return ctx->mark >> 16;
}

static __always_inline __maybe_unused void
set_encrypt_identity_meta(struct __sk_buff *ctx, __u32 identity)
{
	ctx->cb[CB_ENCRYPT_IDENTITY] = identity;
}

static __always_inline __maybe_unused __u32
get_encrypt_identity_meta(const struct __sk_buff *ctx)
{
	return ctx->cb[CB_ENCRYPT_IDENTITY];
}

static __always_inline __maybe_unused int
redirect_self(const struct __sk_buff *ctx)
{
	/* Looping back the packet into the originating netns. We xmit into the
	 * hosts' veth device such that we end up on ingress in the peer.
	 */
	return (int)ctx_redirect(ctx, ctx->ifindex, 0);
}

static __always_inline __maybe_unused bool
neigh_resolver_available(void)
{
	return true;
}

static __always_inline __maybe_unused void
ctx_skip_nodeport_clear(struct __sk_buff *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	ctx->tc_index &= ~TC_INDEX_F_SKIP_NODEPORT;
#endif
}

static __always_inline __maybe_unused void
ctx_skip_nodeport_set(struct __sk_buff *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	ctx->tc_index |= TC_INDEX_F_SKIP_NODEPORT;
#endif
}

static __always_inline __maybe_unused bool
ctx_skip_nodeport(struct __sk_buff *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	volatile __u32 tc_index = ctx->tc_index;
	ctx->tc_index &= ~TC_INDEX_F_SKIP_NODEPORT;
	return tc_index & TC_INDEX_F_SKIP_NODEPORT;
#else
	return true;
#endif
}

#ifdef ENABLE_HOST_FIREWALL
static __always_inline void
ctx_skip_host_fw_set(struct __sk_buff *ctx)
{
	ctx->tc_index |= TC_INDEX_F_SKIP_HOST_FIREWALL;
}

static __always_inline bool
ctx_skip_host_fw(struct __sk_buff *ctx)
{
	volatile __u32 tc_index = ctx->tc_index;

	ctx->tc_index &= ~TC_INDEX_F_SKIP_HOST_FIREWALL;
	return tc_index & TC_INDEX_F_SKIP_HOST_FIREWALL;
}
#endif /* ENABLE_HOST_FIREWALL */

static __always_inline __maybe_unused __u32 ctx_get_xfer(struct __sk_buff *ctx,
							 __u32 off)
{
	__u32 *data_meta = ctx_data_meta(ctx);
	void *data = ctx_data(ctx);

	return !ctx_no_room(data_meta + off + 1, data) ? data_meta[off] : 0;
}

static __always_inline __maybe_unused void
ctx_set_xfer(struct __sk_buff *ctx __maybe_unused, __u32 meta __maybe_unused)
{
	/* Only possible from XDP -> SKB. */
}

static __always_inline __maybe_unused void
ctx_move_xfer(struct __sk_buff *ctx __maybe_unused)
{
	/* Only possible from XDP -> SKB. */
}

static __always_inline __maybe_unused int
ctx_change_head(struct __sk_buff *ctx, __u32 head_room, __u64 flags)
{
	return skb_change_head(ctx, head_room, flags);
}

static __always_inline void ctx_snat_done_set(struct __sk_buff *ctx)
{
	ctx->mark &= ~MARK_MAGIC_HOST_MASK;
	ctx->mark |= MARK_MAGIC_SNAT_DONE;
}

static __always_inline bool ctx_snat_done(const struct __sk_buff *ctx)
{
	return (ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_SNAT_DONE;
}

static __always_inline bool ctx_is_overlay(const struct __sk_buff *ctx)
{
	if (!is_defined(HAVE_ENCAP))
		return false;

	return (ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY;
}

static __always_inline bool ctx_is_encrypt(const struct __sk_buff *ctx)
{
	if (!is_defined(ENABLE_WIREGUARD) && !is_defined(ENABLE_IPSEC))
		return false;

	return (ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT;
}

static __always_inline bool ctx_is_decrypt(const struct __sk_buff *ctx)
{
	if (!is_defined(ENABLE_WIREGUARD) && !is_defined(ENABLE_IPSEC))
		return false;

	return (ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT;
}

#ifdef ENABLE_EGRESS_GATEWAY_COMMON
static __always_inline bool ctx_egw_done(const struct __sk_buff *ctx)
{
	return (ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_EGW_DONE;
}
#endif /* ENABLE_EGRESS_GATEWAY_COMMON */

#ifdef HAVE_ENCAP
static __always_inline __maybe_unused int
ctx_set_encap_info4(struct __sk_buff *ctx, __u32 src_ip,
		    __be16 src_port __maybe_unused, __u32 tunnel_endpoint,
		    __u32 seclabel, __u32 vni __maybe_unused,
		    void *opt, __u32 opt_len)
{
	struct bpf_tunnel_key key = {};
	__u32 key_size = TUNNEL_KEY_WITHOUT_SRC_IP;
	int ret;

#ifdef ENABLE_VTEP
	if (vni != NOT_VTEP_DST)
		key.tunnel_id = get_tunnel_id(vni);
	else
#endif /* ENABLE_VTEP */
		key.tunnel_id = get_tunnel_id(seclabel);

	if (src_ip != 0) {
		key.local_ipv4 = bpf_ntohl(src_ip);
		key_size = sizeof(key);
	}
	key.remote_ipv4 = bpf_ntohl(tunnel_endpoint);
	key.tunnel_ttl = IPDEFTTL;

	ret = ctx_set_tunnel_key(ctx, &key, key_size, BPF_F_ZERO_CSUM_TX);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;

	if (opt && opt_len > 0) {
		ret = ctx_set_tunnel_opt(ctx, opt, opt_len);
		if (unlikely(ret < 0))
			return DROP_WRITE_ERROR;
	}

	return CTX_ACT_REDIRECT;
}

static __always_inline __maybe_unused int
ctx_set_encap_info6(struct __sk_buff *ctx, const union v6addr *tunnel_endpoint,
		    __u32 seclabel, void *opt, __u32 opt_len)
{
	struct bpf_tunnel_key key = {};
	__u32 key_size = TUNNEL_KEY_WITHOUT_SRC_IP;
	int ret;

	key.tunnel_id = get_tunnel_id(seclabel);
	key.remote_ipv6[0] = tunnel_endpoint->p1;
	key.remote_ipv6[1] = tunnel_endpoint->p2;
	key.remote_ipv6[2] = tunnel_endpoint->p3;
	key.remote_ipv6[3] = tunnel_endpoint->p4;
	key.tunnel_ttl = IPDEFTTL;

	ret = ctx_set_tunnel_key(ctx, &key, key_size, BPF_F_TUNINFO_IPV6);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;

	if (opt && opt_len > 0) {
		ret = ctx_set_tunnel_opt(ctx, opt, opt_len);
		if (unlikely(ret < 0))
			return DROP_WRITE_ERROR;
	}

	return CTX_ACT_REDIRECT;
}
#endif /* HAVE_ENCAP */
