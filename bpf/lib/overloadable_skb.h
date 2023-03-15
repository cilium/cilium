/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_OVERLOADABLE_SKB_H_
#define __LIB_OVERLOADABLE_SKB_H_

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
}

/**
 * get_identity - returns source identity from the mark field
 */
static __always_inline __maybe_unused int
get_identity(const struct __sk_buff *ctx)
{
	return ((ctx->mark & 0xFF) << 16) | ctx->mark >> 16;
}

/**
 * get_epid - returns source endpoint identity from the mark field
 */
static __always_inline __maybe_unused __u32
get_epid(const struct __sk_buff *ctx)
{
	return ctx->mark >> 16;
}

/**
 * set_identity_mark - pushes 24 bit identity into ctx mark value.
 */
static __always_inline __maybe_unused void
set_identity_mark(struct __sk_buff *ctx, __u32 identity)
{
	ctx->mark = ctx->mark & MARK_MAGIC_KEY_MASK;
	ctx->mark |= ((identity & 0xFFFF) << 16) | ((identity & 0xFF0000) >> 16);
}

static __always_inline __maybe_unused void
set_identity_meta(struct __sk_buff *ctx, __u32 identity)
{
	ctx->cb[CB_ENCRYPT_IDENTITY] = identity;
}

/**
 * set_encrypt_key - pushes 8 bit key, 16 bit node ID, and encryption marker into ctx mark value.
 */
static __always_inline __maybe_unused void
set_encrypt_key_mark(struct __sk_buff *ctx, __u8 key, __u32 node_id)
{
	ctx->mark = or_encrypt_key(key) | node_id << 16;
}

/**
 * set_cluster_id_mark - sets the cluster_id mark.
 */
static __always_inline __maybe_unused void
ctx_set_cluster_id_mark(struct __sk_buff *ctx, __u32 cluster_id)
{
	ctx->mark |= cluster_id | MARK_MAGIC_CLUSTER_ID;
}

static __always_inline __maybe_unused __u32
ctx_get_cluster_id_mark(struct __sk_buff *ctx)
{
	__u32 ret = 0;

	if ((ctx->mark & MARK_MAGIC_CLUSTER_ID) != MARK_MAGIC_CLUSTER_ID)
		return ret;

	ret = ctx->mark & MARK_MAGIC_CLUSTER_ID_MASK;
	ctx->mark &= ~(__u32)(MARK_MAGIC_CLUSTER_ID | MARK_MAGIC_CLUSTER_ID_MASK);

	return ret;
}

static __always_inline __maybe_unused int
redirect_self(const struct __sk_buff *ctx)
{
	/* Looping back the packet into the originating netns. We xmit into the
	 * hosts' veth device such that we end up on ingress in the peer.
	 */
	return ctx_redirect(ctx, ctx->ifindex, 0);
}

static __always_inline __maybe_unused bool
neigh_resolver_available(void)
{
	return is_defined(HAVE_FIB_NEIGH);
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

#ifdef HAVE_ENCAP
static __always_inline __maybe_unused int
ctx_set_encap_info(struct __sk_buff *ctx, __u32 src_ip,
		   __be16 src_port __maybe_unused, __u32 node_id,
		   __u32 seclabel, __u32 vni __maybe_unused,
		   void *opt, __u32 opt_len, int *ifindex)
{
	struct bpf_tunnel_key key = {};
	__u32 key_size = TUNNEL_KEY_WITHOUT_SRC_IP;
	int ret;

#ifdef ENABLE_VTEP
	if (vni != NOT_VTEP_DST)
		key.tunnel_id = vni;
	else
#endif /* ENABLE_VTEP */
		key.tunnel_id = seclabel;

	if (src_ip != 0) {
		key.local_ipv4 = bpf_ntohl(src_ip);
		key_size = sizeof(key);
	}
	key.remote_ipv4 = node_id;
	key.tunnel_ttl = IPDEFTTL;

	ret = ctx_set_tunnel_key(ctx, &key, key_size, BPF_F_ZERO_CSUM_TX);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;

	if (opt && opt_len > 0) {
		ret = ctx_set_tunnel_opt(ctx, opt, opt_len);
		if (unlikely(ret < 0))
			return DROP_WRITE_ERROR;
	}

	*ifindex = ENCAP_IFINDEX;

	return CTX_ACT_REDIRECT;
}
#endif /* HAVE_ENCAP */

#endif /* __LIB_OVERLOADABLE_SKB_H_ */
