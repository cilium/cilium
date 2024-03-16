/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"
#include "linux/ip.h"
#include "lib/clustermesh.h"


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
 * get_identity - returns source identity from the mark field
 *
 * Identity stored in the mark is rearranged to place identity in the most
 * significant bits and cluster_id in the least significant bits, separated by 8
 * bits that are used for other options. When retrieving identity from the mark,
 * we need to rearrange it back to the original format.
 *
 * Example mark containing identity, where I is a bit for identity, C is a bit
 * for cluster_id, and X is a bit that should not be touched by this function:
 * IIIIIIII IIIIIIII XXXXXXXX CCCCCCCC
 *
 * This function should return an identity that looks like the following:
 * CCCCCCCC IIIIIIII IIIIIIII
 *
 * The agent flag 'max-connected-clusters' can effect the allocation of bits
 * for identity and cluster_id in the mark (see comment in set_identity_mark).
 */
static __always_inline __maybe_unused int
get_identity(const struct __sk_buff *ctx)
{
	__u32 cluster_id_lower = ctx->mark & CLUSTER_ID_LOWER_MASK;
	__u32 cluster_id_upper = (ctx->mark & get_cluster_id_upper_mask()) >> (8 + IDENTITY_LEN);
	__u32 identity = (ctx->mark >> 16) & IDENTITY_MAX;

	return (cluster_id_lower | cluster_id_upper) << IDENTITY_LEN | identity;
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
 *
 * Identity in the mark looks like the following, where I is a bit for
 * identity, C is a bit for cluster_id, and X is a bit that should not be
 * touched by this function:
 * IIIIIIII IIIIIIII XXXXXXXX CCCCCCCC
 *
 * With the agent flag 'max-connected-clusters', it is possible to extend the
 * cluster_id range by sacrificing some bits of the identity. When this is set
 * to a value other than the default 255, the most significant bits are taken
 * from identity and used for the most significant bits of cluster_id.
 *
 * An agent with 'max-connected-clusters=512' would set identity in the mark
 * like the following:
 * CIIIIIII IIIIIIII XXXXXXXX CCCCCCCC
 */
static __always_inline __maybe_unused void
set_identity_mark(struct __sk_buff *ctx, __u32 identity, __u32 magic)
{
	__u32 cluster_id = (identity >> IDENTITY_LEN) & CLUSTER_ID_MAX;
	__u32 cluster_id_lower = cluster_id & 0xFF;
	__u32 cluster_id_upper = ((cluster_id & 0xFFFFFF00) << (8 + IDENTITY_LEN));

	ctx->mark |= magic;
	ctx->mark &= MARK_MAGIC_KEY_MASK;
	ctx->mark |= (identity & IDENTITY_MAX) << 16 | cluster_id_lower | cluster_id_upper;
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

static __always_inline __maybe_unused void
set_encrypt_key_meta(struct __sk_buff *ctx, __u8 key, __u32 node_id)
{
	ctx->cb[CB_ENCRYPT_MAGIC] = or_encrypt_key(key) | node_id << 16;
}

/**
 * set_cluster_id_mark - sets the cluster_id mark.
 */
static __always_inline __maybe_unused void
ctx_set_cluster_id_mark(struct __sk_buff *ctx, __u32 cluster_id)
{
	__u32 cluster_id_lower = (cluster_id & 0xFF);
	__u32 cluster_id_upper = ((cluster_id & 0xFFFFFF00) << (8 + IDENTITY_LEN));

	ctx->mark |=  cluster_id_lower | cluster_id_upper | MARK_MAGIC_CLUSTER_ID;
}

static __always_inline __maybe_unused __u32
ctx_get_cluster_id_mark(struct __sk_buff *ctx)
{
	__u32 ret = 0;
	__u32 cluster_id_lower = ctx->mark & CLUSTER_ID_LOWER_MASK;
	__u32 cluster_id_upper = (ctx->mark & get_cluster_id_upper_mask()) >> (8 + IDENTITY_LEN);

	if ((ctx->mark & MARK_MAGIC_CLUSTER_ID) != MARK_MAGIC_CLUSTER_ID)
		return ret;

	ret = (cluster_id_upper | cluster_id_lower) & CLUSTER_ID_MAX;
	ctx->mark &= ~(__u32)(MARK_MAGIC_CLUSTER_ID | get_mark_magic_cluster_id_mask());

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

static __always_inline bool ctx_is_overlay(const struct __sk_buff *ctx)
{
	if (!is_defined(HAVE_ENCAP))
		return false;

	return (ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY;
}

#ifdef ENABLE_EGRESS_GATEWAY_COMMON
static __always_inline void ctx_egw_done_set(struct __sk_buff *ctx)
{
	ctx->mark &= ~MARK_MAGIC_HOST_MASK;
	ctx->mark |= MARK_MAGIC_EGW_DONE;
}

static __always_inline bool ctx_egw_done(const struct __sk_buff *ctx)
{
	return (ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_EGW_DONE;
}
#endif /* ENABLE_EGRESS_GATEWAY_COMMON */

#ifdef HAVE_ENCAP
static __always_inline __maybe_unused int
ctx_set_encap_info(struct __sk_buff *ctx, __u32 src_ip,
		   __be16 src_port __maybe_unused, __u32 node_id,
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

	return CTX_ACT_REDIRECT;
}
#endif /* HAVE_ENCAP */
