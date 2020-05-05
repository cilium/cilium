/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef __LIB_OVERLOADABLE_SKB_H_
#define __LIB_OVERLOADABLE_SKB_H_

static __always_inline __maybe_unused void
bpf_clear_meta(struct __sk_buff *ctx)
{
	__u32 zero = 0;

	ctx->cb[0] = zero;
	ctx->cb[1] = zero;
	ctx->cb[2] = zero;
	ctx->cb[3] = zero;
	ctx->cb[4] = zero;
}

/**
 * get_identity - returns source identity from the mark field
 */
static __always_inline __maybe_unused int
get_identity(const struct __sk_buff *ctx)
{
	return ((ctx->mark & 0xFF) << 16) | ctx->mark >> 16;
}

static __always_inline __maybe_unused void
set_encrypt_dip(struct __sk_buff *ctx, __u32 ip_endpoint)
{
	ctx->cb[4] = ip_endpoint;
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
	ctx->cb[1] = identity;
}

/**
 * set_encrypt_key - pushes 8 bit key and encryption marker into ctx mark value.
 */
static __always_inline __maybe_unused void
set_encrypt_key_mark(struct __sk_buff *ctx, __u8 key)
{
	ctx->mark = or_encrypt_key(key);
}

static __always_inline __maybe_unused void
set_encrypt_key_meta(struct __sk_buff *ctx, __u8 key)
{
	ctx->cb[0] = or_encrypt_key(key);
}

static __always_inline __maybe_unused int
redirect_self(const struct __sk_buff *ctx)
{
	/* Looping back the packet into the originating netns. In
	 * case of veth, it's xmit'ing into the hosts' veth device
	 * such that we end up on ingress in the peer. For ipvlan
	 * slave it's redirect to ingress as we are attached on the
	 * slave in netns already.
	 */
#ifdef ENABLE_HOST_REDIRECT
	return redirect(ctx->ifindex, 0);
#else
	return redirect(ctx->ifindex, BPF_F_INGRESS);
#endif
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

static __always_inline __maybe_unused __u32 ctx_get_xfer(struct __sk_buff *ctx)
{
	__u32 *data_meta = ctx_data_meta(ctx);
	void *data = ctx_data(ctx);

	return !ctx_no_room(data_meta + 1, data) ? data_meta[0] : 0;
}

static __always_inline __maybe_unused void
ctx_set_xfer(struct __sk_buff *ctx __maybe_unused, __u32 meta __maybe_unused)
{
	/* Only possible from XDP -> SKB. */
}

#endif /* __LIB_OVERLOADABLE_SKB_H_ */
