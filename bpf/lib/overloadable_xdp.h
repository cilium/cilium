/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef __LIB_OVERLOADABLE_XDP_H_
#define __LIB_OVERLOADABLE_XDP_H_

static __always_inline __maybe_unused __overloadable void
bpf_clear_cb(struct xdp_md *ctx)
{
}

static __always_inline __maybe_unused __overloadable int
get_identity(struct xdp_md *ctx)
{
	return 0;
}

static __always_inline __maybe_unused __overloadable void
set_encrypt_dip(struct xdp_md *ctx, __u32 ip_endpoint)
{
}

static __always_inline __maybe_unused __overloadable void
set_identity(struct xdp_md *ctx, __u32 identity)
{
}

static __always_inline __maybe_unused __overloadable void
set_identity_cb(struct xdp_md *ctx, __u32 identity)
{
}

static __always_inline __maybe_unused __overloadable void
set_encrypt_key(struct xdp_md *ctx, __u8 key)
{
}

static __always_inline __maybe_unused __overloadable void
set_encrypt_key_cb(struct xdp_md *ctx, __u8 key)
{
}

static __always_inline __maybe_unused __overloadable int
redirect_self(struct xdp_md *ctx)
{
#ifdef ENABLE_HOST_REDIRECT
	return XDP_TX;
#else
	return -ENOTSUP;
#endif
}

#define RECIRC_MARKER	5

static __always_inline __maybe_unused __overloadable void
ctx_skip_nodeport_clear(struct xdp_md *ctx)
{
#ifdef ENABLE_NODEPORT
	ctx_store_meta(ctx, RECIRC_MARKER, 0);
#endif
}

static __always_inline __maybe_unused __overloadable void
ctx_skip_nodeport_set(struct xdp_md *ctx)
{
#ifdef ENABLE_NODEPORT
	ctx_store_meta(ctx, RECIRC_MARKER, 1);
#endif
}

static __always_inline __maybe_unused __overloadable bool
ctx_skip_nodeport(struct xdp_md *ctx)
{
#ifdef ENABLE_NODEPORT
	return ctx_load_meta(ctx, RECIRC_MARKER);
#else
        return true;
#endif
}

#endif /* __LIB_OVERLOADABLE_XDP_H_ */
