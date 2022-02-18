/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_OVERLOADABLE_XDP_H_
#define __LIB_OVERLOADABLE_XDP_H_

static __always_inline __maybe_unused void
bpf_clear_meta(struct xdp_md *ctx __maybe_unused)
{
}

static __always_inline __maybe_unused int
get_identity(struct xdp_md *ctx __maybe_unused)
{
	return 0;
}

static __always_inline __maybe_unused void
set_encrypt_dip(struct xdp_md *ctx __maybe_unused,
		__u32 ip_endpoint __maybe_unused)
{
}

static __always_inline __maybe_unused void
set_identity_mark(struct xdp_md *ctx __maybe_unused, __u32 identity __maybe_unused)
{
}

static __always_inline __maybe_unused void
set_identity_meta(struct xdp_md *ctx __maybe_unused,
		__u32 identity __maybe_unused)
{
}

static __always_inline __maybe_unused void
set_encrypt_key_mark(struct xdp_md *ctx __maybe_unused, __u8 key __maybe_unused)
{
}

static __always_inline __maybe_unused void
set_encrypt_key_meta(struct xdp_md *ctx __maybe_unused, __u8 key __maybe_unused)
{
}

static __always_inline __maybe_unused int
redirect_self(struct xdp_md *ctx __maybe_unused)
{
#ifdef ENABLE_HOST_REDIRECT
	return XDP_TX;
#else
	return -ENOTSUP;
#endif
}

#define RECIRC_MARKER	5 /* tail call recirculation */
#define XFER_MARKER	6 /* xdp -> skb meta transfer */

static __always_inline __maybe_unused void
ctx_skip_nodeport_clear(struct xdp_md *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	ctx_store_meta(ctx, RECIRC_MARKER, 0);
#endif
}

static __always_inline __maybe_unused void
ctx_skip_nodeport_set(struct xdp_md *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	ctx_store_meta(ctx, RECIRC_MARKER, 1);
#endif
}

static __always_inline __maybe_unused bool
ctx_skip_nodeport(struct xdp_md *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	return ctx_load_meta(ctx, RECIRC_MARKER);
#else
	return true;
#endif
}

static __always_inline __maybe_unused __u32
ctx_get_xfer(struct xdp_md *ctx __maybe_unused)
{
	return 0; /* Only intended for SKB context. */
}

static __always_inline __maybe_unused void ctx_set_xfer(struct xdp_md *ctx,
							__u32 meta)
{
	ctx_store_meta(ctx, XFER_MARKER, meta);
}

static __always_inline __maybe_unused int
ctx_change_head(struct xdp_md *ctx __maybe_unused,
		__u32 head_room __maybe_unused,
		__u64 flags __maybe_unused)
{
	return 0; /* Only intended for SKB context. */
}

#endif /* __LIB_OVERLOADABLE_XDP_H_ */
