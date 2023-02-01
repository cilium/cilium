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
		__be32 ip_endpoint __maybe_unused)
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
set_encrypt_key_mark(struct xdp_md *ctx __maybe_unused, __u8 key __maybe_unused,
		     __u32 node_id __maybe_unused)
{
}

static __always_inline __maybe_unused void
set_encrypt_key_meta(struct xdp_md *ctx __maybe_unused, __u8 key __maybe_unused,
		     __u32 node_id __maybe_unused)
{
}

static __always_inline __maybe_unused int
redirect_self(struct xdp_md *ctx __maybe_unused)
{
	return XDP_TX;
}

static __always_inline __maybe_unused int
redirect_neigh(int ifindex __maybe_unused,
	       struct bpf_redir_neigh *params __maybe_unused,
	       int plen __maybe_unused,
	       __u32 flags __maybe_unused)
{
	return XDP_DROP;
}

static __always_inline __maybe_unused bool
neigh_resolver_available(void)
{
	return false;
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
ctx_get_xfer(struct xdp_md *ctx __maybe_unused, __u32 off __maybe_unused)
{
	return 0; /* Only intended for SKB context. */
}

static __always_inline __maybe_unused void ctx_set_xfer(struct xdp_md *ctx,
							__u32 meta)
{
	__u32 val = ctx_load_meta(ctx, XFER_MARKER);

	val |= meta;
	ctx_store_meta(ctx, XFER_MARKER, val);
}

static __always_inline __maybe_unused void ctx_move_xfer(struct xdp_md *ctx)
{
	__u32 meta_xfer = ctx_load_meta(ctx, XFER_MARKER);

	/* We transfer data from XFER_MARKER. This specifically
	 * does not break packet trains in GRO.
	 */
	if (meta_xfer & XFER_PKT_ENCAP) {
		if (!ctx_adjust_meta(ctx, -(int)(4 * sizeof(__u32)))) {
			__u32 *data_meta = ctx_data_meta(ctx);
			__u32 *data = ctx_data(ctx);

			if (!ctx_no_room(data_meta + 4, data)) {
				data_meta[XFER_FLAGS] = meta_xfer;
				data_meta[XFER_ENCAP_NODEID] =
					ctx_load_meta(ctx, CB_ENCAP_NODEID);
				data_meta[XFER_ENCAP_SECLABEL] =
					ctx_load_meta(ctx, CB_ENCAP_SECLABEL);
				data_meta[XFER_ENCAP_DSTID] =
					ctx_load_meta(ctx, CB_ENCAP_DSTID);
			}
		}
	} else if (meta_xfer) {
		if (!ctx_adjust_meta(ctx, -(int)sizeof(meta_xfer))) {
			__u32 *data_meta = ctx_data_meta(ctx);
			__u32 *data = ctx_data(ctx);

			if (!ctx_no_room(data_meta + 1, data))
				data_meta[XFER_FLAGS] = meta_xfer;
		}
	}
}

static __always_inline __maybe_unused int
ctx_change_head(struct xdp_md *ctx __maybe_unused,
		__u32 head_room __maybe_unused,
		__u64 flags __maybe_unused)
{
	return 0; /* Only intended for SKB context. */
}

static __always_inline void ctx_snat_done_set(struct xdp_md *ctx)
{
	ctx_set_xfer(ctx, XFER_PKT_SNAT_DONE);
}

static __always_inline bool ctx_snat_done(struct xdp_md *ctx)
{
	/* shouldn't be needed, there's no relevant Egress hook in XDP */
	return ctx_load_meta(ctx, XFER_MARKER) & XFER_PKT_SNAT_DONE;
}

#ifdef HAVE_ENCAP
static __always_inline __maybe_unused int
ctx_set_encap_info(struct xdp_md *ctx __maybe_unused,
		   __u32 node_id __maybe_unused,
		   __u32 seclabel __maybe_unused,
		   __u32 dstid __maybe_unused,
		   __u32 vni __maybe_unused, int *ifindex __maybe_unused)
{
	ctx_store_meta(ctx, CB_ENCAP_NODEID, bpf_ntohl(node_id));
	ctx_store_meta(ctx, CB_ENCAP_SECLABEL, seclabel);
	ctx_store_meta(ctx, CB_ENCAP_DSTID, dstid);
	ctx_set_xfer(ctx, XFER_PKT_ENCAP);

	return CTX_ACT_OK;
}
#endif /* HAVE_ENCAP */

#endif /* __LIB_OVERLOADABLE_XDP_H_ */
