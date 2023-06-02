/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_OVERLOADABLE_XDP_H_
#define __LIB_OVERLOADABLE_XDP_H_

#include <linux/udp.h>
#include <linux/ip.h>

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
ctx_set_cluster_id_mark(struct xdp_md *ctx __maybe_unused, __u32 cluster_id __maybe_unused)
{
}

static __always_inline __maybe_unused __u32
ctx_get_cluster_id_mark(struct __sk_buff *ctx __maybe_unused)
{
	return 0;
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

	if (meta_xfer) {
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
ctx_set_encap_info(struct xdp_md *ctx, __u32 src_ip, __be16 src_port,
		   __u32 daddr, __u32 seclabel __maybe_unused,
		   __u32 vni __maybe_unused, void *opt, __u32 opt_len, int *ifindex)
{
	__u32 inner_len = ctx_full_len(ctx);
	__u32 tunnel_hdr_len = 8; /* geneve / vxlan */
	void *data, *data_end;
	struct ethhdr *eth;
	struct udphdr *udp;
	struct iphdr *ip4;
	__u32 outer_len;

	/* Add space in front (50 bytes + options) */
	outer_len = sizeof(*eth) + sizeof(*ip4) + sizeof(*udp) + tunnel_hdr_len + opt_len;

	if (ctx_adjust_hroom(ctx, outer_len, BPF_ADJ_ROOM_NET, ctx_adjust_hroom_flags()))
		return DROP_INVALID;

	/* validate access to outer headers: */
	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + outer_len > data_end)
		return DROP_INVALID;

	eth = data;
	ip4 = (void *)eth + sizeof(*eth);
	udp = (void *)ip4 + sizeof(*ip4);

	memset(data, 0, sizeof(*eth) + sizeof(*ip4) + sizeof(*udp) + tunnel_hdr_len);

	switch (TUNNEL_PROTOCOL) {
	case TUNNEL_PROTOCOL_GENEVE:
		{
			struct genevehdr *geneve = (void *)udp + sizeof(*udp);

			if (opt_len > 0)
				memcpy((void *)geneve + sizeof(*geneve), opt, opt_len);

			geneve->opt_len = (__u8)(opt_len >> 2);
			geneve->protocol_type = bpf_htons(ETH_P_TEB);

			seclabel = bpf_htonl(seclabel << 8);
			memcpy(&geneve->vni, &seclabel, sizeof(__u32));
		}
		break;
	case TUNNEL_PROTOCOL_VXLAN:
		if (opt_len > 0)
			return DROP_INVALID;

		{
			struct vxlanhdr *vxlan = (void *)udp + sizeof(*udp);

			vxlan->vx_flags = bpf_htonl(1U << 27);

			seclabel = bpf_htonl(seclabel << 8);
			memcpy(&vxlan->vx_vni, &seclabel, sizeof(__u32));
		}
		break;
	default:
		__throw_build_bug();
	}

	udp->source = src_port;
	udp->dest = bpf_htons(TUNNEL_PORT);
	udp->len = bpf_htons((__u16)(sizeof(*udp) + tunnel_hdr_len + opt_len + inner_len));
	udp->check = 0; /* we use BPF_F_ZERO_CSUM_TX */

	ip4->ihl = 5;
	ip4->version = IPVERSION;
	ip4->tot_len = bpf_htons((__u16)(sizeof(*ip4) + bpf_ntohs(udp->len)));
	ip4->ttl = IPDEFTTL;
	ip4->protocol = IPPROTO_UDP;
	ip4->saddr = src_ip;
	ip4->daddr = bpf_htonl(daddr);
	ip4->check = csum_fold(csum_diff(NULL, 0, ip4, sizeof(*ip4), 0));

	eth->h_proto = bpf_htons(ETH_P_IP);

	*ifindex = 0;

	return CTX_ACT_REDIRECT;
}
#endif /* HAVE_ENCAP */

#endif /* __LIB_OVERLOADABLE_XDP_H_ */
