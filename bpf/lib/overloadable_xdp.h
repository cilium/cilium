/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "identity.h"
#include "tunnel.h"
#undef ctx_pull_data
#define ctx_pull_data(ctx, ...) ({ 0; })
#include "geneve_encap.h"

static __always_inline __maybe_unused void
bpf_clear_meta(struct xdp_md *ctx __maybe_unused)
{
	__u32 zero = 0, *data_meta = map_lookup_elem(&cilium_xdp_scratch, &zero);

	/* Unlike __sk_buff->cb[] in tcx (per-skb), the XDP "meta" lives
	 * in a per-CPU PERCPU_ARRAY (cilium_xdp_scratch) that persists
	 * across packets on the same CPU. CB slots can alias. Thus zero
	 * the CB region on each program entry to mirror the TC behavior.
	 * Leave RECIRC_MARKER / XFER_MARKER (offsets 5/6) intact; they
	 * have their own dedicated clears.
	 */
	if (always_succeeds(data_meta)) {
		data_meta[0] = 0;
		data_meta[1] = 0;
		data_meta[2] = 0;
		data_meta[3] = 0;
		data_meta[4] = 0;
	}
}

static __always_inline __maybe_unused void
ctx_store_meta_ipv6(struct xdp_md *ctx __maybe_unused, const __u64 off,
		    const union v6addr *addr)
{
	__u32 zero = 0, *data_meta = map_lookup_elem(&cilium_xdp_scratch, &zero);

	if (always_succeeds(data_meta))
		memcpy(&data_meta[off], addr, sizeof(*addr));

	build_bug_on((off + 4) * sizeof(__u32) > META_PIVOT);
}

static __always_inline __maybe_unused void
ctx_load_meta_ipv6(const struct xdp_md *ctx __maybe_unused,
		   union v6addr *addr, const __u64 off)
{
	__u32 zero = 0, *data_meta = map_lookup_elem(&cilium_xdp_scratch, &zero);

	if (always_succeeds(data_meta))
		memcpy(addr, &data_meta[off], sizeof(*addr));

	build_bug_on((off + 4) * sizeof(__u32) > META_PIVOT);
}

static __always_inline __maybe_unused int
redirect_self(struct xdp_md *ctx __maybe_unused)
{
	return CTX_ACT_TX;
}

static __always_inline __maybe_unused int
redirect_neigh(__u32 ifindex __maybe_unused,
	       struct bpf_redir_neigh *params __maybe_unused,
	       int plen __maybe_unused,
	       __u32 flags __maybe_unused)
{
	/* Available only in TC BPF. */
	__throw_build_bug();
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

static __always_inline int
bpf_geneve_xdp_insert_opt(struct xdp_md *ctx, const void *opt, __u32 opt_len);

static __always_inline __maybe_unused int
ctx_set_tunnel_opt(struct xdp_md *ctx, const void *opt, __u32 opt_len)
{
	return bpf_geneve_xdp_insert_opt(ctx, opt, opt_len);
}
static __always_inline __maybe_unused int
ctx_set_encap_info4(struct xdp_md *ctx, __u32 src_ip, __be16 src_port,
		    __u32 daddr, __u32 seclabel, __u32 vni __maybe_unused,
		    const void *opt, __u32 opt_len)
{
	__u32 pkt_len = (__u32)ctx_full_len(ctx);
	__u32 tunnel_hdr_len = 8; /* vxlan */
	struct ethhdr inner_eth;
	void *data, *data_end;
	__be16 inner_proto;
	struct vxlanhdr *vxlan;
	struct ethhdr *eth;
	struct udphdr *udp;
	struct iphdr *ip4;
	__u32 inner_ip_len;
	__u32 hdr_len;
	__u8 tun_proto;
	__be32 vni_be;
	__u16 dport;

	if (pkt_len < ETH_HLEN || ctx_load_bytes(ctx, 0, &inner_eth, ETH_HLEN) < 0)
		return DROP_INVALID;

	inner_proto = inner_eth.h_proto;
	if (!src_ip)
		src_ip = CONFIG(ipv4_direct_routing).be32;

	tun_proto = CONFIG(tunnel_protocol);
#ifdef TUNNEL_PROTOCOL
	if (!tun_proto)
		tun_proto = TUNNEL_PROTOCOL;
#endif
#if defined(ENABLE_BPF_GENEVE) || (defined(DSR_ENCAP_MODE) && defined(DSR_ENCAP_GENEVE) && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE)
	if (!tun_proto)
		tun_proto = TUNNEL_PROTOCOL_GENEVE;
#endif

	if (tun_proto == TUNNEL_PROTOCOL_GENEVE) {
		__u32 tunnel_vni = vni != 0 ? get_tunnel_id(vni) : get_tunnel_id(seclabel);
		int ret = bpf_geneve_encap4_with_sport(ctx, src_ip, daddr,
						       tunnel_vni, inner_proto,
						       src_port, opt, opt_len);
		return ret < 0 ? ret : CTX_ACT_REDIRECT;
	}

	if (opt_len > 0 || tun_proto != TUNNEL_PROTOCOL_VXLAN)
		return DROP_INVALID;

	inner_ip_len = pkt_len - ETH_HLEN;
	hdr_len = sizeof(struct iphdr) + sizeof(struct udphdr) + tunnel_hdr_len;

	if (ctx_adjust_hroom(ctx, (__s32)(ETH_HLEN + hdr_len), BPF_ADJ_ROOM_MAC,
			     BPF_F_ADJ_ROOM_NO_CSUM_RESET))
		return DROP_INVALID;

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + hdr_len > data_end)
		return DROP_INVALID;

	eth = data;
	ip4 = (void *)eth + sizeof(*eth);
	udp = (void *)ip4 + sizeof(*ip4);
	vxlan = (void *)udp + sizeof(*udp);

	*eth = inner_eth;
	eth->h_proto = bpf_htons(ETH_P_IP);

#ifdef TUNNEL_PORT
	dport = CONFIG(tunnel_port) ? CONFIG(tunnel_port) : TUNNEL_PORT;
#else
	dport = CONFIG(tunnel_port);
#endif

	udp->source = src_port;
	udp->dest = bpf_htons(dport);
	udp->len = bpf_htons((__u16)(sizeof(*udp) + tunnel_hdr_len + ETH_HLEN + inner_ip_len));
	udp->check = 0;

	ip4->ihl = 5;
	ip4->version = IPVERSION;
	ip4->tos = 0;
	ip4->tot_len = bpf_htons((__u16)(sizeof(*ip4) + bpf_ntohs(udp->len)));
	ip4->id = 0;
	ip4->frag_off = 0;
	ip4->ttl = IPDEFTTL;
	ip4->protocol = IPPROTO_UDP;
	ip4->saddr = src_ip;
	ip4->daddr = daddr;
	ip4->check = 0;
	ip4->check = bpf_geneve_ipv4_csum(ip4);

	vxlan->vx_flags = bpf_htonl(1U << 27);
	vni_be = sec_identity_to_tunnel_vni(get_tunnel_id(seclabel));
	memcpy(&vxlan->vx_vni, &vni_be, sizeof(__u32));

	if (ctx_store_bytes(ctx, ETH_HLEN + hdr_len, &inner_eth, ETH_HLEN, 0) < 0)
		return DROP_INVALID;

	return CTX_ACT_REDIRECT;
}

static __always_inline __maybe_unused int
__ctx_set_encap_info6(struct xdp_md *ctx, const union v6addr *src_ip,
		      __be16 src_port, const union v6addr *daddr,
		      __u32 seclabel, const void *opt, __u32 opt_len,
		      bool has_src_arg)
{
	struct ethhdr inner_eth;
	union v6addr saddr = {};
	__u8 tun_proto = CONFIG(tunnel_protocol);
	int ret;

#ifdef TUNNEL_PROTOCOL
	if (!tun_proto)
		tun_proto = TUNNEL_PROTOCOL;
#endif
#if defined(ENABLE_BPF_GENEVE) || (defined(DSR_ENCAP_MODE) && defined(DSR_ENCAP_GENEVE) && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE)
	if (!tun_proto)
		tun_proto = TUNNEL_PROTOCOL_GENEVE;
#endif
	if (tun_proto != TUNNEL_PROTOCOL_GENEVE ||
	    ctx_load_bytes(ctx, 0, &inner_eth, ETH_HLEN) < 0)
		return DROP_INVALID;

	if (src_ip && (src_ip->p1 || src_ip->p2 || src_ip->p3 || src_ip->p4)) {
		saddr = *src_ip;
	} else {
#ifdef ENABLE_IPV6
		saddr = CONFIG(ipv6_direct_routing);
#ifdef ENABLE_ROUTING
		if (!saddr.p1 && !saddr.p2 && !saddr.p3 && !saddr.p4)
			saddr = CONFIG(router_ipv6);
#endif
#endif
		if (!has_src_arg && !saddr.p1 && !saddr.p2 && !saddr.p3 && !saddr.p4)
			return DROP_INVALID;
	}

	ret = bpf_geneve_encap6_with_sport(ctx, &saddr, daddr,
					   get_tunnel_id(seclabel),
					   inner_eth.h_proto, src_port,
					   opt, opt_len);
	return ret < 0 ? ret : CTX_ACT_REDIRECT;
}

static __always_inline __maybe_unused int
ctx_set_encap_info6_with_src(struct xdp_md *ctx, const union v6addr *src_ip,
			     __be16 src_port, const union v6addr *daddr,
			     __u32 seclabel, const void *opt, __u32 opt_len)
{
	return __ctx_set_encap_info6(ctx, src_ip, src_port, daddr, seclabel,
				     opt, opt_len, true);
}

static __always_inline __maybe_unused int
ctx_set_encap_info6(struct xdp_md *ctx, const union v6addr *daddr,
		    __u32 seclabel, const void *opt, __u32 opt_len)
{
	return __ctx_set_encap_info6(ctx, NULL, 0, daddr, seclabel,
				     opt, opt_len, false);
}
