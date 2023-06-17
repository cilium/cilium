/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_HIGH_SCALE_IPCACHE_H_
#define __LIB_HIGH_SCALE_IPCACHE_H_

#include "maps.h"

#ifdef ENABLE_HIGH_SCALE_IPCACHE
/* WORLD_CIDR_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of
 * world_cidrs_key4.
 */
# define WORLD_CIDR_STATIC_PREFIX4						\
	(8 * (sizeof(struct world_cidrs_key4) - sizeof(struct bpf_lpm_trie_key)	\
	      - sizeof(__u32)))
#define WORLD_CIDR_PREFIX_LEN4(PREFIX) (WORLD_CIDR_STATIC_PREFIX4 + (PREFIX))

static __always_inline __maybe_unused bool
world_cidrs_lookup4(__u32 addr)
{
	__u8 *matches;
	struct world_cidrs_key4 key = {
		.lpm_key = { WORLD_CIDR_PREFIX_LEN4(V4_CACHE_KEY_LEN), {} },
		.ip = addr,
	};

	key.ip &= GET_PREFIX(V4_CACHE_KEY_LEN);
	matches = map_lookup_elem(&WORLD_CIDRS4_MAP, &key);
	return matches != NULL;
}

static __always_inline bool
needs_encapsulation(__u32 addr)
{
# ifndef ENABLE_ROUTING
	/* If endpoint routes are enabled, we need to check if the destination
	 * is a local endpoint, in which case we don't want to encapsulate. If
	 * endpoint routes are disabled, we don't need to check this because we
	 * will never reach this point and the packet will be redirected to the
	 * destination endpoint directly.
	 */
	if (__lookup_ip4_endpoint(addr))
		return false;
# endif /* ENABLE_ROUTING */
	/* If the destination doesn't match one of the world CIDRs, we assume
	 * it's destined to a remote pod. In that case, since the high-scale
	 * ipcache is enabled, we want to encapsulate with the remote pod's IP
	 * itself.
	 */
	return !world_cidrs_lookup4(addr);
}

static __always_inline int
decapsulate_overlay(struct __ctx_buff *ctx, __u32 *src_id)
{
	struct geneve_dsr_opt4 dsr_opt __maybe_unused;
	struct genevehdr geneve __maybe_unused;
	__u32 opt_len __maybe_unused;
	void *data, *data_end;
	__u16 dport, proto;
	struct iphdr *ip4;
	int shrink;
	__u32 off;

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;
	if (proto != bpf_htons(ETH_P_IP))
		return CTX_ACT_OK;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	if (ip4->protocol != IPPROTO_UDP)
		return CTX_ACT_OK;

	off = ((void *)ip4 - data) + ipv4_hdrlen(ip4) +
	      offsetof(struct udphdr, dest);
	if (l4_load_port(ctx, off, &dport) < 0)
		return DROP_INVALID;

	if (dport != bpf_htons(TUNNEL_PORT))
		return CTX_ACT_OK;

	switch (TUNNEL_PROTOCOL) {
	case TUNNEL_PROTOCOL_GENEVE:
		off = ((void *)ip4 - data) + ipv4_hdrlen(ip4) + sizeof(struct udphdr);
		if (ctx_load_bytes(ctx, off, &geneve, sizeof(geneve)) < 0)
			return DROP_INVALID;

		opt_len = geneve.opt_len * 4;
		memcpy(src_id, &geneve.vni, sizeof(__u32));

#if defined(ENABLE_DSR) && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
		ctx_store_meta(ctx, CB_HSIPC_ADDR_V4, 0);

		if (opt_len && opt_len >= sizeof(dsr_opt)) {
			if (ctx_load_bytes(ctx, off + sizeof(geneve), &dsr_opt,
					   sizeof(dsr_opt)) < 0)
				return DROP_INVALID;

			if (dsr_opt.hdr.opt_class == bpf_htons(DSR_GENEVE_OPT_CLASS) &&
			    dsr_opt.hdr.type == DSR_GENEVE_OPT_TYPE) {
				ctx_store_meta(ctx, CB_HSIPC_ADDR_V4, dsr_opt.addr);
				ctx_store_meta(ctx, CB_HSIPC_PORT, dsr_opt.port);
			}
		}
#endif /* ENABLE_DSR && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE */

		shrink = ipv4_hdrlen(ip4) + sizeof(struct udphdr) +
			 sizeof(struct genevehdr) + opt_len +
			 sizeof(struct ethhdr);
		break;
	case TUNNEL_PROTOCOL_VXLAN:
		shrink = ipv4_hdrlen(ip4) + sizeof(struct udphdr) +
			 sizeof(struct vxlanhdr) + sizeof(struct ethhdr);
		off = ((void *)ip4 - data) + ipv4_hdrlen(ip4) +
		      sizeof(struct udphdr) +
		      offsetof(struct vxlanhdr, vx_vni);

		if (ctx_load_bytes(ctx, off, src_id, sizeof(__u32)) < 0)
			return DROP_INVALID;
		break;
	default:
		/* If the tunnel type is neither VXLAN nor GENEVE, we have an issue. */
		__throw_build_bug();
	}

	*src_id = bpf_ntohl(*src_id) >> 8;
	ctx_store_meta(ctx, CB_SRC_LABEL, *src_id);

	if (ctx_adjust_hroom(ctx, -shrink, BPF_ADJ_ROOM_MAC, ctx_adjust_hroom_flags()))
		return DROP_INVALID;
	return ctx_redirect(ctx, ENCAP_IFINDEX, BPF_F_INGRESS);
}
#endif /* ENABLE_HIGH_SCALE_IPCACHE */
#endif /* __LIB_HIGH_SCALE_IPCACHE_H_ */
