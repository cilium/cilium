/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019-2020 Authors of Cilium */

#ifndef __NODEPORT_H_
#define __NODEPORT_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "tailcall.h"
#include "nat.h"
#include "edt.h"
#include "lb.h"
#include "common.h"
#include "overloadable.h"
#include "conntrack.h"
#include "csum.h"
#include "encap.h"
#include "trace.h"
#include "ghash.h"
#include "host_firewall.h"

#define CB_SRC_IDENTITY	0

#ifdef ENABLE_NODEPORT
 /* Define dummy values to make bpf_{lxc,overlay}.c to compile */
#ifndef NATIVE_DEV_IFINDEX
#define NATIVE_DEV_IFINDEX 0
#endif
#ifndef DSR_ENCAP_MODE
#define DSR_ENCAP_MODE 0
#define DSR_ENCAP_IPIP 2
#endif
#if defined(ENABLE_IPV4) && !defined(IPV4_NODEPORT)
#define IPV4_NODEPORT 0
#endif
#if defined(ENABLE_IPV4) && defined(ENABLE_MASQUERADE) && !defined(IPV4_MASQUERADE)
#define IPV4_MASQUERADE 0
#endif

#if defined(ENABLE_IPV6) && !defined(IPV6_NODEPORT_V)
DEFINE_IPV6(IPV6_NODEPORT,
	    0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
	    0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0);
# define IPV6_NODEPORT_V
#endif
#endif /* ENABLE_NODEPORT */

#ifdef IPV6_NODEPORT_VAL
# define BPF_V6_NODEPORT(dst)				\
	({						\
		union v6addr tmp = IPV6_NODEPORT_VAL;	\
		dst = tmp;				\
	})
#else
# define BPF_V6_NODEPORT(dst)	BPF_V6(dst, IPV6_NODEPORT)
#endif

static __always_inline __maybe_unused void
bpf_skip_nodeport_clear(struct __ctx_buff *ctx)
{
	ctx_skip_nodeport_clear(ctx);
}

static __always_inline __maybe_unused void
bpf_skip_nodeport_set(struct __ctx_buff *ctx)
{
	ctx_skip_nodeport_set(ctx);
}

static __always_inline __maybe_unused bool
bpf_skip_nodeport(struct __ctx_buff *ctx)
{
	return ctx_skip_nodeport(ctx);
}

#ifdef ENABLE_NODEPORT
#ifdef ENABLE_IPV4
struct bpf_elf_map __section_maps NODEPORT_NEIGH4 = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.size_key	= sizeof(__be32),		/* ipv4 addr */
	.size_value	= sizeof(union macaddr),	/* hw addr */
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= NODEPORT_NEIGH4_SIZE,
};
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
struct bpf_elf_map __section_maps NODEPORT_NEIGH6 = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.size_key	= sizeof(union v6addr),		/* ipv6 addr */
	.size_value	= sizeof(union macaddr),	/* hw addr */
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= NODEPORT_NEIGH6_SIZE,
};

/* The IPv6 extension should be 8-bytes aligned */
struct dsr_opt_v6 {
	__u8 nexthdr;
	__u8 len;
	__u8 opt_type;
	__u8 opt_len;
	union v6addr addr;
	__be32 port;
};
#endif /* ENABLE_IPV6 */

static __always_inline bool nodeport_uses_dsr(__u8 nexthdr __maybe_unused)
{
# if defined(ENABLE_DSR) && !defined(ENABLE_DSR_HYBRID)
	return true;
# elif defined(ENABLE_DSR) && defined(ENABLE_DSR_HYBRID)
	if (nexthdr == IPPROTO_TCP)
		return true;
	return false;
# else
	return false;
# endif
}

static __always_inline bool nodeport_lb_hairpin(void)
{
	return is_defined(ENABLE_NODEPORT_HAIRPIN);
}

static __always_inline void
bpf_mark_snat_done(struct __ctx_buff *ctx __maybe_unused)
{
	/* From XDP layer, we do not go through an egress hook from
	 * here, hence nothing to be done.
	 */
#if __ctx_is == __ctx_skb
	ctx->mark |= MARK_MAGIC_SNAT_DONE;
#endif
}

static __always_inline bool
bpf_skip_recirculation(const struct __ctx_buff *ctx __maybe_unused)
{
	/* From XDP layer, we do not go through an egress hook from
	 * here, hence nothing to be skipped.
	 */
#if __ctx_is == __ctx_skb
	return ctx->tc_index & TC_INDEX_F_SKIP_RECIRCULATION;
#else
	return false;
#endif
}

static __always_inline __u64 ctx_adjust_room_dsr_flags(void)
{
#ifdef BPF_HAVE_CSUM_LEVEL
	return BPF_F_ADJ_ROOM_NO_CSUM_RESET;
#else
	return 0;
#endif
}

#ifdef ENABLE_IPV6
static __always_inline bool nodeport_uses_dsr6(const struct ipv6_ct_tuple *tuple)
{
	return nodeport_uses_dsr(tuple->nexthdr);
}

/* TODO(brb): after GH#6320, we can move snat_v{4,6}_needed() to lib/nat.h, as
 * then the helper function won't depend the dsr checks.
 */
static __always_inline bool snat_v6_needed(struct __ctx_buff *ctx,
					   union v6addr *addr)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return false;
#ifdef ENABLE_DSR_HYBRID
	{
		__u8 nexthdr = ip6->nexthdr;
		int ret;

		ret = ipv6_hdrlen(ctx, ETH_HLEN, &nexthdr);
		if (ret > 0) {
			if (nodeport_uses_dsr(nexthdr))
				return false;
		}
	}
#endif /* ENABLE_DSR_HYBRID */
	/* See snat_v4_needed(). */
	return !ipv6_addrcmp((union v6addr *)&ip6->saddr, addr);
}

static __always_inline int nodeport_nat_ipv6_fwd(struct __ctx_buff *ctx,
						 union v6addr *addr)
{
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};
	int ret;

	ipv6_addr_copy(&target.addr, addr);

	ret = snat_v6_needed(ctx, addr) ?
	      snat_v6_process(ctx, NAT_DIR_EGRESS, &target) : CTX_ACT_OK;
	if (ret == NAT_PUNT_TO_STACK)
		ret = CTX_ACT_OK;
	return ret;
}

#ifdef ENABLE_DSR
#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
static __always_inline void rss_gen_src6(union v6addr *src,
					 const union v6addr *client,
					 __be32 l4_hint)
{
	__u32 bits = 128 - IPV6_RSS_PREFIX_BITS;

	*src = (union v6addr)IPV6_RSS_PREFIX;
	if (bits) {
		__u32 todo;

		if (bits > 96) {
			todo = bits - 96;
			src->p1 |= bpf_htonl(hash_32(client->p1 ^ l4_hint, todo));
			bits -= todo;
		}
		if (bits > 64) {
			todo = bits - 64;
			src->p2 |= bpf_htonl(hash_32(client->p2 ^ l4_hint, todo));
			bits -= todo;
		}
		if (bits > 32) {
			todo = bits - 32;
			src->p3 |= bpf_htonl(hash_32(client->p3 ^ l4_hint, todo));
			bits -= todo;
		}
		src->p4 |= bpf_htonl(hash_32(client->p4 ^ l4_hint, bits));
	}
}

static __always_inline int dsr_set_ipip6(struct __ctx_buff *ctx,
					 const struct ipv6hdr *ip6,
					 union v6addr *backend_addr,
					 __be32 l4_hint)
{
	union v6addr saddr;
	const int l3_off = ETH_HLEN;
	struct {
		__be16 payload_len;
		__u8 nexthdr;
		__u8 hop_limit;
	} tp_new = {
		.payload_len	= bpf_htons(bpf_ntohs(ip6->payload_len) +
					    sizeof(*ip6)),
		.nexthdr	= IPPROTO_IPV6,
		.hop_limit	= 64,
	};

	rss_gen_src6(&saddr, (union v6addr *)&ip6->saddr, l4_hint);

	if (ctx_adjust_room(ctx, sizeof(*ip6), BPF_ADJ_ROOM_NET,
			    ctx_adjust_room_dsr_flags()))
		return DROP_INVALID;
	if (ctx_store_bytes(ctx, l3_off + offsetof(struct ipv6hdr, payload_len),
			    &tp_new.payload_len, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, l3_off + offsetof(struct ipv6hdr, daddr),
			    backend_addr, sizeof(ip6->daddr), 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, l3_off + offsetof(struct ipv6hdr, saddr),
			    &saddr, sizeof(ip6->saddr), 0) < 0)
		return DROP_WRITE_ERROR;
	return 0;
}
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
static __always_inline int dsr_set_ext6(struct __ctx_buff *ctx,
					struct ipv6hdr *ip6,
					union v6addr *svc_addr, __be32 svc_port)
{
	struct dsr_opt_v6 opt __align_stack_8 = {};

	opt.nexthdr = ip6->nexthdr;
	ip6->nexthdr = NEXTHDR_DEST;
	ip6->payload_len = bpf_htons(bpf_ntohs(ip6->payload_len) + 24);

	opt.len = DSR_IPV6_EXT_LEN;
	opt.opt_type = DSR_IPV6_OPT_TYPE;
	opt.opt_len = DSR_IPV6_OPT_LEN;
	ipv6_addr_copy(&opt.addr, svc_addr);
	opt.port = svc_port;

	if (ctx_adjust_room(ctx, sizeof(opt), BPF_ADJ_ROOM_NET,
			    ctx_adjust_room_dsr_flags()))
		return DROP_INVALID;
	if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(*ip6), &opt,
			    sizeof(opt), 0) < 0)
		return DROP_INVALID;
	return 0;
}
#endif /* DSR_ENCAP_MODE */

static __always_inline int find_dsr_v6(struct __ctx_buff *ctx, __u8 nexthdr,
				       struct dsr_opt_v6 *dsr_opt, bool *found)
{
	struct ipv6_opt_hdr opthdr __align_stack_8;
	int i, len = sizeof(struct ipv6hdr);
	__u8 nh = nexthdr;

#pragma unroll
	for (i = 0; i < IPV6_MAX_HEADERS; i++) {
		switch (nh) {
		case NEXTHDR_NONE:
			return DROP_INVALID_EXTHDR;

		case NEXTHDR_FRAGMENT:
			return DROP_FRAG_NOSUPPORT;

		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_AUTH:
		case NEXTHDR_DEST:
			if (ctx_load_bytes(ctx, ETH_HLEN + len, &opthdr, sizeof(opthdr)) < 0)
				return DROP_INVALID;

			if (nh == NEXTHDR_DEST && opthdr.hdrlen == DSR_IPV6_EXT_LEN) {
				if (ctx_load_bytes(ctx, ETH_HLEN + len, dsr_opt,
						   sizeof(*dsr_opt)) < 0)
					return DROP_INVALID;
				if (dsr_opt->opt_type == DSR_IPV6_OPT_TYPE &&
				    dsr_opt->opt_len == DSR_IPV6_OPT_LEN) {
					*found = true;
					return 0;
				}
			}

			nh = opthdr.nexthdr;
			if (nh == NEXTHDR_AUTH)
				len += ipv6_authlen(&opthdr);
			else
				len += ipv6_optlen(&opthdr);
			break;

		default:
			return 0;
		}
	}

	/* Reached limit of supported extension headers */
	return DROP_INVALID_EXTHDR;
}

static __always_inline int handle_dsr_v6(struct __ctx_buff *ctx, bool *dsr)
{
	struct dsr_opt_v6 opt __align_stack_8 = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ret = find_dsr_v6(ctx, ip6->nexthdr, &opt, dsr);
	if (ret != 0)
		return ret;

	if (*dsr) {
		if (snat_v6_create_dsr(ctx, &opt.addr, opt.port) < 0)
			return DROP_INVALID;
	}

	return 0;
}

static __always_inline int xlate_dsr_v6(struct __ctx_buff *ctx,
					const struct ipv6_ct_tuple *tuple,
					int l4_off)
{
	struct ipv6_ct_tuple nat_tup = *tuple;
	struct ipv6_nat_entry *entry;
	int ret = 0;

	nat_tup.flags = NAT_DIR_EGRESS;
	nat_tup.sport = tuple->dport;
	nat_tup.dport = tuple->sport;

	entry = snat_v6_lookup(&nat_tup);
	if (entry)
		ret = snat_v6_rewrite_egress(ctx, &nat_tup, entry, l4_off);
	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_DSR)
int tail_nodeport_ipv6_dsr(struct __ctx_buff *ctx)
{
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET6,
			.ifindex	= DIRECT_ROUTING_DEV_IFINDEX,
		},
	};
	union macaddr *dmac = NULL;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr addr;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	addr.p1 = ctx_load_meta(ctx, CB_ADDR_V6_1);
	addr.p2 = ctx_load_meta(ctx, CB_ADDR_V6_2);
	addr.p3 = ctx_load_meta(ctx, CB_ADDR_V6_3);
	addr.p4 = ctx_load_meta(ctx, CB_ADDR_V6_4);

#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	ret = dsr_set_ipip6(ctx, ip6, &addr,
			    ctx_load_meta(ctx, CB_HINT));
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
	ret = dsr_set_ext6(ctx, ip6, &addr,
			   ctx_load_meta(ctx, CB_PORT));
#else
# error "Invalid load balancer DSR encapsulation mode!"
#endif
	if (ret)
		return ret;
	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	if (nodeport_lb_hairpin())
		dmac = map_lookup_elem(&NODEPORT_NEIGH6, &ip6->daddr);
	if (dmac) {
		union macaddr mac = NATIVE_DEV_MAC_BY_IFINDEX(fib_params.l.ifindex);

		if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
			return DROP_WRITE_ERROR;
		if (eth_store_saddr_aligned(ctx, mac.addr, 0) < 0)
			return DROP_WRITE_ERROR;
	} else {
		ipv6_addr_copy((union v6addr *) &fib_params.l.ipv6_src,
			       (union v6addr *) &ip6->saddr);
		ipv6_addr_copy((union v6addr *) &fib_params.l.ipv6_dst,
			       (union v6addr *) &ip6->daddr);

		ret = fib_lookup(ctx, &fib_params.l, sizeof(fib_params),
				 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
		if (ret != 0)
			return DROP_NO_FIB;
		if (nodeport_lb_hairpin())
			map_update_elem(&NODEPORT_NEIGH6, &ip6->daddr,
					fib_params.l.dmac, 0);
		if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0)
			return DROP_WRITE_ERROR;
		if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0)
			return DROP_WRITE_ERROR;
	}

	return ctx_redirect(ctx, fib_params.l.ifindex, 0);
}
#endif /* ENABLE_DSR */

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_NAT)
int tail_nodeport_nat_ipv6(struct __ctx_buff *ctx)
{
	int ret, dir = ctx_load_meta(ctx, CB_NAT);
	union v6addr tmp = IPV6_DIRECT_ROUTING;
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET6,
			.ifindex	= DIRECT_ROUTING_DEV_IFINDEX,
		},
	};
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.src_from_world = true,
	};
	union macaddr *dmac = NULL;
	void *data, *data_end;
	struct ipv6hdr *ip6;

	target.addr = tmp;
#ifdef ENCAP_IFINDEX
	if (dir == NAT_DIR_EGRESS) {
		struct remote_endpoint_info *info;
		union v6addr *dst;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		dst = (union v6addr *)&ip6->daddr;
		info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
		if (info != NULL && info->tunnel_endpoint != 0) {
			ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
						  SECLABEL, TRACE_PAYLOAD_LEN);
			if (ret)
				return ret;

			BPF_V6(target.addr, ROUTER_IP);
			fib_params.l.ifindex = ENCAP_IFINDEX;

			/* fib lookup not necessary when going over tunnel. */
			if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	}
#endif
	ret = snat_v6_process(ctx, dir, &target);
	if (IS_ERR(ret)) {
		/* In case of no mapping, recircle back to main path. SNAT is very
		 * expensive in terms of instructions (since we don't have BPF to
		 * BPF calls as we use tail calls) and complexity, hence this is
		 * done inside a tail call here.
		 */
		if (dir == NAT_DIR_INGRESS) {
			bpf_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_LXC);
			ret = DROP_MISSED_TAIL_CALL;
			goto drop_err;
		}
		if (ret != NAT_PUNT_TO_STACK)
			goto drop_err;
	}

	bpf_mark_snat_done(ctx);

	if (dir == NAT_DIR_INGRESS) {
		ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_REVNAT);
		ret = DROP_MISSED_TAIL_CALL;
		goto drop_err;
	}
#ifdef ENCAP_IFINDEX
	if (fib_params.l.ifindex == ENCAP_IFINDEX)
		goto out_send;
#endif
	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	if (nodeport_lb_hairpin())
		dmac = map_lookup_elem(&NODEPORT_NEIGH6, &ip6->daddr);
	if (dmac) {
		union macaddr mac = NATIVE_DEV_MAC_BY_IFINDEX(fib_params.l.ifindex);

		if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0) {
			ret = DROP_WRITE_ERROR;
			goto drop_err;
		}
		if (eth_store_saddr_aligned(ctx, mac.addr, 0) < 0) {
			ret = DROP_WRITE_ERROR;
			goto drop_err;
		}
	} else {
		ipv6_addr_copy((union v6addr *) &fib_params.l.ipv6_src,
			       (union v6addr *) &ip6->saddr);
		ipv6_addr_copy((union v6addr *) &fib_params.l.ipv6_dst,
			       (union v6addr *) &ip6->daddr);

		ret = fib_lookup(ctx, &fib_params.l, sizeof(fib_params),
				 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
		if (ret != 0) {
			ret = DROP_NO_FIB;
			goto drop_err;
		}
		if (nodeport_lb_hairpin())
			map_update_elem(&NODEPORT_NEIGH6, &ip6->daddr,
					fib_params.l.dmac, 0);

		if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
			ret = DROP_WRITE_ERROR;
			goto drop_err;
		}
		if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
			ret = DROP_WRITE_ERROR;
			goto drop_err;
		}
	}
out_send: __maybe_unused
	return ctx_redirect(ctx, fib_params.l.ifindex, 0);
drop_err:
	return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
				      dir == NAT_DIR_INGRESS ?
				      METRIC_INGRESS : METRIC_EGRESS);
}

/* See nodeport_lb4(). */
static __always_inline int nodeport_lb6(struct __ctx_buff *ctx,
					__u32 src_identity)
{
	int ret, l3_off = ETH_HLEN, l4_off, hdrlen;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	struct lb6_service *svc;
	struct lb6_key key = {};
	struct ct_state ct_state_new = {};
	union macaddr smac, *mac;
	bool backend_local;
	__u32 monitor = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(ctx, l3_off, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = l3_off + hdrlen;

	ret = lb6_extract_key(ctx, &tuple, l4_off, &key, &csum_off, CT_EGRESS);
	if (IS_ERR(ret)) {
		if (ret == DROP_NO_SERVICE)
			goto skip_service_lookup;
		else if (ret == DROP_UNKNOWN_L4)
			return CTX_ACT_OK;
		else
			return ret;
	}

	svc = lb6_lookup_service(&key, false);
	if (svc) {
		const bool skip_xlate = DSR_ENCAP_MODE == DSR_ENCAP_IPIP;

		if (!lb6_src_range_ok(svc, (union v6addr *)&ip6->saddr))
			return DROP_NOT_IN_SRC_RANGE;

		ret = lb6_local(get_ct_map6(&tuple), ctx, l3_off, l4_off,
				&csum_off, &key, &tuple, svc, &ct_state_new,
				skip_xlate);
		if (IS_ERR(ret))
			return ret;
	}

	if (!svc || !lb6_svc_is_routable(svc)) {
		if (svc)
			return DROP_IS_CLUSTER_IP;

skip_service_lookup:
		ctx_set_xfer(ctx, XFER_PKT_NO_SVC);

		if (nodeport_uses_dsr6(&tuple))
			return CTX_ACT_OK;

		ctx_store_meta(ctx, CB_NAT, NAT_DIR_INGRESS);
		ctx_store_meta(ctx, CB_SRC_IDENTITY, src_identity);
		ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT);
		return DROP_MISSED_TAIL_CALL;
	}

	backend_local = __lookup_ip6_endpoint(&tuple.daddr);
	if (!backend_local && lb6_svc_is_hostport(svc))
		return DROP_INVALID;

	if (backend_local || !nodeport_uses_dsr6(&tuple)) {
		struct ct_state ct_state = {};

		ret = ct_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off,
				 CT_EGRESS, &ct_state, &monitor);
		switch (ret) {
		case CT_NEW:
redo_all:
			ct_state_new.src_sec_id = SECLABEL;
			ct_state_new.node_port = 1;
			ct_state_new.ifindex = NATIVE_DEV_IFINDEX;
			ret = ct_create6(get_ct_map6(&tuple), NULL, &tuple, ctx,
					 CT_EGRESS, &ct_state_new, false);
			if (IS_ERR(ret))
				return ret;
			if (backend_local) {
				ct_flip_tuple_dir6(&tuple);
redo_local:
				ct_state_new.rev_nat_index = 0;
				ret = ct_create6(get_ct_map6(&tuple), NULL,
						 &tuple, ctx, CT_INGRESS,
						 &ct_state_new, false);
				if (IS_ERR(ret))
					return ret;
			}
			break;
		case CT_REOPENED:
		case CT_ESTABLISHED:
		case CT_REPLY:
			if (unlikely(ct_state.rev_nat_index !=
				     svc->rev_nat_index))
				goto redo_all;
			if (backend_local) {
				ct_flip_tuple_dir6(&tuple);
				if (!__ct_entry_keep_alive(get_ct_map6(&tuple),
							   &tuple)) {
					ct_state_new.src_sec_id = SECLABEL;
					ct_state_new.node_port = 1;
					ct_state_new.ifindex = NATIVE_DEV_IFINDEX;
					goto redo_local;
				}
			}
			break;
		default:
			return DROP_UNKNOWN_CT;
		}

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
		if (eth_load_saddr(ctx, smac.addr, 0) < 0)
			return DROP_INVALID;

		mac = map_lookup_elem(&NODEPORT_NEIGH6, &ip6->saddr);
		if (!mac || eth_addrcmp(mac, &smac)) {
			ret = map_update_elem(&NODEPORT_NEIGH6, &ip6->saddr,
					      &smac, 0);
			if (ret < 0)
				return ret;
		}
	}

	if (!backend_local) {
		edt_set_aggregate(ctx, 0);
		if (nodeport_uses_dsr6(&tuple)) {
#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
			ctx_store_meta(ctx, CB_HINT,
				       ((__u32)tuple.sport << 16) | tuple.dport);
			ctx_store_meta(ctx, CB_ADDR_V6_1, tuple.daddr.p1);
			ctx_store_meta(ctx, CB_ADDR_V6_2, tuple.daddr.p2);
			ctx_store_meta(ctx, CB_ADDR_V6_3, tuple.daddr.p3);
			ctx_store_meta(ctx, CB_ADDR_V6_4, tuple.daddr.p4);
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
			ctx_store_meta(ctx, CB_PORT, key.dport);
			ctx_store_meta(ctx, CB_ADDR_V6_1, key.address.p1);
			ctx_store_meta(ctx, CB_ADDR_V6_2, key.address.p2);
			ctx_store_meta(ctx, CB_ADDR_V6_3, key.address.p3);
			ctx_store_meta(ctx, CB_ADDR_V6_4, key.address.p4);
#endif /* DSR_ENCAP_MODE */
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_DSR);
		} else {
			ctx_store_meta(ctx, CB_NAT, NAT_DIR_EGRESS);
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT);
		}
		return DROP_MISSED_TAIL_CALL;
	}

	ctx_set_xfer(ctx, XFER_PKT_NO_SVC);

	return CTX_ACT_OK;
}

/* See comment in tail_rev_nodeport_lb4(). */
static __always_inline int rev_nodeport_lb6(struct __ctx_buff *ctx, int *ifindex)
{
	int ret, ret2, l3_off = ETH_HLEN, l4_off, hdrlen;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	struct ct_state ct_state = {};
	struct bpf_fib_lookup fib_params = {};
	union macaddr *dmac;
	__u32 monitor = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(ctx, l3_off, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = l3_off + hdrlen;
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off, CT_INGRESS, &ct_state,
			 &monitor);

	if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {
		ret2 = lb6_rev_nat(ctx, l4_off, &csum_off, ct_state.rev_nat_index,
				   &tuple, REV_NAT_F_TUPLE_SADDR);
		if (IS_ERR(ret2))
			return ret2;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		bpf_mark_snat_done(ctx);

		*ifindex = ct_state.ifindex;
#ifdef ENCAP_IFINDEX
		{
			union v6addr *dst = (union v6addr *)&ip6->daddr;
			struct remote_endpoint_info *info;

			info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
			if (info != NULL && info->tunnel_endpoint != 0) {
				ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
							  SECLABEL, TRACE_PAYLOAD_LEN);
				if (ret)
					return ret;

				*ifindex = ENCAP_IFINDEX;

				/* fib lookup not necessary when going over tunnel. */
				if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
					return DROP_WRITE_ERROR;
				if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
					return DROP_WRITE_ERROR;

				return CTX_ACT_OK;
			}
		}
#endif

		dmac = map_lookup_elem(&NODEPORT_NEIGH6, &tuple.daddr);
		if (dmac) {
			union macaddr mac = NATIVE_DEV_MAC_BY_IFINDEX(*ifindex);

			if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr_aligned(ctx, mac.addr, 0) < 0)
				return DROP_WRITE_ERROR;
		} else {
			fib_params.family = AF_INET6;
			fib_params.ifindex = *ifindex;

			ipv6_addr_copy((union v6addr *) &fib_params.ipv6_src, &tuple.saddr);
			ipv6_addr_copy((union v6addr *) &fib_params.ipv6_dst, &tuple.daddr);

			ret = fib_lookup(ctx, &fib_params, sizeof(fib_params),
					 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
			if (ret != 0)
				return DROP_NO_FIB;

			if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	} else {
		if (!bpf_skip_recirculation(ctx)) {
			bpf_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_LXC);
			return DROP_MISSED_TAIL_CALL;
		}
	}

	return CTX_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_REVNAT)
int tail_rev_nodeport_lb6(struct __ctx_buff *ctx)
{
	int ifindex = 0;
	int ret = 0;
#if defined(ENABLE_HOST_FIREWALL) && defined(IS_BPF_HOST)
	/* We only enforce the host policies if nodeport.h is included from
	 * bpf_host.
	 */
	__u32 src_id = 0;

	ret = ipv6_host_policy_ingress(ctx, &src_id);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, src_id, ret, CTX_ACT_DROP,
					      METRIC_INGRESS);
	/* We don't want to enforce host policies a second time if we jump back to
	 * bpf_host's handle_ipv6.
	 */
	ctx_skip_host_fw_set(ctx);
#endif
	ret = rev_nodeport_lb6(ctx, &ifindex);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
	edt_set_aggregate(ctx, 0);
	return ctx_redirect(ctx, ifindex, 0);
}

declare_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
			       is_defined(ENABLE_IPV6)),
			 __and(is_defined(ENABLE_HOST_FIREWALL),
			       is_defined(IS_BPF_HOST))),
		    CILIUM_CALL_IPV6_ENCAP_NODEPORT_NAT)
int tail_handle_nat_fwd_ipv6(struct __ctx_buff *ctx)
{
	union v6addr addr = { .p1 = 0 };
#if defined(ENCAP_IFINDEX) && defined(IS_BPF_OVERLAY)
	BPF_V6(addr, ROUTER_IP);
#else
	BPF_V6_NODEPORT(addr);
#endif
	return nodeport_nat_ipv6_fwd(ctx, &addr);
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline bool nodeport_uses_dsr4(const struct ipv4_ct_tuple *tuple)
{
	return nodeport_uses_dsr(tuple->nexthdr);
}

/* Returns true if the packet must be SNAT-ed. In addition, sets "addr" to
 * SNAT IP addr, and if a packet is sent from an endpoint, sets "from_endpoint"
 * to true.
 */
static __always_inline bool snat_v4_needed(struct __ctx_buff *ctx, __be32 *addr,
					   bool *from_endpoint __maybe_unused)
{
	struct endpoint_info *ep __maybe_unused;
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return false;

	/* Basic minimum is to only NAT when there is a potential of
	 * overlapping tuples, e.g. applications in hostns reusing
	 * source IPs we SNAT in NodePort and BPF-masq.
	 */
#if defined(ENCAP_IFINDEX) && defined(IS_BPF_OVERLAY)
	if (ip4->saddr == IPV4_GATEWAY) {
		*addr = IPV4_GATEWAY;
		return true;
	}
#else
	if (ip4->saddr == IPV4_NODEPORT) {
		*addr = IPV4_NODEPORT;
		return true;
	}
# ifdef ENABLE_MASQUERADE
	if (ip4->saddr == IPV4_MASQUERADE) {
		*addr = IPV4_MASQUERADE;
		return true;
	}
# endif
#endif /* defined(ENCAP_IFINDEX) && defined(IS_BPF_OVERLAY) */


#ifdef ENABLE_MASQUERADE /* SNAT local pod to world packets */
# ifdef IS_BPF_OVERLAY
	/* Do not MASQ when this function is executed from bpf_overlay
	 * (IS_BPF_OVERLAY denotes this fact). Otherwise, a packet will
	 * be SNAT'd to cilium_host IP addr.
	 */
	return false;
# endif
#ifdef IPV4_SNAT_EXCLUSION_DST_CIDR
	/* Do not MASQ if a dst IP belongs to a pods CIDR
	 * (native-routing-cidr if specified, otherwise local pod CIDR).
	 * The check is performed before we determine that a packet is
	 * sent from a local pod, as this check is cheaper than
	 * the map lookup done in the latter check.
	 */
	if (ipv4_is_in_subnet(ip4->daddr, IPV4_SNAT_EXCLUSION_DST_CIDR,
			      IPV4_SNAT_EXCLUSION_DST_CIDR_LEN))
		return false;
#endif

	ep = __lookup_ip4_endpoint(ip4->saddr);
	if (ep && !(ep->flags & ENDPOINT_F_HOST)) {
		struct remote_endpoint_info *info;
		*from_endpoint = true;

		info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr,
				       V4_CACHE_KEY_LEN);
		if (info) {
#ifdef ENABLE_IP_MASQ_AGENT
			/* Do not SNAT if dst belongs to any ip-masq-agent
			 * subnet.
			 */
			struct lpm_v4_key pfx;

			pfx.lpm.prefixlen = 32;
			memcpy(pfx.lpm.data, &ip4->daddr, sizeof(pfx.addr));
			if (map_lookup_elem(&IP_MASQ_AGENT_IPV4, &pfx))
				return false;
#endif
#ifndef ENCAP_IFINDEX
			/* In the tunnel mode, a packet from a local ep
			 * to a remote node is not encap'd, and is sent
			 * via a native dev. Therefore, such packet has
			 * to be MASQ'd. Otherwise, it might be dropped
			 * either by underlying network (e.g. AWS drops
			 * packets by default from unknown subnets) or
			 * by the remote node if its native dev's
			 * rp_filter=1.
			 */
			if (info->sec_label == REMOTE_NODE_ID)
				return false;
#endif

			*addr = IPV4_MASQUERADE;
			return true;
		}
	}
#endif /*ENABLE_MASQUERADE */

	return false;
}

static __always_inline int nodeport_nat_ipv4_fwd(struct __ctx_buff *ctx)
{
	bool from_endpoint = false;
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.addr = 0,
	};
	int ret = CTX_ACT_OK;

	if (snat_v4_needed(ctx, &target.addr, &from_endpoint))
		ret = snat_v4_process(ctx, NAT_DIR_EGRESS, &target,
				      from_endpoint);
	if (ret == NAT_PUNT_TO_STACK)
		ret = CTX_ACT_OK;

	return ret;
}

#ifdef ENABLE_DSR
#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
static __always_inline __be32 rss_gen_src4(__be32 client, __be32 l4_hint)
{
	const __u32 bits = 32 - IPV4_RSS_PREFIX_BITS;
	__be32 src = IPV4_RSS_PREFIX;

	if (bits)
		src |= bpf_htonl(hash_32(client ^ l4_hint, bits));
	return src;
}

/*
 * Original packet: [clientIP:clientPort -> serviceIP:servicePort] } IP/L4
 *
 * After DSR IPIP:  [rssSrcIP -> backendIP]                        } IP
 *                  [clientIP:clientPort -> serviceIP:servicePort] } IP/L4
 */
static __always_inline int dsr_set_ipip4(struct __ctx_buff *ctx,
					 const struct iphdr *ip4,
					 __be32 backend_addr,
					 __be32 l4_hint)
{
	const int l3_off = ETH_HLEN;
	__be32 sum;
	struct {
		__be16 tot_len;
		__be16 id;
		__be16 frag_off;
		__u8   ttl;
		__u8   protocol;
		__be32 saddr;
		__be32 daddr;
	} tp_old = {
		.tot_len	= ip4->tot_len,
		.ttl		= ip4->ttl,
		.protocol	= ip4->protocol,
		.saddr		= ip4->saddr,
		.daddr		= ip4->daddr,
	}, tp_new = {
		.tot_len	= bpf_htons(bpf_ntohs(tp_old.tot_len) +
					    sizeof(*ip4)),
		.ttl		= 64,
		.protocol	= IPPROTO_IPIP,
		.saddr		= rss_gen_src4(ip4->saddr, l4_hint),
		.daddr		= backend_addr,
	};

	if (ctx_adjust_room(ctx, sizeof(*ip4), BPF_ADJ_ROOM_NET,
			    ctx_adjust_room_dsr_flags()))
		return DROP_INVALID;
	sum = csum_diff(&tp_old, 16, &tp_new, 16, 0);
	if (ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, tot_len),
			    &tp_new.tot_len, 2, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, ttl),
			    &tp_new.ttl, 2, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, saddr),
			    &tp_new.saddr, 8, 0) < 0)
		return DROP_WRITE_ERROR;
	if (l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	return 0;
}
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
static __always_inline int dsr_set_opt4(struct __ctx_buff *ctx,
					struct iphdr *ip4,
					__be32 svc_addr, __be32 svc_port)
{
	__u32 iph_old, iph_new, opt[2];
	__be32 sum;

	if (ip4->protocol == IPPROTO_TCP) {
		union tcp_flags tcp_flags = { .value = 0 };

		if (ctx_load_bytes(ctx, ETH_HLEN + sizeof(*ip4) + 12,
				   &tcp_flags, 2) < 0)
			return DROP_CT_INVALID_HDR;

		/* Setting the option is required only for the first packet
		 * (SYN), in the case of TCP, as for further packets of the
		 * same connection a remote node will use a NAT entry to
		 * reverse xlate a reply.
		 */
		if (!(tcp_flags.value & (TCP_FLAG_SYN)))
			return 0;
	}

	iph_old = *(__u32 *)ip4;
	ip4->ihl += 0x2; /* To accommodate u64 option. */
	ip4->tot_len = bpf_htons(bpf_ntohs(ip4->tot_len) + 0x8);
	iph_new = *(__u32 *)ip4;

	opt[0] = bpf_htonl(DSR_IPV4_OPT_32 | svc_port);
	opt[1] = bpf_htonl(svc_addr);

	sum = csum_diff(&iph_old, 4, &iph_new, 4, 0);
	sum = csum_diff(NULL, 0, &opt, sizeof(opt), sum);

	if (ctx_adjust_room(ctx, 0x8, BPF_ADJ_ROOM_NET,
			    ctx_adjust_room_dsr_flags()))
		return DROP_INVALID;

	if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(*ip4),
			    &opt, sizeof(opt), 0) < 0)
		return DROP_INVALID;
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;

	return 0;
}
#endif /* DSR_ENCAP_MODE */

static __always_inline int handle_dsr_v4(struct __ctx_buff *ctx, bool *dsr)
{
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* Check whether IPv4 header contains a 64-bit option (IPv4 header
	 * w/o option (5 x 32-bit words) + the DSR option (2 x 32-bit words)).
	 */
	if (ip4->ihl == 0x7) {
		__u32 opt1 = 0, opt2 = 0;
		__be32 address, dport;

		if (ctx_load_bytes(ctx, ETH_HLEN + sizeof(struct iphdr),
				   &opt1, sizeof(opt1)) < 0)
			return DROP_INVALID;

		opt1 = bpf_ntohl(opt1);
		if ((opt1 & DSR_IPV4_OPT_MASK) == DSR_IPV4_OPT_32) {
			if (ctx_load_bytes(ctx, ETH_HLEN +
					   sizeof(struct iphdr) +
					   sizeof(opt1),
					   &opt2, sizeof(opt2)) < 0)
				return DROP_INVALID;

			opt2 = bpf_ntohl(opt2);
			dport = opt1 & DSR_IPV4_DPORT_MASK;
			address = opt2;
			*dsr = true;

			if (snat_v4_create_dsr(ctx, address, dport) < 0)
				return DROP_INVALID;
		}
	}

	return 0;
}

static __always_inline int xlate_dsr_v4(struct __ctx_buff *ctx,
					const struct ipv4_ct_tuple *tuple,
					int l4_off, bool has_l4_header)
{
	struct ipv4_ct_tuple nat_tup = *tuple;
	struct ipv4_nat_entry *entry;
	int ret = 0;

	nat_tup.flags = NAT_DIR_EGRESS;
	nat_tup.sport = tuple->dport;
	nat_tup.dport = tuple->sport;

	entry = snat_v4_lookup(&nat_tup);
	if (entry)
		ret = snat_v4_rewrite_egress(ctx, &nat_tup, entry, l4_off, has_l4_header);
	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_DSR)
int tail_nodeport_ipv4_dsr(struct __ctx_buff *ctx)
{
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET,
			.ifindex	= DIRECT_ROUTING_DEV_IFINDEX,
		},
	};
	union macaddr *dmac = NULL;
	void *data, *data_end;
	struct iphdr *ip4;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	ret = dsr_set_ipip4(ctx, ip4,
			    ctx_load_meta(ctx, CB_ADDR_V4),
			    ctx_load_meta(ctx, CB_HINT));
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
	ret = dsr_set_opt4(ctx, ip4,
			   ctx_load_meta(ctx, CB_ADDR_V4),
			   ctx_load_meta(ctx, CB_PORT));
#else
# error "Invalid load balancer DSR encapsulation mode!"
#endif
	if (ret)
		return ret;
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	if (nodeport_lb_hairpin())
		dmac = map_lookup_elem(&NODEPORT_NEIGH4, &ip4->daddr);
	if (dmac) {
		union macaddr mac = NATIVE_DEV_MAC_BY_IFINDEX(fib_params.l.ifindex);

		if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
			return DROP_WRITE_ERROR;
		if (eth_store_saddr_aligned(ctx, mac.addr, 0) < 0)
			return DROP_WRITE_ERROR;
	} else {
		fib_params.l.ipv4_src = ip4->saddr;
		fib_params.l.ipv4_dst = ip4->daddr;

		ret = fib_lookup(ctx, &fib_params.l, sizeof(fib_params),
				 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
		if (ret != 0)
			return DROP_NO_FIB;
		if (nodeport_lb_hairpin())
			map_update_elem(&NODEPORT_NEIGH4, &ip4->daddr,
					fib_params.l.dmac, 0);
		if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0)
			return DROP_WRITE_ERROR;
		if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0)
			return DROP_WRITE_ERROR;
	}

	return ctx_redirect(ctx, fib_params.l.ifindex, 0);
}
#endif /* ENABLE_DSR */

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_NAT)
int tail_nodeport_nat_ipv4(struct __ctx_buff *ctx)
{
	int ret, dir = ctx_load_meta(ctx, CB_NAT);
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET,
			.ifindex	= DIRECT_ROUTING_DEV_IFINDEX,
		},
	};
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.src_from_world = true,
	};
	union macaddr *dmac = NULL;
	void *data, *data_end;
	struct iphdr *ip4;

	target.addr = IPV4_DIRECT_ROUTING;
#ifdef ENCAP_IFINDEX
	if (dir == NAT_DIR_EGRESS) {
		struct remote_endpoint_info *info;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
		if (info != NULL && info->tunnel_endpoint != 0) {
			ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
						  SECLABEL, TRACE_PAYLOAD_LEN);
			if (ret)
				return ret;

			target.addr = IPV4_GATEWAY;
			fib_params.l.ifindex = ENCAP_IFINDEX;

			/* fib lookup not necessary when going over tunnel. */
			if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	}
#endif
	ret = snat_v4_process(ctx, dir, &target, false);
	if (IS_ERR(ret)) {
		/* In case of no mapping, recircle back to main path. SNAT is very
		 * expensive in terms of instructions (since we don't have BPF to
		 * BPF calls as we use tail calls) and complexity, hence this is
		 * done inside a tail call here.
		 */
		if (dir == NAT_DIR_INGRESS) {
			bpf_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_LXC);
			ret = DROP_MISSED_TAIL_CALL;
			goto drop_err;
		}
		if (ret != NAT_PUNT_TO_STACK)
			goto drop_err;
	}

	bpf_mark_snat_done(ctx);

	if (dir == NAT_DIR_INGRESS) {
		ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_REVNAT);
		ret = DROP_MISSED_TAIL_CALL;
		goto drop_err;
	}
#ifdef ENCAP_IFINDEX
	if (fib_params.l.ifindex == ENCAP_IFINDEX)
		goto out_send;
#endif
	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	if (nodeport_lb_hairpin())
		dmac = map_lookup_elem(&NODEPORT_NEIGH4, &ip4->daddr);
	if (dmac) {
		union macaddr mac = NATIVE_DEV_MAC_BY_IFINDEX(fib_params.l.ifindex);

		if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0) {
			ret = DROP_WRITE_ERROR;
			goto drop_err;
		}
		if (eth_store_saddr_aligned(ctx, mac.addr, 0) < 0) {
			ret = DROP_WRITE_ERROR;
			goto drop_err;
		}
	} else {
		fib_params.l.ipv4_src = ip4->saddr;
		fib_params.l.ipv4_dst = ip4->daddr;

		ret = fib_lookup(ctx, &fib_params.l, sizeof(fib_params),
				 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
		if (ret != 0) {
			ret = DROP_NO_FIB;
			goto drop_err;
		}
		if (nodeport_lb_hairpin())
			map_update_elem(&NODEPORT_NEIGH4, &ip4->daddr,
					fib_params.l.dmac, 0);

		if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
			ret = DROP_WRITE_ERROR;
			goto drop_err;
		}
		if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
			ret = DROP_WRITE_ERROR;
			goto drop_err;
		}
	}
out_send: __maybe_unused
	return ctx_redirect(ctx, fib_params.l.ifindex, 0);
drop_err:
	return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
				      dir == NAT_DIR_INGRESS ?
				      METRIC_INGRESS : METRIC_EGRESS);
}

/* Main node-port entry point for host-external ingressing node-port traffic
 * which handles the case of: i) backend is local EP, ii) backend is remote EP,
 * iii) reply from remote backend EP.
 */
static __always_inline int nodeport_lb4(struct __ctx_buff *ctx,
					__u32 src_identity)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	int ret,  l3_off = ETH_HLEN, l4_off;
	struct csum_offset csum_off = {};
	struct lb4_service *svc;
	struct lb4_key key = {};
	struct ct_state ct_state_new = {};
	union macaddr smac, *mac;
	bool backend_local;
	__u32 monitor = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);

	ret = lb4_extract_key(ctx, ip4, l4_off, &key, &csum_off, CT_EGRESS);
	if (IS_ERR(ret)) {
		if (ret == DROP_NO_SERVICE)
			goto skip_service_lookup;
		else if (ret == DROP_UNKNOWN_L4)
			return CTX_ACT_OK;
		else
			return ret;
	}

	svc = lb4_lookup_service(&key, false);
	if (svc) {
		const bool skip_xlate = DSR_ENCAP_MODE == DSR_ENCAP_IPIP;

		if (!lb4_src_range_ok(svc, ip4->saddr))
			return DROP_NOT_IN_SRC_RANGE;

		ret = lb4_local(get_ct_map4(&tuple), ctx, l3_off, l4_off,
				&csum_off, &key, &tuple, svc, &ct_state_new,
				ip4->saddr, ipv4_has_l4_header(ip4), skip_xlate);
		if (IS_ERR(ret))
			return ret;
	}

	if (!svc || !lb4_svc_is_routable(svc)) {
		if (svc)
			return DROP_IS_CLUSTER_IP;

skip_service_lookup:
		ctx_set_xfer(ctx, XFER_PKT_NO_SVC);

#ifndef ENABLE_MASQUERADE
		if (nodeport_uses_dsr4(&tuple))
			return CTX_ACT_OK;
#endif

		ctx_store_meta(ctx, CB_NAT, NAT_DIR_INGRESS);
		ctx_store_meta(ctx, CB_SRC_IDENTITY, src_identity);
		ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_NAT);
		return DROP_MISSED_TAIL_CALL;
	}

	backend_local = __lookup_ip4_endpoint(tuple.daddr);
	if (!backend_local && lb4_svc_is_hostport(svc))
		return DROP_INVALID;

	/* Reply from DSR packet is never seen on this node again hence no
	 * need to track in here.
	 */
	if (backend_local || !nodeport_uses_dsr4(&tuple)) {
		struct ct_state ct_state = {};

		ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off,
				 CT_EGRESS, &ct_state, &monitor);
		switch (ret) {
		case CT_NEW:
redo_all:
			ct_state_new.src_sec_id = SECLABEL;
			ct_state_new.node_port = 1;
			ct_state_new.ifindex = NATIVE_DEV_IFINDEX;
			ret = ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx,
					 CT_EGRESS, &ct_state_new, false);
			if (IS_ERR(ret))
				return ret;
			if (backend_local) {
				ct_flip_tuple_dir4(&tuple);
redo_local:
				/* Reset rev_nat_index, otherwise ipv4_policy()
				 * in bpf_lxc will do invalid xlation.
				 */
				ct_state_new.rev_nat_index = 0;
				ret = ct_create4(get_ct_map4(&tuple), NULL,
						 &tuple, ctx, CT_INGRESS,
						 &ct_state_new, false);
				if (IS_ERR(ret))
					return ret;
			}
			break;
		case CT_REOPENED:
		case CT_ESTABLISHED:
		case CT_REPLY:
			/* Recreate CT entries, as the existing one is stale and
			 * belongs to a flow which target a different svc.
			 */
			if (unlikely(ct_state.rev_nat_index !=
				     svc->rev_nat_index))
				goto redo_all;
			if (backend_local) {
				ct_flip_tuple_dir4(&tuple);
				if (!__ct_entry_keep_alive(get_ct_map4(&tuple),
							   &tuple)) {
					ct_state_new.src_sec_id = SECLABEL;
					ct_state_new.node_port = 1;
					ct_state_new.ifindex = NATIVE_DEV_IFINDEX;
					goto redo_local;
				}
			}
			break;
		default:
			return DROP_UNKNOWN_CT;
		}

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		if (eth_load_saddr(ctx, smac.addr, 0) < 0)
			return DROP_INVALID;

		mac = map_lookup_elem(&NODEPORT_NEIGH4, &ip4->saddr);
		if (!mac || eth_addrcmp(mac, &smac)) {
			ret = map_update_elem(&NODEPORT_NEIGH4, &ip4->saddr,
					      &smac, 0);
			if (ret < 0)
				return ret;
		}
	}

	if (!backend_local) {
		edt_set_aggregate(ctx, 0);
		if (nodeport_uses_dsr4(&tuple)) {
#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
			ctx_store_meta(ctx, CB_HINT,
				       ((__u32)tuple.sport << 16) | tuple.dport);
			ctx_store_meta(ctx, CB_ADDR_V4, tuple.daddr);
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
			ctx_store_meta(ctx, CB_PORT, key.dport);
			ctx_store_meta(ctx, CB_ADDR_V4, key.address);
#endif /* DSR_ENCAP_MODE */
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_DSR);
		} else {
			ctx_store_meta(ctx, CB_NAT, NAT_DIR_EGRESS);
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_NAT);
		}
		return DROP_MISSED_TAIL_CALL;
	}

	ctx_set_xfer(ctx, XFER_PKT_NO_SVC);

	return CTX_ACT_OK;
}

/* Reverse NAT handling of node-port traffic for the case where the
 * backend i) was a local EP and bpf_lxc redirected to us, ii) was
 * a remote backend and we got here after reverse SNAT from the
 * tail_nodeport_nat_ipv4().
 *
 * CILIUM_CALL_IPV{4,6}_NODEPORT_REVNAT is plugged into CILIUM_MAP_CALLS
 * of the bpf_host, bpf_overlay and of the bpf_lxc.
 */
static __always_inline int rev_nodeport_lb4(struct __ctx_buff *ctx, int *ifindex)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct csum_offset csum_off = {};
	int ret, ret2, l3_off = ETH_HLEN, l4_off;
	struct ct_state ct_state = {};
	struct bpf_fib_lookup fib_params = {};
	union macaddr *dmac;
	__u32 monitor = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_INGRESS, &ct_state,
			 &monitor);

	if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {
		ret2 = lb4_rev_nat(ctx, l3_off, l4_off, &csum_off,
				   &ct_state, &tuple,
				   REV_NAT_F_TUPLE_SADDR, ipv4_has_l4_header(ip4));
		if (IS_ERR(ret2))
			return ret2;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		bpf_mark_snat_done(ctx);

		*ifindex = ct_state.ifindex;
#ifdef ENCAP_IFINDEX
		{
			struct remote_endpoint_info *info;

			info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
			if (info != NULL && info->tunnel_endpoint != 0) {
				ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
							  SECLABEL, TRACE_PAYLOAD_LEN);
				if (ret)
					return ret;

				*ifindex = ENCAP_IFINDEX;

				/* fib lookup not necessary when going over tunnel. */
				if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
					return DROP_WRITE_ERROR;
				if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
					return DROP_WRITE_ERROR;

				return CTX_ACT_OK;
			}
		}
#endif

		dmac = map_lookup_elem(&NODEPORT_NEIGH4, &ip4->daddr);
		if (dmac) {
			union macaddr mac = NATIVE_DEV_MAC_BY_IFINDEX(*ifindex);

			if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr_aligned(ctx, mac.addr, 0) < 0)
				return DROP_WRITE_ERROR;
		} else {
			fib_params.family = AF_INET;
			fib_params.ifindex = *ifindex;

			fib_params.ipv4_src = ip4->saddr;
			fib_params.ipv4_dst = ip4->daddr;

			ret = fib_lookup(ctx, &fib_params, sizeof(fib_params),
					 BPF_FIB_LOOKUP_DIRECT |
					 BPF_FIB_LOOKUP_OUTPUT);
			if (ret != 0)
				return DROP_NO_FIB;

			if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	} else {
		if (!bpf_skip_recirculation(ctx)) {
			bpf_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_LXC);
			return DROP_MISSED_TAIL_CALL;
		}
	}

	return CTX_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_REVNAT)
int tail_rev_nodeport_lb4(struct __ctx_buff *ctx)
{
	int ifindex = 0;
	int ret = 0;
#if defined(ENABLE_HOST_FIREWALL) && defined(IS_BPF_HOST)
	/* We only enforce the host policies if nodeport.h is included from
	 * bpf_host.
	 */
	__u32 src_id = 0;

	ret = ipv4_host_policy_ingress(ctx, &src_id);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, src_id, ret, CTX_ACT_DROP,
					      METRIC_INGRESS);
	/* We don't want to enforce host policies a second time if we jump back to
	 * bpf_host's handle_ipv6.
	 */
	ctx_skip_host_fw_set(ctx);
#endif
	ret = rev_nodeport_lb4(ctx, &ifindex);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
	edt_set_aggregate(ctx, 0);
	return ctx_redirect(ctx, ifindex, 0);
}

declare_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
			       is_defined(ENABLE_IPV6)),
			 __and(is_defined(ENABLE_HOST_FIREWALL),
			       is_defined(IS_BPF_HOST))),
		    CILIUM_CALL_IPV4_ENCAP_NODEPORT_NAT)
int tail_handle_nat_fwd_ipv4(struct __ctx_buff *ctx)
{
	return nodeport_nat_ipv4_fwd(ctx);
}
#endif /* ENABLE_IPV4 */

static __always_inline int nodeport_nat_fwd(struct __ctx_buff *ctx)
{
	int ret = CTX_ACT_OK;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
					      is_defined(ENABLE_IPV6)),
					__and(is_defined(ENABLE_HOST_FIREWALL),
					      is_defined(IS_BPF_HOST))),
				   CILIUM_CALL_IPV4_ENCAP_NODEPORT_NAT,
				   tail_handle_nat_fwd_ipv4);
		break;
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
					      is_defined(ENABLE_IPV6)),
					__and(is_defined(ENABLE_HOST_FIREWALL),
					      is_defined(IS_BPF_HOST))),
				   CILIUM_CALL_IPV6_ENCAP_NODEPORT_NAT,
				   tail_handle_nat_fwd_ipv6);
		break;
#endif /* ENABLE_IPV6 */
	default:
		build_bug_on(!(NODEPORT_PORT_MIN_NAT < NODEPORT_PORT_MAX_NAT));
		build_bug_on(!(NODEPORT_PORT_MIN     < NODEPORT_PORT_MAX));
		build_bug_on(!(NODEPORT_PORT_MAX     < NODEPORT_PORT_MIN_NAT));
		break;
	}
	return ret;
}

#endif /* ENABLE_NODEPORT */
#endif /* __NODEPORT_H_ */
