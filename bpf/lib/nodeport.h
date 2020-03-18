/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019-2020 Authors of Cilium */

#ifndef __NODEPORT_H_
#define __NODEPORT_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "nat.h"
#include "lb.h"
#include "common.h"
#include "overloadable.h"
#include "conntrack.h"
#include "csum.h"
#include "encap.h"
#include "trace.h"

#define CB_SRC_IDENTITY	0

/* No nodeport on cilium_host interface. */
#ifdef FROM_HOST
# undef ENABLE_NODEPORT
# undef ENABLE_MASQUERADE
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
	.size_key	= sizeof(__be32),		// ipv4 addr
	.size_value	= sizeof(union macaddr),	// hw addr
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= SNAT_MAPPING_IPV4_SIZE,
};
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
struct bpf_elf_map __section_maps NODEPORT_NEIGH6 = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.size_key	= sizeof(union v6addr),		// ipv6 addr
	.size_value	= sizeof(union macaddr),	// hw addr
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= SNAT_MAPPING_IPV6_SIZE,
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

static __always_inline bool nodeport_uses_dsr(__u8 nexthdr)
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

static __always_inline void bpf_mark_snat_done(struct __ctx_buff *ctx)
{
	/* From XDP layer, we do not go through an egress hook from
	 * here, hence nothing to be done.
	 */
#if __ctx_is == __ctx_skb
	ctx->mark |= MARK_MAGIC_SNAT_DONE;
#endif
}

static __always_inline bool bpf_skip_recirculation(struct __ctx_buff *ctx)
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

#ifdef ENABLE_IPV6
static __always_inline bool nodeport_uses_dsr6(const struct ipv6_ct_tuple *tuple)
{
	return nodeport_uses_dsr(tuple->nexthdr);
}

static __always_inline bool nodeport_nat_ipv6_needed(struct __ctx_buff *ctx,
						     union v6addr *addr, int dir)
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
	/* See nodeport_nat_ipv4_needed(). */
	if (dir == NAT_DIR_EGRESS)
		return !ipv6_addrcmp((union v6addr *)&ip6->saddr, addr);
	else
		return !ipv6_addrcmp((union v6addr *)&ip6->daddr, addr);
}

#define NODEPORT_DO_NAT_IPV6(ADDR, NDIR)					\
	({									\
		struct ipv6_nat_target target = {				\
			.min_port = NODEPORT_PORT_MIN_NAT,			\
			.max_port = 65535,					\
		};								\
		ipv6_addr_copy(&target.addr, (ADDR));				\
		int ____ret = nodeport_nat_ipv6_needed(ctx, (ADDR), (NDIR)) ?	\
			      snat_v6_process(ctx, (NDIR), &target) : CTX_ACT_OK;\
		if (____ret == NAT_PUNT_TO_STACK)				\
			____ret = CTX_ACT_OK;					\
		____ret;							\
	})

static __always_inline int nodeport_nat_ipv6_fwd(struct __ctx_buff *ctx,
						 union v6addr *addr)
{
	return NODEPORT_DO_NAT_IPV6(addr, NAT_DIR_EGRESS);
}

static __always_inline int nodeport_nat_ipv6_rev(struct __ctx_buff *ctx,
						 union v6addr *addr)
{
	return NODEPORT_DO_NAT_IPV6(addr, NAT_DIR_INGRESS);
}

# ifdef ENABLE_DSR
static __always_inline int set_dsr_ext6(struct __ctx_buff *ctx,
					struct ipv6hdr *ip6,
					union v6addr *svc_addr, __be32 svc_port)
{
	struct dsr_opt_v6 opt = {};

	opt.nexthdr = ip6->nexthdr;
	ip6->nexthdr = NEXTHDR_DEST;
	ip6->payload_len = bpf_htons(bpf_ntohs(ip6->payload_len) + 24);

	opt.len = DSR_IPV6_EXT_LEN;
	opt.opt_type = DSR_IPV6_OPT_TYPE;
	opt.opt_len = DSR_IPV6_OPT_LEN;
	ipv6_addr_copy(&opt.addr, svc_addr);
	opt.port = svc_port;

	if (ctx_adjust_room(ctx, sizeof(opt), BPF_ADJ_ROOM_NET, 0))
		return DROP_INVALID;

	if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(*ip6), &opt, sizeof(opt), 0) < 0)
		return DROP_INVALID;

	return 0;
}

static __always_inline int find_dsr_v6(struct __ctx_buff *ctx, __u8 nexthdr,
				       struct dsr_opt_v6 *dsr_opt, bool *found)
{
	int i, len = sizeof(struct ipv6hdr);
	struct ipv6_opt_hdr opthdr;
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
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct dsr_opt_v6 opt = {};
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
					struct ipv6_ct_tuple *tuple,
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
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr addr = {};
	struct bpf_fib_lookup fib_params = {};
	__be32 dport;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	dport   = ctx_load_meta(ctx, CB_SVC_PORT);
	addr.p1 = ctx_load_meta(ctx, CB_SVC_ADDR_V6_1);
	addr.p2 = ctx_load_meta(ctx, CB_SVC_ADDR_V6_2);
	addr.p3 = ctx_load_meta(ctx, CB_SVC_ADDR_V6_3);
	addr.p4 = ctx_load_meta(ctx, CB_SVC_ADDR_V6_4);

	ret = set_dsr_ext6(ctx, ip6, &addr, dport);
	if (ret)
		return ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	fib_params.family = AF_INET6;
	fib_params.ifindex = NATIVE_DEV_IFINDEX;
	ipv6_addr_copy((union v6addr *) &fib_params.ipv6_src, (union v6addr *) &ip6->saddr);
	ipv6_addr_copy((union v6addr *) &fib_params.ipv6_dst, (union v6addr *) &ip6->daddr);

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (ret != 0)
		return DROP_NO_FIB;

	if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
		return DROP_WRITE_ERROR;
	if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
		return DROP_WRITE_ERROR;

	return ctx_redirect(ctx, fib_params.ifindex, 0);
}
# endif /* ENABLE_DSR */

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_NAT)
int tail_nodeport_nat_ipv6(struct __ctx_buff *ctx)
{
	int ifindex = NATIVE_DEV_IFINDEX, ret, dir = ctx_load_meta(ctx, CB_NAT);
	struct bpf_fib_lookup fib_params = {};
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.src_from_world = true,
	};
	void *data, *data_end;
	struct ipv6hdr *ip6;

	BPF_V6(target.addr, IPV6_NODEPORT);
#ifdef ENCAP_IFINDEX
	if (dir == NAT_DIR_EGRESS) {
		struct remote_endpoint_info *info;
		union v6addr *dst;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		dst = (union v6addr *)&ip6->daddr;
		info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
		if (info != NULL && info->tunnel_endpoint != 0) {
			int ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
						      SECLABEL, TRACE_PAYLOAD_LEN);
			if (ret)
				return ret;

			BPF_V6(target.addr, ROUTER_IP);
			ifindex = ENCAP_IFINDEX;

			/* fib lookup not necessary when going over tunnel. */
			if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
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
		}
		if (ret == NAT_PUNT_TO_STACK)
			ret = CTX_ACT_OK;
		else
			goto drop_err;
	}

	bpf_mark_snat_done(ctx);

	if (dir == NAT_DIR_INGRESS) {
		ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_REVNAT);
		ret = DROP_MISSED_TAIL_CALL;
		goto drop_err;
	}
#ifdef ENCAP_IFINDEX
	if (ifindex == ENCAP_IFINDEX)
		goto out_send;
#endif
	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	fib_params.family = AF_INET6;
	fib_params.ifindex = ifindex;
	ipv6_addr_copy((union v6addr *) &fib_params.ipv6_src, (union v6addr *) &ip6->saddr);
	ipv6_addr_copy((union v6addr *) &fib_params.ipv6_dst, (union v6addr *) &ip6->daddr);

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (ret != 0) {
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(ctx, fib_params.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	ifindex = fib_params.ifindex;
out_send:
	return ctx_redirect(ctx, ifindex, 0);
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
	struct ct_state ct_state = {};
	bool backend_local;
	__u32 monitor = 0;
	union macaddr smac;

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
		if (ret == DROP_UNKNOWN_L4)
			return CTX_ACT_OK;
		else
			return ret;
	}

	if ((svc = lb6_lookup_service(ctx, &key)) != NULL) {
		ret = lb6_local(get_ct_map6(&tuple), ctx, l3_off, l4_off,
				&csum_off, &key, &tuple, svc, &ct_state_new);
		if (IS_ERR(ret))
			return ret;
	}

	if (!svc || (!lb6_svc_is_external_ip(svc) &&
		     !lb6_svc_is_nodeport(svc)) &&
		     !lb6_svc_is_hostport(svc)) {
		if (svc)
			return DROP_IS_CLUSTER_IP;

		if (nodeport_uses_dsr6(&tuple)) {
			return CTX_ACT_OK;
		} else {
			ctx_store_meta(ctx, CB_NAT, NAT_DIR_INGRESS);
			ctx_store_meta(ctx, CB_SRC_IDENTITY, src_identity);
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT);
			return DROP_MISSED_TAIL_CALL;
		}
	}

	ret = ct_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;
	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	backend_local = lookup_ip6_endpoint(ip6);
	if (lb6_svc_is_hostport(svc) && !backend_local)
		return DROP_INVALID;

	switch (ret) {
	case CT_NEW:
		ct_state_new.src_sec_id = SECLABEL;
		ct_state_new.node_port = 1;
		ret = ct_create6(get_ct_map6(&tuple), &tuple, ctx, CT_EGRESS,
				 &ct_state_new, false);
		if (IS_ERR(ret))
			return ret;
		if (backend_local) {
			ct_flip_tuple_dir6(&tuple);
redo:
			ct_state_new.rev_nat_index = 0;
			ret = ct_create6(get_ct_map6(&tuple), &tuple, ctx,
					 CT_INGRESS, &ct_state_new, false);
			if (IS_ERR(ret))
				return ret;
		}
		break;

	case CT_ESTABLISHED:
	case CT_REPLY:
		if (backend_local) {
			ct_flip_tuple_dir6(&tuple);
			if (!__ct_entry_keep_alive(get_ct_map6(&tuple),
						   &tuple)) {
				ct_state_new.src_sec_id = SECLABEL;
				ct_state_new.node_port = 1;
				goto redo;
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
	ret = map_update_elem(&NODEPORT_NEIGH6, &ip6->saddr, &smac, 0);
	if (ret < 0) {
		return ret;
	}

	if (!backend_local) {
		if (nodeport_uses_dsr6(&tuple)) {
			ctx_store_meta(ctx, CB_SVC_PORT, key.dport);
			ctx_store_meta(ctx, CB_SVC_ADDR_V6_1, key.address.p1);
			ctx_store_meta(ctx, CB_SVC_ADDR_V6_2, key.address.p2);
			ctx_store_meta(ctx, CB_SVC_ADDR_V6_3, key.address.p3);
			ctx_store_meta(ctx, CB_SVC_ADDR_V6_4, key.address.p4);
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_DSR);
		} else {
			ctx_store_meta(ctx, CB_NAT, NAT_DIR_EGRESS);
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT);
		}
		return DROP_MISSED_TAIL_CALL;
	}

	return CTX_ACT_OK;
}

/* See comment in tail_rev_nodeport_lb4(). */
static __always_inline int rev_nodeport_lb6(struct __ctx_buff *ctx, int *ifindex,
					    union macaddr *mac)
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
#ifdef ENCAP_IFINDEX
		{
			union v6addr *dst = (union v6addr *)&ip6->daddr;
			struct remote_endpoint_info *info;

			info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
			if (info != NULL && info->tunnel_endpoint != 0) {
				int ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
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
			if (eth_store_daddr(ctx, dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(ctx, mac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
		} else {
			fib_params.family = AF_INET6;
			fib_params.ifindex = *ifindex;

			ipv6_addr_copy((union v6addr *) &fib_params.ipv6_src, &tuple.saddr);
			ipv6_addr_copy((union v6addr *) &fib_params.ipv6_dst, &tuple.daddr);

			int rc = fib_lookup(ctx, &fib_params, sizeof(fib_params),
					BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
			if (rc != 0)
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
	int ifindex = NATIVE_DEV_IFINDEX;
	union macaddr mac = NATIVE_DEV_MAC;
	int ret = 0;

	ret = rev_nodeport_lb6(ctx, &ifindex, &mac);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
	return ctx_redirect(ctx, ifindex, 0);
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline bool nodeport_uses_dsr4(const struct ipv4_ct_tuple *tuple)
{
	return nodeport_uses_dsr(tuple->nexthdr);
}

static __always_inline bool nodeport_nat_ipv4_needed(struct __ctx_buff *ctx,
						     __be32 addr, int dir)
{
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return false;
#ifdef ENABLE_DSR_HYBRID
	if (nodeport_uses_dsr(ip4->protocol))
		return false;
#endif /* ENABLE_DSR_HYBRID */
	/* Basic minimum is to only NAT when there is a potential of
	 * overlapping tuples, e.g. applications in hostns reusing
	 * source IPs we SNAT in node-port.
	 */
	if (dir == NAT_DIR_EGRESS)
		return ip4->saddr == addr;
	else
		return ip4->daddr == addr;
}

#define NODEPORT_DO_NAT_IPV4(ADDR, NDIR)					\
	({									\
		struct ipv4_nat_target target = {				\
			.min_port = NODEPORT_PORT_MIN_NAT,			\
			.max_port = 65535,					\
			.addr = (ADDR),						\
		};								\
		int ____ret = nodeport_nat_ipv4_needed(ctx, (ADDR), (NDIR)) ?	\
			      snat_v4_process(ctx, (NDIR), &target) : CTX_ACT_OK;\
		if (____ret == NAT_PUNT_TO_STACK)				\
			____ret = CTX_ACT_OK;					\
		____ret;							\
	})

static __always_inline int nodeport_nat_ipv4_fwd(struct __ctx_buff *ctx,
						 const __be32 addr)
{
	return NODEPORT_DO_NAT_IPV4(addr, NAT_DIR_EGRESS);
}

static __always_inline int nodeport_nat_ipv4_rev(struct __ctx_buff *ctx,
						 const __be32 addr)
{
	return NODEPORT_DO_NAT_IPV4(addr, NAT_DIR_INGRESS);
}

# ifdef ENABLE_DSR
/* Helper function to set the IPv4 option for DSR when a backend is remote.
 * NOTE: Revalidate data after calling the function.
 */
static __always_inline int set_dsr_opt4(struct __ctx_buff *ctx,
					struct iphdr *ip4,
					__be32 svc_addr, __be32 svc_port)
{
	union tcp_flags tcp_flags = { .value = 0 };
	__be32 sum;
	__u32 iph_old, iph_new;

	if (ip4->protocol == IPPROTO_TCP) {
		if (ctx_load_bytes(ctx, ETH_HLEN + sizeof(*ip4) + 12,
				   &tcp_flags, 2) < 0)
			return DROP_CT_INVALID_HDR;
		// Setting the option is required only for the first packet
		// (SYN), in the case of TCP, as for further packets of the
		// same connection a remote node will use a NAT entry to
		// reverse xlate a reply.
		if (!(tcp_flags.value & (TCP_FLAG_SYN)))
			return 0;
	}

	iph_old = *(__u32 *)ip4;
	ip4->ihl += 0x2; // To accommodate u64 option
	ip4->tot_len = bpf_htons(bpf_ntohs(ip4->tot_len) + 0x8);
	iph_new = *(__u32 *)ip4;
	__u32 opt1 = bpf_htonl(DSR_IPV4_OPT_32 | svc_port);
	__u32 opt2 = bpf_htonl(svc_addr);

	sum = csum_diff(&iph_old, 4, &iph_new, 4, 0);
	sum = csum_diff(NULL, 0, &opt1, sizeof(opt1), sum);
	sum = csum_diff(NULL, 0, &opt2, sizeof(opt2), sum);

	if (ctx_adjust_room(ctx, 0x8, BPF_ADJ_ROOM_NET, 0))
		return DROP_INVALID;

	if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(*ip4),
			    &opt1, sizeof(opt1), 0) < 0)
		return DROP_INVALID;
	if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(*ip4) + sizeof(opt1),
			    &opt2, sizeof(opt2), 0) < 0)
		return DROP_INVALID;

	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
	    0, sum, 0) < 0) {
		return DROP_CSUM_L3;
	}

	return 0;
}

static __always_inline int handle_dsr_v4(struct __ctx_buff *ctx, bool *dsr)
{
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	// Check whether IPv4 header contains a 64-bit option (IPv4 header
	// w/o option (5 x 32-bit words) + the DSR option (2 x 32-bit words))
	if (ip4->ihl == 0x7) {
		__u32 opt1 = 0;
		__u32 opt2 = 0;

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

			__be32 dport = opt1 & DSR_IPV4_DPORT_MASK;
			__be32 address = opt2;
			*dsr = true;

			if (snat_v4_create_dsr(ctx, address, dport) < 0)
				return DROP_INVALID;
		}
	}

	return 0;
}

static __always_inline int xlate_dsr_v4(struct __ctx_buff *ctx,
					struct ipv4_ct_tuple *tuple,
					int l4_off)
{
	struct ipv4_ct_tuple nat_tup = *tuple;
	struct ipv4_nat_entry *entry;
	int ret = 0;

	nat_tup.flags = NAT_DIR_EGRESS;
	nat_tup.sport = tuple->dport;
	nat_tup.dport = tuple->sport;

	entry = snat_v4_lookup(&nat_tup);
	if (entry)
		ret = snat_v4_rewrite_egress(ctx, &nat_tup, entry, l4_off);
	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_DSR)
int tail_nodeport_ipv4_dsr(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct bpf_fib_lookup fib_params = {};
	__be32 address;
	__be16 dport;
	int ret;

	address = ctx_load_meta(ctx, CB_SVC_ADDR_V4);
	dport = ctx_load_meta(ctx, CB_SVC_PORT);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	ret = set_dsr_opt4(ctx, ip4, address, dport);
	if (ret != 0)
		return DROP_INVALID;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	fib_params.family = AF_INET;
	fib_params.ifindex = NATIVE_DEV_IFINDEX;
	fib_params.ipv4_src = ip4->saddr;
	fib_params.ipv4_dst = ip4->daddr;

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (ret != 0)
		return DROP_NO_FIB;

	if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
		return DROP_WRITE_ERROR;
	if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
		return DROP_WRITE_ERROR;

	return ctx_redirect(ctx, fib_params.ifindex, 0);
}
# endif /* ENABLE_DSR */

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_NAT)
int tail_nodeport_nat_ipv4(struct __ctx_buff *ctx)
{
	int ifindex = NATIVE_DEV_IFINDEX, ret, dir = ctx_load_meta(ctx, CB_NAT);
	struct bpf_fib_lookup fib_params = {};
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.src_from_world = true,
	};
	void *data, *data_end;
	struct iphdr *ip4;

	target.addr = IPV4_NODEPORT;
#ifdef ENCAP_IFINDEX
	if (dir == NAT_DIR_EGRESS) {
		struct remote_endpoint_info *info;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
		if (info != NULL && info->tunnel_endpoint != 0) {
			int ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
						      SECLABEL, TRACE_PAYLOAD_LEN);
			if (ret)
				return ret;

			target.addr = IPV4_GATEWAY;
			ifindex = ENCAP_IFINDEX;

			/* fib lookup not necessary when going over tunnel. */
			if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	}
#endif
	ret = snat_v4_process(ctx, dir, &target);
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
		}
		if (ret == NAT_PUNT_TO_STACK)
			ret = CTX_ACT_OK;
		else
			goto drop_err;
	}

	bpf_mark_snat_done(ctx);

	if (dir == NAT_DIR_INGRESS) {
		ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_REVNAT);
		ret = DROP_MISSED_TAIL_CALL;
		goto drop_err;
	}
#ifdef ENCAP_IFINDEX
	if (ifindex == ENCAP_IFINDEX)
		goto out_send;
#endif

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	fib_params.family = AF_INET;
	fib_params.ifindex = ifindex;
	fib_params.ipv4_src = ip4->saddr;
	fib_params.ipv4_dst = ip4->daddr;

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (ret != 0) {
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(ctx, fib_params.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	ifindex = fib_params.ifindex;
out_send:
	return ctx_redirect(ctx, ifindex, 0);
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
	struct ct_state ct_state = {};
	bool backend_local;
	__u32 monitor = 0;
	union macaddr smac;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);

	ret = lb4_extract_key(ctx, &tuple, l4_off, &key, &csum_off, CT_EGRESS);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNKNOWN_L4)
			return CTX_ACT_OK;
		else
			return ret;
	}

	if ((svc = lb4_lookup_service(ctx, &key)) != NULL) {
		ret = lb4_local(get_ct_map4(&tuple), ctx, l3_off, l4_off, &csum_off,
				&key, &tuple, svc, &ct_state_new, ip4->saddr);
		if (IS_ERR(ret))
			return ret;
	}

	if (!svc || (!lb4_svc_is_external_ip(svc) &&
		     !lb4_svc_is_nodeport(svc)) &&
		     !lb4_svc_is_hostport(svc)) {
		if (svc)
			return DROP_IS_CLUSTER_IP;

		if (nodeport_uses_dsr4(&tuple)) {
			return CTX_ACT_OK;
		} else {
			ctx_store_meta(ctx, CB_NAT, NAT_DIR_INGRESS);
			ctx_store_meta(ctx, CB_SRC_IDENTITY, src_identity);
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_NAT);
			return DROP_MISSED_TAIL_CALL;
		}
	}

	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	backend_local = lookup_ip4_endpoint(ip4);
	if (lb4_svc_is_hostport(svc) && !backend_local)
		return DROP_INVALID;

	switch (ret) {
	case CT_NEW:
		ct_state_new.src_sec_id = SECLABEL;
		ct_state_new.node_port = 1;
		ret = ct_create4(get_ct_map4(&tuple), &tuple, ctx, CT_EGRESS,
				 &ct_state_new, false);
		if (IS_ERR(ret))
			return ret;
		if (backend_local) {
			ct_flip_tuple_dir4(&tuple);
redo:
			ct_state_new.rev_nat_index = 0;
			ret = ct_create4(get_ct_map4(&tuple), &tuple, ctx,
					 CT_INGRESS, &ct_state_new, false);
			if (IS_ERR(ret))
				return ret;
		}
		break;

	case CT_ESTABLISHED:
	case CT_REPLY:
		if (backend_local) {
			ct_flip_tuple_dir4(&tuple);
			if (!__ct_entry_keep_alive(get_ct_map4(&tuple),
						   &tuple)) {
				ct_state_new.src_sec_id = SECLABEL;
				ct_state_new.node_port = 1;
				goto redo;
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
	ret = map_update_elem(&NODEPORT_NEIGH4, &ip4->saddr, &smac, 0);
	if (ret < 0) {
		return ret;
	}

	if (!backend_local) {
		if (nodeport_uses_dsr4(&tuple)) {
			ctx_store_meta(ctx, CB_SVC_PORT, key.dport);
			ctx_store_meta(ctx, CB_SVC_ADDR_V4, key.address);
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_DSR);
		} else {
			ctx_store_meta(ctx, CB_NAT, NAT_DIR_EGRESS);
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_NAT);
		}
		return DROP_MISSED_TAIL_CALL;
	}

	return CTX_ACT_OK;
}

/* Reverse NAT handling of node-port traffic for the case where the
 * backend i) was a local EP and bpf_lxc redirected to us, ii) was
 * a remote backend and we got here after reverse SNAT from the
 * tail_nodeport_nat_ipv4().
 *
 * CILIUM_CALL_IPV{4,6}_NODEPORT_REVNAT is plugged into CILIUM_MAP_CALLS
 * of the bpf_netdev, bpf_overlay and of the bpf_lxc.
 */
static __always_inline int rev_nodeport_lb4(struct __ctx_buff *ctx, int *ifindex,
					    union macaddr *mac)
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
				   REV_NAT_F_TUPLE_SADDR);
		if (IS_ERR(ret2))
			return ret2;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		bpf_mark_snat_done(ctx);
#ifdef ENCAP_IFINDEX
		{
			struct remote_endpoint_info *info;

			info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
			if (info != NULL && info->tunnel_endpoint != 0) {
				int ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
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
		    if (eth_store_daddr(ctx, dmac->addr, 0) < 0)
			return DROP_WRITE_ERROR;
		    if (eth_store_saddr(ctx, mac->addr, 0) < 0)
			return DROP_WRITE_ERROR;
		} else {
		    fib_params.family = AF_INET;
		    fib_params.ifindex = *ifindex;

		    fib_params.ipv4_src = ip4->saddr;
		    fib_params.ipv4_dst = ip4->daddr;

		    int rc = fib_lookup(ctx, &fib_params, sizeof(fib_params),
				BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
		    if (rc != 0)
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
	int ifindex = NATIVE_DEV_IFINDEX;
	union macaddr mac = NATIVE_DEV_MAC;
	int ret = 0;

	ret = rev_nodeport_lb4(ctx, &ifindex, &mac);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
	return ctx_redirect(ctx, ifindex, 0);
}
#endif /* ENABLE_IPV4 */

static __always_inline int nodeport_nat_fwd(struct __ctx_buff *ctx,
					    const bool encap)
{
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		__be32 addr;
#ifdef ENCAP_IFINDEX
		if (encap)
			addr = IPV4_GATEWAY;
		else
#endif
			addr = IPV4_NODEPORT;
		return nodeport_nat_ipv4_fwd(ctx, addr);
	}
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6): {
		union v6addr addr;
#ifdef ENCAP_IFINDEX
		if (encap)
			BPF_V6(addr, ROUTER_IP);
		else
#endif
			BPF_V6(addr, IPV6_NODEPORT);
		return nodeport_nat_ipv6_fwd(ctx, &addr);
	}
#endif /* ENABLE_IPV6 */
	default:
		break;
	}
	return CTX_ACT_OK;
}

static __always_inline int nodeport_nat_rev(struct __ctx_buff *ctx,
					    const bool encap)
{
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		__be32 addr;
#ifdef ENCAP_IFINDEX
		if (encap)
			addr = IPV4_GATEWAY;
		else
#endif
			addr = IPV4_NODEPORT;
		return nodeport_nat_ipv4_rev(ctx, addr);
	}
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6): {
		union v6addr addr;
#ifdef ENCAP_IFINDEX
		if (encap)
			BPF_V6(addr, ROUTER_IP);
		else
#endif
			BPF_V6(addr, IPV6_NODEPORT);
		return nodeport_nat_ipv6_rev(ctx, &addr);
	}
#endif /* ENABLE_IPV6 */
	default:
		build_bug_on(!(NODEPORT_PORT_MIN_NAT < NODEPORT_PORT_MAX_NAT));
		build_bug_on(!(NODEPORT_PORT_MIN     < NODEPORT_PORT_MAX));
		build_bug_on(!(NODEPORT_PORT_MAX     < NODEPORT_PORT_MIN_NAT));
		build_bug_on(!(NODEPORT_PORT_MAX     < EPHEMERAL_MIN));
		break;
	}
	return CTX_ACT_OK;
}
#endif /* ENABLE_NODEPORT */
#endif /* __NODEPORT_H_ */
