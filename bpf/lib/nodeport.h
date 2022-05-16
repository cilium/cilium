/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

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
#include "egress_policies.h"
#include "eps.h"
#include "conntrack.h"
#include "csum.h"
#include "encap.h"
#include "identity.h"
#include "trace.h"
#include "ghash.h"
#include "pcap.h"
#include "host_firewall.h"
#include "stubs.h"
#include "proxy_hairpin.h"

#define CB_SRC_IDENTITY	0

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
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __be32);	/* ipv4 addr */
	__type(value, union macaddr);	/* hw addr */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, NODEPORT_NEIGH4_SIZE);
} NODEPORT_NEIGH4 __section_maps_btf;
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, union v6addr);	/* ipv6 addr */
	__type(value, union macaddr);	/* hw addr */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, NODEPORT_NEIGH6_SIZE);
} NODEPORT_NEIGH6 __section_maps_btf;

/* The IPv6 extension should be 8-bytes aligned */
struct dsr_opt_v6 {
	__u8 nexthdr;
	__u8 len;
	__u8 opt_type;
	__u8 opt_len;
	union v6addr addr;
	__be16 port;
	__u16 pad;
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

static __always_inline __u64 ctx_adjust_hroom_dsr_flags(void)
{
#ifdef BPF_HAVE_CSUM_LEVEL
	return BPF_F_ADJ_ROOM_NO_CSUM_RESET;
#else
	return 0;
#endif
}

static __always_inline bool dsr_fail_needs_reply(int code __maybe_unused)
{
#ifdef ENABLE_DSR_ICMP_ERRORS
	if (code == DROP_FRAG_NEEDED)
		return true;
#endif
	return false;
}

static __always_inline bool dsr_is_too_big(struct __ctx_buff *ctx __maybe_unused,
					   __u16 expanded_len __maybe_unused)
{
#ifdef ENABLE_DSR_ICMP_ERRORS
	if (expanded_len > THIS_MTU)
		return true;
#endif
	return false;
}

static __always_inline int
maybe_add_l2_hdr(struct __ctx_buff *ctx __maybe_unused,
		 __u32 ifindex __maybe_unused,
		 bool *l2_hdr_required __maybe_unused)
{
	if (IS_L3_DEV(ifindex))
		/* NodePort request is going to be redirected to L3 dev, so skip
		 * L2 addr settings.
		 */
		*l2_hdr_required = false;
	else if (ETH_HLEN == 0) {
		/* NodePort request is going to be redirected from L3 to L2 dev,
		 * so we need to create L2 hdr first.
		 */
		__u16 proto = ctx_get_protocol(ctx);

		if (ctx_change_head(ctx, __ETH_HLEN, 0))
			return DROP_INVALID;

		if (eth_store_proto(ctx, proto, 0) < 0)
			return DROP_WRITE_ERROR;
	}

	return 0;
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
					   const union v6addr *addr)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return false;
#ifdef ENABLE_DSR_HYBRID
	{
		__u8 nexthdr = ip6->nexthdr;
		int ret;

		ret = ipv6_hdrlen(ctx, &nexthdr);
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
						 const union v6addr *addr)
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
					 const union v6addr *backend_addr,
					 __be32 l4_hint, int *ohead)
{
	__u16 payload_len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
	const int l3_off = ETH_HLEN;
	union v6addr saddr;
	struct {
		__be16 payload_len;
		__u8 nexthdr;
		__u8 hop_limit;
	} tp_new = {
		.payload_len	= bpf_htons(payload_len),
		.nexthdr	= IPPROTO_IPV6,
		.hop_limit	= IPDEFTTL,
	};

	if (dsr_is_too_big(ctx, payload_len + sizeof(*ip6))) {
		*ohead = sizeof(*ip6);
		return DROP_FRAG_NEEDED;
	}

	rss_gen_src6(&saddr, (union v6addr *)&ip6->saddr, l4_hint);

	if (ctx_adjust_hroom(ctx, sizeof(*ip6), BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_dsr_flags()))
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
					const union v6addr *svc_addr,
					__be16 svc_port, int *ohead)
{
	struct dsr_opt_v6 opt __align_stack_8 = {};
	__u16 payload_len = bpf_ntohs(ip6->payload_len) + sizeof(opt);

	/* The IPv6 extension should be 8-bytes aligned */
	build_bug_on((sizeof(struct dsr_opt_v6) % 8) != 0);

	if (dsr_is_too_big(ctx, payload_len)) {
		*ohead = sizeof(opt);
		return DROP_FRAG_NEEDED;
	}

	opt.nexthdr = ip6->nexthdr;
	ip6->nexthdr = NEXTHDR_DEST;
	ip6->payload_len = bpf_htons(payload_len);

	opt.len = DSR_IPV6_EXT_LEN;
	opt.opt_type = DSR_IPV6_OPT_TYPE;
	opt.opt_len = DSR_IPV6_OPT_LEN;
	ipv6_addr_copy(&opt.addr, svc_addr);
	opt.port = svc_port;

	if (ctx_adjust_hroom(ctx, sizeof(opt), BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_dsr_flags()))
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

static __always_inline int dsr_reply_icmp6(struct __ctx_buff *ctx,
					   struct ipv6hdr *ip6 __maybe_unused,
					   int code, int ohead __maybe_unused)
{
#ifdef ENABLE_DSR_ICMP_ERRORS
	const __s32 orig_dgram = 64, off = ETH_HLEN;
	const __u32 l3_max = sizeof(*ip6) + orig_dgram;
	__be16 type = bpf_htons(ETH_P_IPV6);
	__u64 len_new = off + sizeof(*ip6) + orig_dgram;
	__u64 len_old = ctx_full_len(ctx);
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	__u8 reason = (__u8)-code;
	__wsum wsum;
	union macaddr smac, dmac;
	struct icmp6hdr icmp __align_stack_8 = {
		.icmp6_type	= ICMPV6_PKT_TOOBIG,
		.icmp6_mtu	= bpf_htonl(THIS_MTU - ohead),
	};
	__u64 payload_len = sizeof(*ip6) + sizeof(icmp) + orig_dgram;
	struct ipv6hdr ip __align_stack_8 = {
		.version	= 6,
		.priority	= ip6->priority,
		.flow_lbl[0]	= ip6->flow_lbl[0],
		.flow_lbl[1]	= ip6->flow_lbl[1],
		.flow_lbl[2]	= ip6->flow_lbl[2],
		.nexthdr	= IPPROTO_ICMPV6,
		.hop_limit	= IPDEFTTL,
		.saddr		= ip6->daddr,
		.daddr		= ip6->saddr,
		.payload_len	= bpf_htons((__u16)payload_len),
	};

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, reason);

	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		goto drop_err;
	if (eth_load_daddr(ctx, dmac.addr, 0) < 0)
		goto drop_err;
	if (unlikely(data + len_new > data_end))
		goto drop_err;

	wsum = ipv6_pseudohdr_checksum(&ip, IPPROTO_ICMPV6,
				       bpf_ntohs(ip.payload_len), 0);
	icmp.icmp6_cksum = csum_fold(csum_diff(NULL, 0, data + off, l3_max,
					       csum_diff(NULL, 0, &icmp,
							 sizeof(icmp), wsum)));

	if (ctx_adjust_troom(ctx, -(len_old - len_new)) < 0)
		goto drop_err;
	if (ctx_adjust_hroom(ctx, sizeof(ip) + sizeof(icmp),
			     BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_dsr_flags()) < 0)
		goto drop_err;

	if (eth_store_daddr(ctx, smac.addr, 0) < 0)
		goto drop_err;
	if (eth_store_saddr(ctx, dmac.addr, 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, ETH_ALEN * 2, &type, sizeof(type), 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, off, &ip, sizeof(ip), 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, off + sizeof(ip), &icmp,
			    sizeof(icmp), 0) < 0)
		goto drop_err;

	return ctx_redirect(ctx, ctx_get_ifindex(ctx), 0);
drop_err:
#endif
	return send_drop_notify_error(ctx, 0, code, CTX_ACT_DROP,
				      METRIC_EGRESS);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_DSR)
int tail_nodeport_ipv6_dsr(struct __ctx_buff *ctx)
{
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET6,
			.ifindex	= ctx_get_ifindex(ctx),
		},
	};
	__u16 port __maybe_unused;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr addr;
	int ret, ohead = 0;
	bool l2_hdr_required = true;

	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	addr.p1 = ctx_load_meta(ctx, CB_ADDR_V6_1);
	addr.p2 = ctx_load_meta(ctx, CB_ADDR_V6_2);
	addr.p3 = ctx_load_meta(ctx, CB_ADDR_V6_3);
	addr.p4 = ctx_load_meta(ctx, CB_ADDR_V6_4);

#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	ret = dsr_set_ipip6(ctx, ip6, &addr,
			    ctx_load_meta(ctx, CB_HINT), &ohead);
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
	port = (__u16)ctx_load_meta(ctx, CB_PORT);
	ret = dsr_set_ext6(ctx, ip6, &addr, port, &ohead);
#else
# error "Invalid load balancer DSR encapsulation mode!"
#endif
	if (unlikely(ret)) {
		if (dsr_fail_needs_reply(ret))
			return dsr_reply_icmp6(ctx, ip6, ret, ohead);
		goto drop_err;
	}
	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_src,
		       (union v6addr *)&ip6->saddr);
	ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_dst,
		       (union v6addr *)&ip6->daddr);

	ret = fib_lookup(ctx, &fib_params.l, sizeof(fib_params), 0);
	if (ret != 0) {
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	ret = maybe_add_l2_hdr(ctx, fib_params.l.ifindex, &l2_hdr_required);
	if (ret != 0)
		goto drop_err;
	if (!l2_hdr_required)
		goto out_send;

	if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
out_send:
	cilium_capture_out(ctx);
	return ctx_redirect(ctx, fib_params.l.ifindex, 0);
drop_err:
	return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
}
#endif /* ENABLE_DSR */

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_NAT)
int tail_nodeport_nat_ipv6(struct __ctx_buff *ctx)
{
	enum nat_dir dir = (enum nat_dir)ctx_load_meta(ctx, CB_NAT);
	const bool nat_46x64 = ctx_load_meta(ctx, CB_NAT_46X64);
	union v6addr tmp = IPV6_DIRECT_ROUTING;
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET6,
			.ifindex	= ctx_get_ifindex(ctx),
		},
	};
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.src_from_world = true,
	};
	bool l2_hdr_required = true;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret;

	if (nat_46x64)
		build_v4_in_v6(&tmp, IPV4_DIRECT_ROUTING);
	target.addr = tmp;
#ifdef TUNNEL_MODE
	if (dir == NAT_DIR_EGRESS) {
		struct remote_endpoint_info *info;
		union v6addr *dst;

		if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
			ret = DROP_INVALID;
			goto drop_err;
		}

		dst = (union v6addr *)&ip6->daddr;
		info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
		if (info != NULL && info->tunnel_endpoint != 0) {
			ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
						  WORLD_ID,
						  (enum trace_reason)CT_NEW,
						  TRACE_PAYLOAD_LEN);
			if (ret)
				goto drop_err;

			BPF_V6(target.addr, ROUTER_IP);
			fib_params.l.ifindex = ENCAP_IFINDEX;

			/* fib lookup not necessary when going over tunnel. */
			if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
				ret = DROP_WRITE_ERROR;
				goto drop_err;
			}
			if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
				ret = DROP_WRITE_ERROR;
				goto drop_err;
			}
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
			ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
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
#ifdef TUNNEL_MODE
	if (fib_params.l.ifindex == ENCAP_IFINDEX)
		goto out_send;
#endif
	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}
	if (nat_46x64) {
		struct iphdr *ip4;

		ret = lb6_to_lb4(ctx, ip6);
		if (ret < 0)
			goto drop_err;
		if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto drop_err;
		}
		fib_params.l.ipv4_src = ip4->saddr;
		fib_params.l.ipv4_dst = ip4->daddr;
		fib_params.l.family = AF_INET;
	} else {
		ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_src,
			       (union v6addr *)&ip6->saddr);
		ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_dst,
			       (union v6addr *)&ip6->daddr);
	}

	ret = fib_lookup(ctx, &fib_params.l, sizeof(fib_params), 0);
	if (ret != 0) {
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	ret = maybe_add_l2_hdr(ctx, fib_params.l.ifindex, &l2_hdr_required);
	if (ret != 0)
		goto drop_err;
	if (!l2_hdr_required)
		goto out_send;

	if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
out_send:
	cilium_capture_out(ctx);
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

	cilium_capture_in(ctx);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(ctx, &tuple.nexthdr);
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
		const bool skip_l3_xlate = DSR_ENCAP_MODE == DSR_ENCAP_IPIP;

		if (!lb6_src_range_ok(svc, (union v6addr *)&ip6->saddr))
			return DROP_NOT_IN_SRC_RANGE;

#if defined(ENABLE_L7_LB)
		if (lb6_svc_is_l7loadbalancer(svc) && svc->l7_lb_proxy_port > 0) {
			send_trace_notify(ctx, TRACE_TO_PROXY, src_identity, 0,
					  bpf_ntohs((__u16)svc->l7_lb_proxy_port), 0,
					  TRACE_REASON_POLICY, monitor);
			return ctx_redirect_to_proxy_hairpin_ipv6(ctx,
								  (__be16)svc->l7_lb_proxy_port);
		}
#endif
		ret = lb6_local(get_ct_map6(&tuple), ctx, l3_off, l4_off,
				&csum_off, &key, &tuple, svc, &ct_state_new,
				skip_l3_xlate);
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
		ctx_store_meta(ctx, CB_NAT_46X64, 0);
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
redo:
			ct_state_new.src_sec_id = WORLD_ID;
			ct_state_new.node_port = 1;
			ct_state_new.ifindex = (__u16)NATIVE_DEV_IFINDEX;
			ret = ct_create6(get_ct_map6(&tuple), NULL, &tuple, ctx,
					 CT_EGRESS, &ct_state_new, false, false);
			if (IS_ERR(ret))
				return ret;
			break;
		case CT_REOPENED:
		case CT_ESTABLISHED:
		case CT_REPLY:
			if (unlikely(ct_state.rev_nat_index !=
				     svc->rev_nat_index))
				goto redo;
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
			/* This code path is not only hit for NAT64, but also
			 * for NAT46. For the latter we initially hit the IPv4
			 * NodePort path, then migrate the request to IPv6 and
			 * recirculate into the regular IPv6 NodePort path. So
			 * we need to make sure to not NAT back to IPv4 for
			 * IPv4-in-IPv6 converted addresses.
			 */
			ctx_store_meta(ctx, CB_NAT_46X64,
				       !is_v4_in_v6(&key.address) &&
				       lb6_to_lb4_service(svc));
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
	int ret, fib_ret, ret2, l3_off = ETH_HLEN, l4_off, hdrlen;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	struct ct_state ct_state = {};
	struct bpf_fib_lookup fib_params = {};
	__u32 monitor = 0;
	bool l2_hdr_required = true;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(ctx, &tuple.nexthdr);
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
#ifdef TUNNEL_MODE
		{
			union v6addr *dst = (union v6addr *)&ip6->daddr;
			struct remote_endpoint_info *info;

			info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
			if (info != NULL && info->tunnel_endpoint != 0) {
				ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
							  SECLABEL,
							  TRACE_REASON_CT_REPLY,
							  TRACE_PAYLOAD_LEN);
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

		fib_params.family = AF_INET6;
		fib_params.ifindex = ctx_get_ifindex(ctx);

		ipv6_addr_copy((union v6addr *)&fib_params.ipv6_src, &tuple.saddr);
		ipv6_addr_copy((union v6addr *)&fib_params.ipv6_dst, &tuple.daddr);

		fib_ret = fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

		if (fib_ret == 0)
			*ifindex = fib_params.ifindex;

		ret = maybe_add_l2_hdr(ctx, *ifindex, &l2_hdr_required);
		if (ret != 0)
			return ret;
		if (!l2_hdr_required)
			return CTX_ACT_OK;

		if (fib_ret != 0) {
			union macaddr smac =
				NATIVE_DEV_MAC_BY_IFINDEX(*ifindex);
			union macaddr *dmac;

			if (fib_ret != BPF_FIB_LKUP_RET_NO_NEIGH)
				return DROP_NO_FIB;

			/* See comment in rev_nodeport_lb4(). */
			dmac = map_lookup_elem(&NODEPORT_NEIGH6, &tuple.daddr);
			if (unlikely(!dmac))
				return DROP_NO_FIB;
			if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr_aligned(ctx, smac.addr, 0) < 0)
				return DROP_WRITE_ERROR;
		} else {
			if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	} else {
		if (!bpf_skip_recirculation(ctx)) {
			bpf_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
			return DROP_MISSED_TAIL_CALL;
		}
	}

	return CTX_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_REVNAT)
int tail_rev_nodeport_lb6(struct __ctx_buff *ctx)
{
	int ifindex = 0, ret = 0;
	void *data, *data_end;
	struct ipv6hdr *ip6;

#if defined(ENABLE_HOST_FIREWALL) && defined(IS_BPF_HOST)
	/* We only enforce the host policies if nodeport.h is included from
	 * bpf_host.
	 */
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 src_id = 0;

	ret = ipv6_host_policy_ingress(ctx, &src_id, &trace);
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
		goto drop;
	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		goto drop;
	if (is_v4_in_v6((union v6addr *)&ip6->saddr)) {
		ret = lb6_to_lb4(ctx, ip6);
		if (ret)
			goto drop;
	}

	edt_set_aggregate(ctx, 0);
	cilium_capture_out(ctx);

	return ctx_redirect(ctx, ifindex, 0);
drop:
	return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
}

declare_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
			       is_defined(ENABLE_IPV6)),
			 __and(is_defined(ENABLE_HOST_FIREWALL),
			       is_defined(IS_BPF_HOST))),
		    CILIUM_CALL_IPV6_ENCAP_NODEPORT_NAT)
int tail_handle_nat_fwd_ipv6(struct __ctx_buff *ctx)
{
	int ret;
	enum trace_point obs_point;
#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
	union v6addr addr = { .p1 = 0 };
	BPF_V6(addr, ROUTER_IP);
	obs_point = TRACE_TO_OVERLAY;
#else
	union v6addr addr = IPV6_DIRECT_ROUTING;
	obs_point = TRACE_TO_NETWORK;
#endif
	ret = nodeport_nat_ipv6_fwd(ctx, &addr);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);

	send_trace_notify(ctx, obs_point, 0, 0, 0, 0, TRACE_REASON_UNKNOWN, 0);

	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline bool nodeport_uses_dsr4(const struct ipv4_ct_tuple *tuple)
{
	return nodeport_uses_dsr(tuple->nexthdr);
}

/* The function contains a core logic for deciding whether an egressing packet
 * has to be SNAT-ed. Currently, the function targets the following flows:
 *
 *	- From pod to outside to masquerade requests
 *	  when --enable-bpf-masquerade=true.
 *	- From host to outside to track (and masquerade) flows which
 *	  can conflict with NodePort BPF.
 *
 * The function sets "addr" to the SNAT IP addr, and "from_endpoint" to true
 * if the packet is sent from a local endpoint.
 *
 * Callers should treat contents of "from_endpoint" and "addr" as undetermined,
 * if function returns false.
 */
static __always_inline bool snat_v4_needed(struct __ctx_buff *ctx, __be32 *addr,
					   bool *from_endpoint __maybe_unused)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct endpoint_info *local_ep __maybe_unused;
	struct remote_endpoint_info *remote_ep __maybe_unused;
	struct egress_gw_policy_entry *egress_gw_policy __maybe_unused;
	bool is_reply = false;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return false;

	/* Basic minimum is to only NAT when there is a potential of
	 * overlapping tuples, e.g. applications in hostns reusing
	 * source IPs we SNAT in NodePort and BPF-masq.
	 */
#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
	if (ip4->saddr == IPV4_GATEWAY) {
		*addr = IPV4_GATEWAY;
		return true;
	}
#else
    /* NATIVE_DEV_IFINDEX == DIRECT_ROUTING_DEV_IFINDEX cannot be moved into
     * preprocessor, as the former is known only during load time (templating).
     * This checks whether bpf_host is running on the direct routing device.
     */
	if (DIRECT_ROUTING_DEV_IFINDEX == NATIVE_DEV_IFINDEX &&
	    ip4->saddr == IPV4_DIRECT_ROUTING) {
		*addr = IPV4_DIRECT_ROUTING;
		return true;
	}
# ifdef ENABLE_MASQUERADE
	if (ip4->saddr == IPV4_MASQUERADE) {
		*addr = IPV4_MASQUERADE;
		return true;
	}
# endif
#endif /* defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY) */

	local_ep = __lookup_ip4_endpoint(ip4->saddr);
	remote_ep = lookup_ip4_remote_endpoint(ip4->daddr);

	/* Check if this packet belongs to reply traffic coming from a
	 * local endpoint.
	 *
	 * If local_ep is NULL, it means there's no endpoint running on the
	 * node which matches the packet source IP, which means we can
	 * skip the CT lookup since this cannot be reply traffic.
	 */
	if (local_ep) {
		struct ipv4_ct_tuple tuple = {
			.nexthdr = ip4->protocol,
			.daddr = ip4->daddr,
			.saddr = ip4->saddr
		};

		ct_is_reply4(get_ct_map4(&tuple), ctx, ETH_HLEN +
			     ipv4_hdrlen(ip4), &tuple, &is_reply);
	}

#ifdef ENABLE_MASQUERADE /* SNAT local pod to world packets */
# ifdef IS_BPF_OVERLAY
	/* Do not MASQ when this function is executed from bpf_overlay
	 * (IS_BPF_OVERLAY denotes this fact). Otherwise, a packet will
	 * be SNAT'd to cilium_host IP addr.
	 */
	return false;
# endif

/* Check if the packet matches an egress NAT policy and so needs to be SNAT'ed.
 *
 * This check must happen before the IPV4_SNAT_EXCLUSION_DST_CIDR check below as
 * the destination may be in the SNAT exclusion CIDR but regardless of that we
 * always want to SNAT a packet if it's matched by an egress NAT policy.
 */
#if defined(ENABLE_EGRESS_GATEWAY)
	/* If the packet is destined to an entity inside the cluster, either EP
	 * or node, skip SNAT since only traffic leaving the cluster is supposed
	 * to be masqueraded with an egress IP.
	 */
	if (remote_ep &&
	    is_cluster_destination(ip4, remote_ep->sec_label, remote_ep->tunnel_endpoint))
		goto skip_egress_gateway;

	/* If the packet is a reply it means that outside has initiated the
	 * connection, so no need to SNAT the reply.
	 */
	if (is_reply)
		goto skip_egress_gateway;

	egress_gw_policy = lookup_ip4_egress_gw_policy(ip4->saddr, ip4->daddr);
	if (!egress_gw_policy)
		goto skip_egress_gateway;

	*addr = egress_gw_policy->egress_ip;
	*from_endpoint = true;

	return true;

skip_egress_gateway:
#endif

#ifdef IPV4_SNAT_EXCLUSION_DST_CIDR
	/* Do not MASQ if a dst IP belongs to a pods CIDR
	 * (ipv4-native-routing-cidr if specified, otherwise local pod CIDR).
	 * The check is performed before we determine that a packet is
	 * sent from a local pod, as this check is cheaper than
	 * the map lookup done in the latter check.
	 */
	if (ipv4_is_in_subnet(ip4->daddr, IPV4_SNAT_EXCLUSION_DST_CIDR,
			      IPV4_SNAT_EXCLUSION_DST_CIDR_LEN))
		return false;
#endif

	/* if this is a localhost endpoint, no SNAT is needed */
	if (local_ep && (local_ep->flags & ENDPOINT_F_HOST))
		return false;

	if (remote_ep) {
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
#ifndef TUNNEL_MODE
		/* In the tunnel mode, a packet from a local ep
		 * to a remote node is not encap'd, and is sent
		 * via a native dev. Therefore, such packet has
		 * to be MASQ'd. Otherwise, it might be dropped
		 * either by underlying network (e.g. AWS drops
		 * packets by default from unknown subnets) or
		 * by the remote node if its native dev's
		 * rp_filter=1.
		 */
		if (identity_is_remote_node(remote_ep->sec_label))
			return false;
#endif

		/* If the packet is a reply it means that outside has
		 * initiated the connection, so no need to SNAT the
		 * reply.
		 */
		if (!is_reply && local_ep) {
			*from_endpoint = true;
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
					 __be32 l4_hint, __be16 *ohead)
{
	__u16 tot_len = bpf_ntohs(ip4->tot_len) + sizeof(*ip4);
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
		.tot_len	= bpf_htons(tot_len),
		.ttl		= IPDEFTTL,
		.protocol	= IPPROTO_IPIP,
		.saddr		= rss_gen_src4(ip4->saddr, l4_hint),
		.daddr		= backend_addr,
	};

	if (dsr_is_too_big(ctx, tot_len)) {
		*ohead = sizeof(*ip4);
		return DROP_FRAG_NEEDED;
	}

	if (ctx_adjust_hroom(ctx, sizeof(*ip4), BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_dsr_flags()))
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
					struct iphdr *ip4, __be32 svc_addr,
					__be32 svc_port, __be16 *ohead)
{
	__u32 iph_old, iph_new, opt[2];
	__u16 tot_len = bpf_ntohs(ip4->tot_len) + sizeof(opt);
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

	if (dsr_is_too_big(ctx, tot_len)) {
		*ohead = sizeof(opt);
		return DROP_FRAG_NEEDED;
	}

	iph_old = *(__u32 *)ip4;
	ip4->ihl += sizeof(opt) >> 2;
	ip4->tot_len = bpf_htons(tot_len);
	iph_new = *(__u32 *)ip4;

	opt[0] = bpf_htonl(DSR_IPV4_OPT_32 | svc_port);
	opt[1] = bpf_htonl(svc_addr);

	sum = csum_diff(&iph_old, 4, &iph_new, 4, 0);
	sum = csum_diff(NULL, 0, &opt, sizeof(opt), sum);

	if (ctx_adjust_hroom(ctx, sizeof(opt), BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_dsr_flags()))
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
		__be32 address;
		__be16 dport;

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

static __always_inline int dsr_reply_icmp4(struct __ctx_buff *ctx,
					   struct iphdr *ip4 __maybe_unused,
					   int code, __be16 ohead __maybe_unused)
{
#ifdef ENABLE_DSR_ICMP_ERRORS
	const __s32 orig_dgram = 8, off = ETH_HLEN;
	const __u32 l3_max = MAX_IPOPTLEN + sizeof(*ip4) + orig_dgram;
	__be16 type = bpf_htons(ETH_P_IP);
	__s32 len_new = off + ipv4_hdrlen(ip4) + orig_dgram;
	__s32 len_old = ctx_full_len(ctx);
	__u8 reason = (__u8)-code;
	__u8 tmp[l3_max];
	union macaddr smac, dmac;
	struct icmphdr icmp __align_stack_8 = {
		.type		= ICMP_DEST_UNREACH,
		.code		= ICMP_FRAG_NEEDED,
		.un = {
			.frag = {
				.mtu = bpf_htons(THIS_MTU - ohead),
			},
		},
	};
	__u64 tot_len = sizeof(struct iphdr) + ipv4_hdrlen(ip4) + sizeof(icmp) + orig_dgram;
	struct iphdr ip __align_stack_8 = {
		.ihl		= sizeof(ip) >> 2,
		.version	= IPVERSION,
		.ttl		= IPDEFTTL,
		.tos		= ip4->tos,
		.id		= ip4->id,
		.protocol	= IPPROTO_ICMP,
		.saddr		= ip4->daddr,
		.daddr		= ip4->saddr,
		.frag_off	= bpf_htons(IP_DF),
		.tot_len	= bpf_htons((__u16)tot_len),
	};

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, reason);

	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		goto drop_err;
	if (eth_load_daddr(ctx, dmac.addr, 0) < 0)
		goto drop_err;

	ip.check = csum_fold(csum_diff(NULL, 0, &ip, sizeof(ip), 0));

	/* We use a workaround here in that we push zero-bytes into the
	 * payload in order to support dynamic IPv4 header size. This
	 * works given one's complement sum does not change.
	 */
	memset(tmp, 0, MAX_IPOPTLEN);
	if (ctx_store_bytes(ctx, len_new, tmp, MAX_IPOPTLEN, 0) < 0)
		goto drop_err;
	if (ctx_load_bytes(ctx, off, tmp, sizeof(tmp)) < 0)
		goto drop_err;

	icmp.checksum = csum_fold(csum_diff(NULL, 0, tmp, sizeof(tmp),
					    csum_diff(NULL, 0, &icmp,
						      sizeof(icmp), 0)));

	if (ctx_adjust_troom(ctx, -(len_old - len_new)) < 0)
		goto drop_err;
	if (ctx_adjust_hroom(ctx, sizeof(ip) + sizeof(icmp),
			     BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_dsr_flags()) < 0)
		goto drop_err;

	if (eth_store_daddr(ctx, smac.addr, 0) < 0)
		goto drop_err;
	if (eth_store_saddr(ctx, dmac.addr, 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, ETH_ALEN * 2, &type, sizeof(type), 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, off, &ip, sizeof(ip), 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, off + sizeof(ip), &icmp,
			    sizeof(icmp), 0) < 0)
		goto drop_err;

	return ctx_redirect(ctx, ctx_get_ifindex(ctx), 0);
drop_err:
#endif
	return send_drop_notify_error(ctx, 0, code, CTX_ACT_DROP,
				      METRIC_EGRESS);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_DSR)
int tail_nodeport_ipv4_dsr(struct __ctx_buff *ctx)
{
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET,
			.ifindex	= ctx_get_ifindex(ctx),
		},
	};
	bool l2_hdr_required = true;
	void *data, *data_end;
	struct iphdr *ip4;
	__be16 ohead = 0;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	ret = dsr_set_ipip4(ctx, ip4,
			    ctx_load_meta(ctx, CB_ADDR_V4),
			    ctx_load_meta(ctx, CB_HINT), &ohead);
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
	ret = dsr_set_opt4(ctx, ip4,
			   ctx_load_meta(ctx, CB_ADDR_V4),
			   ctx_load_meta(ctx, CB_PORT), &ohead);
#else
# error "Invalid load balancer DSR encapsulation mode!"
#endif
	if (unlikely(ret)) {
		if (dsr_fail_needs_reply(ret))
			return dsr_reply_icmp4(ctx, ip4, ret, ohead);
		goto drop_err;
	}
	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	fib_params.l.ipv4_src = ip4->saddr;
	fib_params.l.ipv4_dst = ip4->daddr;

	ret = fib_lookup(ctx, &fib_params.l, sizeof(fib_params), 0);
	if (ret != 0) {
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	ret = maybe_add_l2_hdr(ctx, fib_params.l.ifindex, &l2_hdr_required);
	if (ret != 0)
		goto drop_err;
	if (!l2_hdr_required)
		goto out_send;

	if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
out_send:
	cilium_capture_out(ctx);
	return ctx_redirect(ctx, fib_params.l.ifindex, 0);
drop_err:
	return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
}
#endif /* ENABLE_DSR */

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_NAT)
int tail_nodeport_nat_ipv4(struct __ctx_buff *ctx)
{
	enum nat_dir dir = (enum nat_dir)ctx_load_meta(ctx, CB_NAT);
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET,
			.ifindex	= ctx_get_ifindex(ctx),
		},
	};
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.src_from_world = true,
	};
	void *data, *data_end;
	struct iphdr *ip4;
	bool l2_hdr_required = true;
	int ret;

	/* Unfortunately, the bpf_fib_lookup() is not able to set src IP addr.
	 * So we need to assume that the direct routing device is going to be
	 * used to fwd the NodePort request, thus SNAT-ing to its IP addr.
	 * This will change once we have resolved GH#17158.
	 */
	target.addr = IPV4_DIRECT_ROUTING;
#ifdef TUNNEL_MODE
	if (dir == NAT_DIR_EGRESS) {
		struct remote_endpoint_info *info;

		if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto drop_err;
		}

		info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
		if (info != NULL && info->tunnel_endpoint != 0) {
			/* The dir == NAT_DIR_EGRESS branch is executed for
			 * N/S LB requests which needs to be fwd-ed to a remote
			 * node. As the request came from outside, we need to
			 * set the security id in the tunnel header to WORLD_ID.
			 * Otherwise, the remote node will assume, that the
			 * request originated from a cluster node which will
			 * bypass any netpol which disallows LB requests from
			 * outside.
			 */
			ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
						  WORLD_ID,
						  (enum trace_reason)CT_NEW,
						  TRACE_PAYLOAD_LEN);
			if (ret)
				goto drop_err;

			target.addr = IPV4_GATEWAY;
			fib_params.l.ifindex = ENCAP_IFINDEX;

			/* fib lookup not necessary when going over tunnel. */
			if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
				ret = DROP_WRITE_ERROR;
				goto drop_err;
			}
			if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
				ret = DROP_WRITE_ERROR;
				goto drop_err;
			}
		}
	}
#endif
	/* Handles SNAT on NAT_DIR_EGRESS and reverse SNAT for reply packets
	 * from remote backends on NAT_DIR_INGRESS.
	 */
	ret = snat_v4_process(ctx, dir, &target, false);
	if (IS_ERR(ret)) {
		/* In case of no mapping, recircle back to main path. SNAT is very
		 * expensive in terms of instructions (since we don't have BPF to
		 * BPF calls as we use tail calls) and complexity, hence this is
		 * done inside a tail call here.
		 */
		if (dir == NAT_DIR_INGRESS) {
			bpf_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_NETDEV);
			ret = DROP_MISSED_TAIL_CALL;
			goto drop_err;
		}
		if (ret != NAT_PUNT_TO_STACK)
			goto drop_err;
	}

	bpf_mark_snat_done(ctx);

	if (dir == NAT_DIR_INGRESS) {
		/* At this point we know that a reverse SNAT mapping exists.
		 * Otherwise, we would have tail-called back to
		 * CALL_IPV4_FROM_NETDEV in the code above. The existence of the
		 * mapping is an indicator that the packet might be a reply from
		 * a remote backend. So handle the service reverse DNAT (if
		 * needed)
		 */
		ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_REVNAT);
		ret = DROP_MISSED_TAIL_CALL;
		goto drop_err;
	}
#ifdef TUNNEL_MODE
	if (fib_params.l.ifindex == ENCAP_IFINDEX)
		goto out_send;
#endif
	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	fib_params.l.ipv4_src = ip4->saddr;
	fib_params.l.ipv4_dst = ip4->daddr;

	ret = fib_lookup(ctx, &fib_params.l, sizeof(fib_params), 0);
	if (ret != 0) {
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	ret = maybe_add_l2_hdr(ctx, fib_params.l.ifindex, &l2_hdr_required);
	if (ret != 0)
		goto drop_err;
	if (!l2_hdr_required)
		goto out_send;

	if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
out_send:
	cilium_capture_out(ctx);
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

	cilium_capture_in(ctx);

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
		const bool skip_l3_xlate = DSR_ENCAP_MODE == DSR_ENCAP_IPIP;

		if (!lb4_src_range_ok(svc, ip4->saddr))
			return DROP_NOT_IN_SRC_RANGE;
#if defined(ENABLE_L7_LB)
		if (lb4_svc_is_l7loadbalancer(svc) && svc->l7_lb_proxy_port > 0) {
			send_trace_notify(ctx, TRACE_TO_PROXY, src_identity, 0,
					  bpf_ntohs((__u16)svc->l7_lb_proxy_port), 0,
					  TRACE_REASON_POLICY, monitor);
			return ctx_redirect_to_proxy_hairpin_ipv4(ctx,
								  (__be16)svc->l7_lb_proxy_port);
		}
#endif
		if (lb4_to_lb6_service(svc)) {
			ret = lb4_to_lb6(ctx, ip4, l3_off);
			if (!ret)
				return NAT_46X64_RECIRC;
		} else {
			ret = lb4_local(get_ct_map4(&tuple), ctx, l3_off, l4_off,
					&csum_off, &key, &tuple, svc, &ct_state_new,
					ip4->saddr, ipv4_has_l4_header(ip4),
					skip_l3_xlate);
		}
		if (IS_ERR(ret))
			return ret;
	}

	if (!svc || !lb4_svc_is_routable(svc)) {
		if (svc)
			return DROP_IS_CLUSTER_IP;

		/* The packet is not destined to a service but it can be a reply
		 * packet from a remote backend, in which case we need to perform
		 * the reverse NAT.
		 */
skip_service_lookup:
		ctx_set_xfer(ctx, XFER_PKT_NO_SVC);

#ifndef ENABLE_MASQUERADE
		if (nodeport_uses_dsr4(&tuple))
			return CTX_ACT_OK;
#endif
		ctx_store_meta(ctx, CB_NAT, NAT_DIR_INGRESS);
		ctx_store_meta(ctx, CB_SRC_IDENTITY, src_identity);
		/* For NAT64 we might see an IPv4 reply from the backend to
		 * the LB entering this path. Thus, transform back to IPv6.
		 */
		if (!lb4_populate_ports(ctx, &tuple, l4_off) &&
		    snat_v6_has_v4_match(&tuple)) {
			ret = lb4_to_lb6(ctx, ip4, l3_off);
			if (ret)
				return ret;
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT);
		} else {
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_NAT);
		}
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
redo:
			ct_state_new.src_sec_id = WORLD_ID;
			ct_state_new.node_port = 1;
			ct_state_new.ifindex = (__u16)NATIVE_DEV_IFINDEX;
			ret = ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx,
					 CT_EGRESS, &ct_state_new, false, false);
			if (IS_ERR(ret))
				return ret;
			break;
		case CT_REOPENED:
		case CT_ESTABLISHED:
		case CT_REPLY:
			/* Recreate CT entries, as the existing one is stale and
			 * belongs to a flow which target a different svc.
			 */
			if (unlikely(ct_state.rev_nat_index !=
				     svc->rev_nat_index))
				goto redo;
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
 * Also, reverse NAT handling return path egress-gw traffic.
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
	int ret, fib_ret, ret2, l3_off = ETH_HLEN, l4_off;
	struct ct_state ct_state = {};
	struct bpf_fib_lookup fib_params = {};
	enum trace_reason __maybe_unused reason = TRACE_REASON_UNKNOWN;
	__u32 monitor = TRACE_PAYLOAD_LEN;
	bool l2_hdr_required = true;
	__u32 tunnel_endpoint __maybe_unused = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

#if defined(ENABLE_EGRESS_GATEWAY) && !defined(TUNNEL_MODE) && \
	__ctx_is != __ctx_xdp
	/* Traffic from clients to egress gateway nodes reaches said gateways
	 * by a vxlan tunnel. If we are not using TUNNEL_MODE, we need to
	 * identify reverse traffic from the gateway to clients and also steer
	 * it via the vxlan tunnel to avoid issues with iptables dropping these
	 * packets. We do this in the code below, by performing a lookup in the
	 * egress gateway map using a reverse address tuple. A match means that
	 * the corresponding forward traffic was forwarded to the egress gateway
	 * via the tunnel.
	 *
	 * Currently, we don't support redirect to a tunnel netdev / encap on
	 * XDP. Thus, the problem mentioned above is present when using the
	 * egress gw feature with bpf_xdp.
	 */
	{
		struct egress_gw_policy_entry *egress_policy;

		egress_policy = lookup_ip4_egress_gw_policy(ip4->daddr, ip4->saddr);
		if (egress_policy) {
			struct remote_endpoint_info *info;

			info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
			if (info && info->tunnel_endpoint != 0) {
				tunnel_endpoint = info->tunnel_endpoint;
				goto encap_redirect;
			}
		}
	}
#endif /* ENABLE_EGRESS_GATEWAY */
	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_INGRESS, &ct_state,
			 &monitor);

	if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {
		reason = TRACE_REASON_CT_REPLY;
		ret2 = lb4_rev_nat(ctx, l3_off, l4_off, &csum_off,
				   &ct_state, &tuple,
				   REV_NAT_F_TUPLE_SADDR, ipv4_has_l4_header(ip4));
		if (IS_ERR(ret2))
			return ret2;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		bpf_mark_snat_done(ctx);

		*ifindex = ct_state.ifindex;
#if defined(TUNNEL_MODE) && __ctx_is != __ctx_xdp
		{
			struct remote_endpoint_info *info;

			info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
			if (info != NULL && info->tunnel_endpoint != 0) {
				tunnel_endpoint = info->tunnel_endpoint;
				goto encap_redirect;
			}
		}
#endif

		fib_params.family = AF_INET;
		fib_params.ifindex = ctx_get_ifindex(ctx);

		fib_params.ipv4_src = ip4->saddr;
		fib_params.ipv4_dst = ip4->daddr;

		fib_ret = fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

		if (fib_ret == 0)
			/* If the FIB lookup was successful, use the outgoing
			 * iface from its result. Otherwise, we will fallback
			 * to CT's ifindex which was learned when the request
			 * was sent. The latter assumes that the reply should
			 * be sent over the same device which received the
			 * request.
			 */
			*ifindex = fib_params.ifindex;

		ret = maybe_add_l2_hdr(ctx, *ifindex, &l2_hdr_required);
		if (ret != 0)
			return ret;
		if (!l2_hdr_required)
			return CTX_ACT_OK;

		if (fib_ret != 0) {
			union macaddr smac =
				NATIVE_DEV_MAC_BY_IFINDEX(*ifindex);
			union macaddr *dmac;

			if (fib_ret != BPF_FIB_LKUP_RET_NO_NEIGH)
				return DROP_NO_FIB;

			/* For the case where a client from the same L2
			 * domain previously sent traffic over the node
			 * which did the service -> backend translation
			 * and that node has never seen the client before
			 * then XDP/tc BPF layer won't create a neighbor
			 * entry for it. This makes the above fib_lookup()
			 * fail and we have to consult the NODEPORT_NEIGH4
			 * table instead where we recorded the client
			 * address in nodeport_lb4().
			 */
			dmac = map_lookup_elem(&NODEPORT_NEIGH4, &tuple.daddr);
			if (unlikely(!dmac))
				return DROP_NO_FIB;
			if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr_aligned(ctx, smac.addr, 0) < 0)
				return DROP_WRITE_ERROR;
		} else {
			if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	} else {
		if (!bpf_skip_recirculation(ctx)) {
			bpf_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_NETDEV);
			return DROP_MISSED_TAIL_CALL;
		}
	}

	return CTX_ACT_OK;

#if (defined(ENABLE_EGRESS_GATEWAY) || defined(TUNNEL_MODE)) && \
	__ctx_is != __ctx_xdp
encap_redirect:
	ret = __encap_with_nodeid(ctx, tunnel_endpoint, SECLABEL,
				  reason, monitor);
	if (ret)
		return ret;

	*ifindex = ENCAP_IFINDEX;

	/* fib lookup not necessary when going over tunnel. */
	if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
		return DROP_WRITE_ERROR;
	if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
		return DROP_WRITE_ERROR;

	return CTX_ACT_OK;
#endif
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
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 src_id = 0;

	ret = ipv4_host_policy_ingress(ctx, &src_id, &trace);
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
	cilium_capture_out(ctx);

	return ctx_redirect(ctx, ifindex, 0);
}

declare_tailcall_if(__or3(__and(is_defined(ENABLE_IPV4),
				is_defined(ENABLE_IPV6)),
			  __and(is_defined(ENABLE_HOST_FIREWALL),
				is_defined(IS_BPF_HOST)),
			  is_defined(ENABLE_EGRESS_GATEWAY)),
		    CILIUM_CALL_IPV4_ENCAP_NODEPORT_NAT)
int tail_handle_nat_fwd_ipv4(struct __ctx_buff *ctx)
{
	int ret;
	enum trace_point obs_point;

#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
	obs_point = TRACE_TO_OVERLAY;
#else
	obs_point = TRACE_TO_NETWORK;
#endif

	ret = nodeport_nat_ipv4_fwd(ctx);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);

	send_trace_notify(ctx, obs_point, 0, 0, 0, 0, TRACE_REASON_UNKNOWN, 0);

	return ret;
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_HEALTH_CHECK
static __always_inline int
health_encap_v4(struct __ctx_buff *ctx, __u32 tunnel_ep,
		__u32 seclabel)
{
	struct bpf_tunnel_key key;

	/* When encapsulating, a packet originating from the local
	 * host is being considered as a packet from a remote node
	 * as it is being received.
	 */
	memset(&key, 0, sizeof(key));
	key.tunnel_id = seclabel == HOST_ID ? LOCAL_NODE_ID : seclabel;
	key.remote_ipv4 = bpf_htonl(tunnel_ep);
	key.tunnel_ttl = 64;

	if (unlikely(ctx_set_tunnel_key(ctx, &key, sizeof(key),
					BPF_F_ZERO_CSUM_TX) < 0))
		return DROP_WRITE_ERROR;
	return 0;
}

static __always_inline int
health_encap_v6(struct __ctx_buff *ctx, const union v6addr *tunnel_ep,
		__u32 seclabel)
{
	struct bpf_tunnel_key key;

	memset(&key, 0, sizeof(key));
	key.tunnel_id = seclabel == HOST_ID ? LOCAL_NODE_ID : seclabel;
	key.remote_ipv6[0] = tunnel_ep->p1;
	key.remote_ipv6[1] = tunnel_ep->p2;
	key.remote_ipv6[2] = tunnel_ep->p3;
	key.remote_ipv6[3] = tunnel_ep->p4;
	key.tunnel_ttl = 64;

	if (unlikely(ctx_set_tunnel_key(ctx, &key, sizeof(key),
					BPF_F_ZERO_CSUM_TX |
					BPF_F_TUNINFO_IPV6) < 0))
		return DROP_WRITE_ERROR;
	return 0;
}

static __always_inline int
lb_handle_health(struct __ctx_buff *ctx __maybe_unused)
{
	void *data __maybe_unused, *data_end __maybe_unused;
	__sock_cookie key __maybe_unused;
	int ret __maybe_unused;
	__u16 proto = 0;

	if ((ctx->mark & MARK_MAGIC_HEALTH_IPIP_DONE) ==
	    MARK_MAGIC_HEALTH_IPIP_DONE)
		return CTX_ACT_OK;
	validate_ethertype(ctx, &proto);
	switch (proto) {
#if defined(ENABLE_IPV4) && DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	case bpf_htons(ETH_P_IP): {
		struct lb4_health *val;

		key = get_socket_cookie(ctx);
		val = map_lookup_elem(&LB4_HEALTH_MAP, &key);
		if (!val)
			return CTX_ACT_OK;
		ret = health_encap_v4(ctx, val->peer.address, 0);
		if (ret != 0)
			return ret;
		ctx->mark |= MARK_MAGIC_HEALTH_IPIP_DONE;
		return ctx_redirect(ctx, ENCAP4_IFINDEX, 0);
	}
#endif
#if defined(ENABLE_IPV6) && DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	case bpf_htons(ETH_P_IPV6): {
		struct lb6_health *val;

		key = get_socket_cookie(ctx);
		val = map_lookup_elem(&LB6_HEALTH_MAP, &key);
		if (!val)
			return CTX_ACT_OK;
		ret = health_encap_v6(ctx, &val->peer.address, 0);
		if (ret != 0)
			return ret;
		ctx->mark |= MARK_MAGIC_HEALTH_IPIP_DONE;
		return ctx_redirect(ctx, ENCAP6_IFINDEX, 0);
	}
#endif
	default:
		return CTX_ACT_OK;
	}
}
#endif /* ENABLE_HEALTH_CHECK */

static __always_inline int handle_nat_fwd(struct __ctx_buff *ctx)
{
	int ret = CTX_ACT_OK;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		invoke_tailcall_if(__or3(__and(is_defined(ENABLE_IPV4),
					       is_defined(ENABLE_IPV6)),
					 __and(is_defined(ENABLE_HOST_FIREWALL),
					       is_defined(IS_BPF_HOST)),
					 is_defined(ENABLE_EGRESS_GATEWAY)),
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
