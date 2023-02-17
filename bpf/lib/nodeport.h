/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __NODEPORT_H_
#define __NODEPORT_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "bpf/compiler.h"
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
#include "fib.h"

#ifdef ENABLE_NODEPORT
/* The IPv6 extension should be 8-bytes aligned */
struct dsr_opt_v6 {
	struct ipv6_opt_hdr hdr;
	__u8 opt_type;
	__u8 opt_len;
	union v6addr addr;
	__be16 port;
	__u16 pad;
};

struct dsr_opt_v4 {
	__u8 type;
	__u8 len;
	__u16 port;
	__u32 addr;
};

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

#ifdef ENABLE_IPV6
static __always_inline bool nodeport_uses_dsr6(const struct ipv6_ct_tuple *tuple)
{
	return nodeport_uses_dsr(tuple->nexthdr);
}

static __always_inline int nodeport_snat_fwd_ipv6(struct __ctx_buff *ctx,
						  const union v6addr *addr,
						  __s8 *ext_err)
{
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};
	int ret;

	ipv6_addr_copy(&target.addr, addr);

	ret = snat_v6_needed(ctx, addr) ?
	      snat_v6_nat(ctx, &target, ext_err) : CTX_ACT_OK;
	if (ret == NAT_PUNT_TO_STACK)
		ret = CTX_ACT_OK;

	/* See the equivalent v4 path for comment */
	ctx_snat_done_set(ctx);

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
			     ctx_adjust_hroom_flags()))
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
	__u16 total_len = bpf_ntohs(ip6->payload_len) + sizeof(struct ipv6hdr) + sizeof(opt);
	__u8 nexthdr = ip6->nexthdr;
	int hdrlen;

	/* The IPv6 extension should be 8-bytes aligned */
	build_bug_on((sizeof(struct dsr_opt_v6) % 8) != 0);

	hdrlen = ipv6_hdrlen(ctx, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	/* See dsr_set_opt4(): */
	if (nexthdr == IPPROTO_TCP) {
		union tcp_flags tcp_flags = { .value = 0 };

		if (l4_load_tcp_flags(ctx, ETH_HLEN + hdrlen, &tcp_flags) < 0)
			return DROP_CT_INVALID_HDR;

		if (!(tcp_flags.value & (TCP_FLAG_SYN)))
			return 0;
	}

	if (dsr_is_too_big(ctx, total_len)) {
		*ohead = sizeof(opt);
		return DROP_FRAG_NEEDED;
	}

	opt.hdr.nexthdr = ip6->nexthdr;
	ip6->nexthdr = NEXTHDR_DEST;
	ip6->payload_len = bpf_htons(payload_len);

	opt.hdr.hdrlen = DSR_IPV6_EXT_LEN;
	opt.opt_type = DSR_IPV6_OPT_TYPE;
	opt.opt_len = DSR_IPV6_OPT_LEN;
	ipv6_addr_copy(&opt.addr, svc_addr);
	opt.port = svc_port;

	if (ctx_adjust_hroom(ctx, sizeof(opt), BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_flags()))
		return DROP_INVALID;
	if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(*ip6), &opt,
			    sizeof(opt), 0) < 0)
		return DROP_INVALID;
	return 0;
}
#elif DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
static __always_inline int encap_geneve_dsr_opt6(struct __ctx_buff *ctx,
						 struct ipv6hdr *ip6,
						 const union v6addr *svc_addr,
						 __be16 svc_port,
						 int *ifindex, int *ohead)
{
	__be16 src_port = tunnel_gen_src_port_v6();
	struct remote_endpoint_info *info;
	struct geneve_dsr_opt6 gopt;
	union v6addr *dst;
	bool need_opt = true;
	__u16 encap_len = sizeof(struct ipv6hdr) + sizeof(struct udphdr) +
		sizeof(struct genevehdr) + ETH_HLEN;
	__u16 payload_len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
	__u32 dst_sec_identity;
	__be32 tunnel_endpoint;
	__u16 total_len = 0;
	__u8 nexthdr = ip6->nexthdr;
	int hdrlen;

	dst = (union v6addr *)&ip6->daddr;
	info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN, 0);
	if (!info || info->tunnel_endpoint == 0)
		return DROP_NO_TUNNEL_ENDPOINT;

	tunnel_endpoint = info->tunnel_endpoint;
	dst_sec_identity = info->sec_identity;

	hdrlen = ipv6_hdrlen(ctx, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	/* See encap_geneve_dsr_opt4(): */
	if (nexthdr == IPPROTO_TCP) {
		union tcp_flags tcp_flags = { .value = 0 };

		if (l4_load_tcp_flags(ctx, ETH_HLEN + hdrlen, &tcp_flags) < 0)
			return DROP_CT_INVALID_HDR;

		if (!(tcp_flags.value & (TCP_FLAG_SYN)))
			need_opt = false;
	}

	if (need_opt) {
		encap_len += sizeof(struct geneve_dsr_opt6);
		set_geneve_dsr_opt6(svc_port, svc_addr, &gopt);
	}

	total_len = encap_len + payload_len;

	if (dsr_is_too_big(ctx, total_len)) {
		*ohead = encap_len;
		return DROP_FRAG_NEEDED;
	}

	if (need_opt)
		return  __encap_with_nodeid_opt(ctx,
						IPV4_DIRECT_ROUTING,
						src_port,
						tunnel_endpoint,
						WORLD_ID,
						dst_sec_identity,
						NOT_VTEP_DST,
						&gopt,
						sizeof(gopt),
						(enum trace_reason)CT_NEW,
						TRACE_PAYLOAD_LEN,
						ifindex);

	return __encap_with_nodeid(ctx,
				   IPV4_DIRECT_ROUTING,
				   src_port,
				   tunnel_endpoint,
				   WORLD_ID,
				   dst_sec_identity,
				   NOT_VTEP_DST,
				   (enum trace_reason)CT_NEW,
				   TRACE_PAYLOAD_LEN,
				   ifindex);
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

			if (nh == NEXTHDR_AUTH)
				len += ipv6_authlen(&opthdr);
			else
				len += ipv6_optlen(&opthdr);

			nh = opthdr.nexthdr;
			break;

		default:
			return 0;
		}
	}

	/* Reached limit of supported extension headers */
	return DROP_INVALID_EXTHDR;
}

static __always_inline int
nodeport_extract_dsr_v6(struct __ctx_buff *ctx,
			struct ipv6hdr *ip6 __maybe_unused,
			const struct ipv6_ct_tuple *tuple, int l4_off,
			union v6addr *addr, __be16 *port, bool *dsr)
{
	struct ipv6_ct_tuple tmp = *tuple;

	if (tuple->nexthdr == IPPROTO_TCP) {
		union tcp_flags tcp_flags = {};

		if (l4_load_tcp_flags(ctx, l4_off, &tcp_flags) < 0)
			return DROP_CT_INVALID_HDR;

		ipv6_ct_tuple_reverse(&tmp);

		if (!(tcp_flags.value & TCP_FLAG_SYN)) {
			*dsr = ct_has_dsr_egress_entry6(get_ct_map6(&tmp), &tmp);
			*port = 0;
			return 0;
		}
	}

#if defined(IS_BPF_OVERLAY)
	{
		struct geneve_dsr_opt6 gopt;
		int ret = ctx_get_tunnel_opt(ctx, &gopt, sizeof(gopt));

		if (ret > 0) {
			if (gopt.hdr.opt_class == bpf_htons(DSR_GENEVE_OPT_CLASS) &&
			    gopt.hdr.type == DSR_GENEVE_OPT_TYPE) {
				*dsr = true;
				*port = gopt.port;
				ipv6_addr_copy(addr, &gopt.addr);
				return 0;
			}
		}
	}
#else
	{
		struct dsr_opt_v6 opt __align_stack_8 = {};
		int ret;

		ret = find_dsr_v6(ctx, ip6->nexthdr, &opt, dsr);
		if (ret != 0)
			return ret;

		if (*dsr) {
			*addr = opt.addr;
			*port = opt.port;
			return 0;
		}
	}
#endif

	if (tuple->nexthdr == IPPROTO_TCP)
		ct_update_dsr(get_ct_map6(&tmp), &tmp, false);

	return 0;
}

static __always_inline int xlate_dsr_v6(struct __ctx_buff *ctx,
					const struct ipv6_ct_tuple *tuple,
					int l4_off)
{
	struct ipv6_ct_tuple nat_tup = *tuple;
	struct ipv6_nat_entry *entry;

	nat_tup.flags = NAT_DIR_EGRESS;
	nat_tup.sport = tuple->dport;
	nat_tup.dport = tuple->sport;

	entry = snat_v6_lookup(&nat_tup);
	if (!entry)
		return 0;

	ctx_snat_done_set(ctx);
	return snat_v6_rewrite_egress(ctx, &nat_tup, entry, l4_off);
}

static __always_inline int dsr_reply_icmp6(struct __ctx_buff *ctx,
					   const struct ipv6hdr *ip6 __maybe_unused,
					   const union v6addr *svc_addr __maybe_unused,
					   __be16 dport __maybe_unused,
					   int code, int ohead __maybe_unused)
{
#ifdef ENABLE_DSR_ICMP_ERRORS
	const __s32 orig_dgram = 64, off = ETH_HLEN;
	__u8 orig_ipv6_hdr[orig_dgram];
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
	struct ipv6hdr inner_ipv6_hdr __align_stack_8 = *ip6;
	__s32 l4_dport_offset;

	/* DSR changes the destination address from service ip to pod ip and
	 * destination port from service port to pod port. While resppnding
	 * back with ICMP error, it is necessary to set it to original ip and
	 * port.
	 */
	ipv6_addr_copy((union v6addr *)&inner_ipv6_hdr.daddr, svc_addr);

	if (inner_ipv6_hdr.nexthdr == IPPROTO_UDP)
		l4_dport_offset = UDP_DPORT_OFF;
	else if (inner_ipv6_hdr.nexthdr == IPPROTO_TCP)
		l4_dport_offset = TCP_DPORT_OFF;
	else
		goto drop_err;

	if (ctx_load_bytes(ctx, off + sizeof(inner_ipv6_hdr), orig_ipv6_hdr,
			   sizeof(orig_ipv6_hdr)) < 0)
		goto drop_err;
	memcpy(orig_ipv6_hdr + l4_dport_offset, &dport, sizeof(dport));

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, reason);

	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		goto drop_err;
	if (eth_load_daddr(ctx, dmac.addr, 0) < 0)
		goto drop_err;
	if (unlikely(data + len_new > data_end))
		goto drop_err;

	wsum = ipv6_pseudohdr_checksum(&ip, IPPROTO_ICMPV6,
				       bpf_ntohs(ip.payload_len), 0);
	icmp.icmp6_cksum = csum_fold(csum_diff(NULL, 0, orig_ipv6_hdr, sizeof(orig_ipv6_hdr),
					       csum_diff(NULL, 0, &inner_ipv6_hdr,
							 sizeof(inner_ipv6_hdr),
							 csum_diff(NULL, 0, &icmp,
								   sizeof(icmp), wsum))));

	if (ctx_adjust_troom(ctx, -(len_old - len_new)) < 0)
		goto drop_err;
	if (ctx_adjust_hroom(ctx, sizeof(ip) + sizeof(icmp),
			     BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_flags()) < 0)
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
	if (ctx_store_bytes(ctx, off + sizeof(ip) + sizeof(icmp), &inner_ipv6_hdr,
			    sizeof(inner_ipv6_hdr), 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, off + sizeof(ip) + sizeof(icmp) +
			    sizeof(inner_ipv6_hdr) + l4_dport_offset,
			    &dport, sizeof(dport), 0) < 0)
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
	int ret, oif = 0, ohead = 0;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr addr;
	__s8 ext_err = 0;
	__be16 port;

	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	addr.p1 = ctx_load_meta(ctx, CB_ADDR_V6_1);
	addr.p2 = ctx_load_meta(ctx, CB_ADDR_V6_2);
	addr.p3 = ctx_load_meta(ctx, CB_ADDR_V6_3);
	addr.p4 = ctx_load_meta(ctx, CB_ADDR_V6_4);

	port = (__be16)ctx_load_meta(ctx, CB_PORT);

#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	ret = dsr_set_ipip6(ctx, ip6, &addr,
			    ctx_load_meta(ctx, CB_HINT), &ohead);
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
	ret = dsr_set_ext6(ctx, ip6, &addr, port, &ohead);
#elif DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
	ret = encap_geneve_dsr_opt6(ctx, ip6, &addr, port, &oif, &ohead);
	if (!IS_ERR(ret)) {
		if (ret == CTX_ACT_REDIRECT && oif) {
			cilium_capture_out(ctx);
			return ctx_redirect(ctx, oif, 0);
		}

		fib_params.l.family = AF_INET;
	}
#else
# error "Invalid load balancer DSR encapsulation mode!"
#endif
	if (IS_ERR(ret)) {
		if (dsr_fail_needs_reply(ret))
			return dsr_reply_icmp6(ctx, ip6, &addr, port, ret, ohead);
		goto drop_err;
	}

	if (fib_params.l.family == AF_INET) {
		struct iphdr *ip4;

		if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto drop_err;
		}

		fib_params.l.ipv4_src = ip4->saddr;
		fib_params.l.ipv4_dst = ip4->daddr;
	} else {
		if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
			ret = DROP_INVALID;
			goto drop_err;
		}

		ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_src,
			       (union v6addr *)&ip6->saddr);
		ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_dst,
			       (union v6addr *)&ip6->daddr);
	}

	ret = fib_redirect(ctx, true, &fib_params, &ext_err, &oif);
	if (fib_ok(ret)) {
		cilium_capture_out(ctx);
		return ret;
	}
drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err,
					  CTX_ACT_DROP, METRIC_EGRESS);
}

declare_tailcall_if(__not(is_defined(IS_BPF_LXC)), CILIUM_CALL_IPV6_NODEPORT_DSR_INGRESS)
int tail_nodeport_dsr_ingress_ipv6(struct __ctx_buff *ctx)
{
	struct ct_state ct_state_new = {};
	struct ipv6_ct_tuple tuple = {};
	struct ct_state ct_state = {};
	union v6addr addr = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u32 monitor = 0;
	bool dsr = false;
	int ret, l4_off;
	__be16 port = 0;
	__s8 ext_err = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	ret = lb6_extract_tuple(ctx, ip6, ETH_HLEN, &l4_off, &tuple);
	if (IS_ERR(ret))
		goto drop_err;

	ret = nodeport_extract_dsr_v6(ctx, ip6, &tuple, l4_off, &addr, &port, &dsr);
	if (IS_ERR(ret))
		goto drop_err;
	if (!dsr) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	ret = ct_lazy_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off, ACTION_CREATE,
			      CT_EGRESS, &ct_state, &monitor);
	switch (ret) {
	case CT_NEW:
	case CT_REOPENED:
create_ct:
		if (port == 0) {
			ret = DROP_INVALID;
			goto drop_err;
		}

		ct_state_new.src_sec_id = WORLD_ID;
		ct_state_new.dsr = 1;
		ct_state_new.ifindex = (__u16)NATIVE_DEV_IFINDEX;
		ret = ct_create6(get_ct_map6(&tuple), NULL, &tuple, ctx,
				 CT_EGRESS, &ct_state_new, false, false, &ext_err);
		if (!IS_ERR(ret))
			ret = snat_v6_create_dsr(&tuple, &addr, port);

		if (IS_ERR(ret))
			goto drop_err;
		break;
	case CT_ESTABLISHED:
		if ((tuple.nexthdr == IPPROTO_TCP && port) || !ct_state.dsr)
			goto create_ct;
		break;
	case CT_REPLY:
		ipv6_ct_tuple_reverse(&tuple);
		goto create_ct;
	default:
		ret = DROP_UNKNOWN_CT;
		goto drop_err;
	}

	ctx_skip_nodeport_set(ctx);
	ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
	ret = DROP_MISSED_TAIL_CALL;

drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err, CTX_ACT_DROP, METRIC_INGRESS);
}
#endif /* ENABLE_DSR */

#ifdef ENABLE_NAT_46X64_GATEWAY
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV46_RFC8215)
int tail_nat_ipv46(struct __ctx_buff *ctx)
{
	int ret, oif = 0, l3_off = ETH_HLEN;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct iphdr *ip4;
	__s8 ext_err = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}
	if (nat46_rfc8215(ctx, ip4, l3_off)) {
		ret = DROP_NAT46;
		goto drop_err;
	}
	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}
	ret = fib_redirect_v6(ctx, l3_off, ip6, false, &ext_err,
			      ctx_get_ifindex(ctx), &oif);
	if (fib_ok(ret)) {
		cilium_capture_out(ctx);
		return ret;
	}
drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err,
					  CTX_ACT_DROP, METRIC_EGRESS);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV64_RFC8215)
int tail_nat_ipv64(struct __ctx_buff *ctx)
{
	int ret, oif = 0, l3_off = ETH_HLEN;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct iphdr *ip4;
	__s8 ext_err = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}
	if (nat64_rfc8215(ctx, ip6)) {
		ret = DROP_NAT64;
		goto drop_err;
	}
	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}
	ret = fib_redirect_v4(ctx, l3_off, ip4, false, &ext_err,
			      ctx_get_ifindex(ctx), &oif);
	if (fib_ok(ret)) {
		cilium_capture_out(ctx);
		return ret;
	}
drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err,
					  CTX_ACT_DROP, METRIC_EGRESS);
}
#endif /* ENABLE_NAT_46X64_GATEWAY */

declare_tailcall_if(__not(is_defined(IS_BPF_LXC)), CILIUM_CALL_IPV6_NODEPORT_NAT_INGRESS)
int tail_nodeport_nat_ingress_ipv6(struct __ctx_buff *ctx)
{
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.src_from_world = true,
	};
	__s8 ext_err = 0;
	int ret;

	ret = snat_v6_rev_nat(ctx, &target, &ext_err);
	if (IS_ERR(ret)) {
		if (ret == NAT_PUNT_TO_STACK ||
		    /* DROP_NAT_NO_MAPPING is unwanted behavior in a
		     * rev-SNAT context. Let's continue to passing it
		     * up to the host and revisiting this later if
		     * needed.
		     */
		    ret == DROP_NAT_NO_MAPPING) {
			/* In case of no mapping, recircle back to
			 * main path. SNAT is very expensive in terms
			 * of instructions and
			 * complexity. Consequently, this is done
			 * inside a tail call here (because we don't
			 * have BPF to BPF calls).
			 */
			ctx_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
			ret = DROP_MISSED_TAIL_CALL;
		}
		goto drop_err;
	}

	ctx_snat_done_set(ctx);

#if !defined(ENABLE_DSR) || (defined(ENABLE_DSR) && defined(ENABLE_DSR_HYBRID))
	ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_REVNAT);
#else
	ctx_skip_nodeport_set(ctx);
	ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
#endif
	ret = DROP_MISSED_TAIL_CALL;

 drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err, CTX_ACT_DROP,
					  METRIC_INGRESS);
}

declare_tailcall_if(__not(is_defined(IS_BPF_LXC)), CILIUM_CALL_IPV6_NODEPORT_NAT_EGRESS)
int tail_nodeport_nat_egress_ipv6(struct __ctx_buff *ctx)
{
	const bool nat_46x64 = nat46x64_cb_xlate(ctx);
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
		.addr = IPV6_DIRECT_ROUTING,
	};
	int ret, oif = 0;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__s8 ext_err = 0;
#ifdef TUNNEL_MODE
	struct remote_endpoint_info *info;
	__be32 tunnel_endpoint = 0;
	__u32 dst_sec_identity = 0;
	union v6addr *dst;
#endif

	if (nat_46x64)
		build_v4_in_v6(&target.addr, IPV4_DIRECT_ROUTING);

#ifdef TUNNEL_MODE
	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	dst = (union v6addr *)&ip6->daddr;
	info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN, 0);
	if (info && info->tunnel_endpoint != 0) {
		tunnel_endpoint = info->tunnel_endpoint;
		dst_sec_identity = info->sec_identity;

		BPF_V6(target.addr, ROUTER_IP);
	}
#endif
	ret = snat_v6_nat(ctx, &target, &ext_err);
	if (IS_ERR(ret) && ret != NAT_PUNT_TO_STACK)
		goto drop_err;

	ctx_snat_done_set(ctx);
#ifdef TUNNEL_MODE
	if (tunnel_endpoint) {
		__be16 src_port = tunnel_gen_src_port_v6();

		ret = __encap_with_nodeid(ctx,
					  IPV4_DIRECT_ROUTING,
					  src_port,
					  tunnel_endpoint,
					  WORLD_ID,
					  dst_sec_identity,
					  NOT_VTEP_DST,
					  (enum trace_reason)CT_NEW,
					  TRACE_PAYLOAD_LEN, &oif);
		if (IS_ERR(ret))
			goto drop_err;

		if (ret == CTX_ACT_REDIRECT && oif) {
			cilium_capture_out(ctx);
			return ctx_redirect(ctx, oif, 0);
		}

		goto fib_ipv4;
	}
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

#ifdef TUNNEL_MODE
fib_ipv4:
#endif
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
	ret = fib_redirect(ctx, true, &fib_params, &ext_err, &oif);
	if (fib_ok(ret)) {
		cilium_capture_out(ctx);
		return ret;
	}
drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err,
					  CTX_ACT_DROP, METRIC_EGRESS);
}

/* See nodeport_lb4(). */
static __always_inline int nodeport_lb6(struct __ctx_buff *ctx,
					__u32 src_sec_identity,
					__s8 *ext_err)
{
	int ret, l3_off = ETH_HLEN, l4_off;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct lb6_service *svc;
	struct lb6_key key = {};
	struct ct_state ct_state_new = {};
	bool backend_local;
	__u32 monitor = 0;

	cilium_capture_in(ctx);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ret = lb6_extract_tuple(ctx, ip6, ETH_HLEN, &l4_off, &tuple);
	if (IS_ERR(ret)) {
		if (ret == DROP_NO_SERVICE)
			goto skip_service_lookup;
		if (ret == DROP_UNKNOWN_L4) {
			ctx_set_xfer(ctx, XFER_PKT_NO_SVC);
			return CTX_ACT_OK;
		}
		return ret;
	}

	lb6_fill_key(&key, &tuple);

	svc = lb6_lookup_service(&key, false, false);
	if (svc) {
		const bool skip_l3_xlate = DSR_ENCAP_MODE == DSR_ENCAP_IPIP;

		if (!lb6_src_range_ok(svc, (union v6addr *)&ip6->saddr))
			return DROP_NOT_IN_SRC_RANGE;

#if defined(ENABLE_L7_LB)
		if (lb6_svc_is_l7loadbalancer(svc) && svc->l7_lb_proxy_port > 0) {
#if __ctx_is == __ctx_xdp
			return CTX_ACT_OK;
#endif
			send_trace_notify(ctx, TRACE_TO_PROXY, src_sec_identity, 0,
					  bpf_ntohs((__u16)svc->l7_lb_proxy_port), 0,
					  TRACE_REASON_POLICY, monitor);
			return ctx_redirect_to_proxy_hairpin_ipv6(ctx,
								  (__be16)svc->l7_lb_proxy_port);
		}
#endif
		ret = lb6_local(get_ct_map6(&tuple), ctx, l3_off, l4_off,
				&key, &tuple, svc, &ct_state_new,
				skip_l3_xlate, ext_err);
		if (IS_ERR(ret))
			return ret;

		if (!lb6_svc_is_routable(svc))
			return DROP_IS_CLUSTER_IP;
	} else {
skip_service_lookup:
#ifdef ENABLE_NAT_46X64_GATEWAY
		if (is_v4_in_v6_rfc8215((union v6addr *)&ip6->daddr)) {
			ret = neigh_record_ip6(ctx);
			if (ret < 0)
				return ret;
			if (is_v4_in_v6_rfc8215((union v6addr *)&ip6->saddr)) {
				ep_tail_call(ctx, CILIUM_CALL_IPV64_RFC8215);
			} else {
				ctx_store_meta(ctx, CB_NAT_46X64, NAT46x64_MODE_XLATE);
				ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT_EGRESS);
			}
			return DROP_MISSED_TAIL_CALL;
		}
#endif
		ctx_set_xfer(ctx, XFER_PKT_NO_SVC);

#ifdef ENABLE_DSR
		if (nodeport_uses_dsr6(&tuple)) {
#if (defined(IS_BPF_OVERLAY) && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE) || \
	(!defined(IS_BPF_OVERLAY) && DSR_ENCAP_MODE != DSR_ENCAP_GENEVE)
			bool dsr = false;

			ret = nodeport_extract_dsr_v6(ctx, ip6, &tuple, l4_off,
						      &key.address,
						      &key.dport, &dsr);
			if (dsr) {
				ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
				ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_DSR_INGRESS);
				return DROP_MISSED_TAIL_CALL;
			}

			if (IS_ERR(ret))
				return ret;
#endif
			return CTX_ACT_OK;
		}
#endif /* ENABLE_DSR */

		ctx_store_meta(ctx, CB_NAT_46X64, 0);
		ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
		ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT_INGRESS);
		return DROP_MISSED_TAIL_CALL;
	}

	backend_local = __lookup_ip6_endpoint(&tuple.daddr);
	if (!backend_local && lb6_svc_is_hostport(svc))
		return DROP_INVALID;
	if (backend_local || !nodeport_uses_dsr6(&tuple)) {
		struct ct_state ct_state = {};

		ret = ct_lazy_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off, ACTION_CREATE,
				      CT_EGRESS, &ct_state, &monitor);
		switch (ret) {
		case CT_REPLY:
			ipv6_ct_tuple_reverse(&tuple);
		case CT_NEW:
redo:
			ct_state_new.src_sec_id = WORLD_ID;
			ct_state_new.node_port = 1;
			ct_state_new.ifindex = (__u16)NATIVE_DEV_IFINDEX;
			ret = ct_create6(get_ct_map6(&tuple), NULL, &tuple, ctx,
					 CT_EGRESS, &ct_state_new, false, false, ext_err);
			if (IS_ERR(ret))
				return ret;
			break;
		case CT_REOPENED:
		case CT_ESTABLISHED:
			if (unlikely(ct_state.rev_nat_index !=
				     ct_state_new.rev_nat_index))
				goto redo;
			break;
		default:
			return DROP_UNKNOWN_CT;
		}

		if (backend_local) {
			ctx_set_xfer(ctx, XFER_PKT_NO_SVC);
			return CTX_ACT_OK;
		}

		ret = neigh_record_ip6(ctx);
		if (ret < 0)
			return ret;
	}

	/* TX request to remote backend: */
	edt_set_aggregate(ctx, 0);
	if (nodeport_uses_dsr6(&tuple)) {
#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
		ctx_store_meta(ctx, CB_HINT,
			       ((__u32)tuple.sport << 16) | tuple.dport);
		ctx_store_meta(ctx, CB_ADDR_V6_1, tuple.daddr.p1);
		ctx_store_meta(ctx, CB_ADDR_V6_2, tuple.daddr.p2);
		ctx_store_meta(ctx, CB_ADDR_V6_3, tuple.daddr.p3);
		ctx_store_meta(ctx, CB_ADDR_V6_4, tuple.daddr.p4);
#elif DSR_ENCAP_MODE == DSR_ENCAP_GENEVE || DSR_ENCAP_MODE == DSR_ENCAP_NONE
		ctx_store_meta(ctx, CB_PORT, key.dport);
		ctx_store_meta(ctx, CB_ADDR_V6_1, key.address.p1);
		ctx_store_meta(ctx, CB_ADDR_V6_2, key.address.p2);
		ctx_store_meta(ctx, CB_ADDR_V6_3, key.address.p3);
		ctx_store_meta(ctx, CB_ADDR_V6_4, key.address.p4);
#endif /* DSR_ENCAP_MODE */
		ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_DSR);
	} else {
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
		ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT_EGRESS);
	}
	return DROP_MISSED_TAIL_CALL;
}

static __always_inline int
nodeport_rev_dnat_fwd_ipv6(struct __ctx_buff *ctx, struct trace_ctx *trace)
{
	struct ipv6_ct_tuple tuple = {};
	struct ct_state ct_state = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, l4_off;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ret = lb6_extract_tuple(ctx, ip6, ETH_HLEN, &l4_off, &tuple);
	if (ret < 0) {
		if (ret == DROP_NO_SERVICE || ret == DROP_UNKNOWN_L4)
			return CTX_ACT_OK;
		return ret;
	}

	if (!ct_has_nodeport_egress_entry6(get_ct_map6(&tuple), &tuple,
					   is_defined(ENABLE_DSR)))
		return CTX_ACT_OK;

	ret = ct_lazy_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off, ACTION_CREATE,
			      CT_INGRESS, &ct_state, &trace->monitor);
	if (ret == CT_REPLY) {
		trace->reason = TRACE_REASON_CT_REPLY;

		if (ct_state.node_port && ct_state.rev_nat_index) {
			ret = lb6_rev_nat(ctx, l4_off, ct_state.rev_nat_index,
					  &tuple, REV_NAT_F_TUPLE_SADDR);
			if (IS_ERR(ret))
				return ret;

			ctx_snat_done_set(ctx);
#ifdef ENABLE_DSR
		} else if (ct_state.dsr) {
			ret = xlate_dsr_v6(ctx, &tuple, l4_off);
			if (IS_ERR(ret))
				return ret;
#endif
		}
	}

	return CTX_ACT_OK;
}

static __always_inline int rev_nodeport_lb6(struct __ctx_buff *ctx, __s8 *ext_err)
{
	enum trace_reason __maybe_unused reason = TRACE_REASON_CT_REPLY;
#ifdef ENABLE_NAT_46X64_GATEWAY
	const bool nat_46x64_fib = nat46x64_cb_route(ctx);
#endif
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET6,
			.ifindex	= ctx_get_ifindex(ctx),
		},
	};
	int ret, l4_off;
	struct ipv6_ct_tuple tuple = {};
	struct ct_state ct_state = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u32 monitor = TRACE_PAYLOAD_LEN;
	__u32 tunnel_endpoint __maybe_unused = 0;
	__u32 dst_sec_identity __maybe_unused = 0;
	__be16 src_port __maybe_unused = 0;
	int ifindex = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;
#ifdef ENABLE_NAT_46X64_GATEWAY
	if (nat_46x64_fib)
		goto fib_lookup;
#endif
	ret = lb6_extract_tuple(ctx, ip6, ETH_HLEN, &l4_off, &tuple);
	if (ret < 0) {
		if (ret == DROP_NO_SERVICE || ret == DROP_UNKNOWN_L4)
			goto out;
		return ret;
	}

	if (!ct_has_nodeport_egress_entry6(get_ct_map6(&tuple), &tuple, false))
		goto out;

	ret = ct_lazy_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off, ACTION_CREATE,
			      CT_INGRESS, &ct_state, &monitor);
	if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {
		ret = lb6_rev_nat(ctx, l4_off, ct_state.rev_nat_index,
				  &tuple, REV_NAT_F_TUPLE_SADDR);
		if (IS_ERR(ret))
			return ret;
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
		ctx_snat_done_set(ctx);
		ifindex = ct_state.ifindex;
#ifdef TUNNEL_MODE
		{
			union v6addr *dst = (union v6addr *)&ip6->daddr;
			struct remote_endpoint_info *info;

			info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN, 0);
			if (info != NULL && info->tunnel_endpoint != 0) {
				tunnel_endpoint = info->tunnel_endpoint;
				dst_sec_identity = info->sec_identity;
				goto encap_redirect;
			}
		}
#endif

		goto fib_lookup;
	}
out:
	if (bpf_skip_recirculation(ctx))
		return DROP_NAT_NO_MAPPING;

	ctx_skip_nodeport_set(ctx);
	ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
	return DROP_MISSED_TAIL_CALL;
#ifdef TUNNEL_MODE
encap_redirect:
	src_port = tunnel_gen_src_port_v6();

	ret = __encap_with_nodeid(ctx, IPV4_DIRECT_ROUTING, src_port,
				  tunnel_endpoint, SECLABEL, dst_sec_identity,
				  NOT_VTEP_DST, reason, monitor, &ifindex);
	if (IS_ERR(ret))
		return ret;

	if (ret == CTX_ACT_REDIRECT && ifindex)
		return ctx_redirect(ctx, ifindex, 0);

	goto fib_ipv4;
#endif

fib_lookup:
	if (is_v4_in_v6((union v6addr *)&ip6->saddr)) {
		struct iphdr *ip4;

		ret = lb6_to_lb4(ctx, ip6);
		if (ret < 0)
			return ret;

#ifdef TUNNEL_MODE
fib_ipv4:
#endif
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		fib_params.l.ipv4_src = ip4->saddr;
		fib_params.l.ipv4_dst = ip4->daddr;
		fib_params.l.family = AF_INET;
	} else {
		ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_src,
			       (union v6addr *)&ip6->saddr);
		ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_dst,
			       (union v6addr *)&ip6->daddr);
	}
	return fib_redirect(ctx, true, &fib_params, ext_err, &ifindex);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_REVNAT)
int tail_rev_nodeport_lb6(struct __ctx_buff *ctx)
{
	__s8 ext_err = 0;
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

	ret = ipv6_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);
	/* We don't want to enforce host policies a second time if we jump back to
	 * bpf_host's handle_ipv6.
	 */
	ctx_skip_host_fw_set(ctx);
#endif
	ret = rev_nodeport_lb6(ctx, &ext_err);
	if (IS_ERR(ret))
		goto drop;
	edt_set_aggregate(ctx, 0);
	cilium_capture_out(ctx);
	return ret;
drop:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err, CTX_ACT_DROP, METRIC_EGRESS);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_SNAT_FWD)
int tail_handle_snat_fwd_ipv6(struct __ctx_buff *ctx)
{
	enum trace_point obs_point;
	int ret;
	__s8 ext_err = 0;
#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
	union v6addr addr = { .p1 = 0 };

	BPF_V6(addr, ROUTER_IP);
#else
	union v6addr addr = IPV6_DIRECT_ROUTING;
#endif

#ifdef IS_BPF_OVERLAY
	obs_point = TRACE_TO_OVERLAY;
#else
	obs_point = TRACE_TO_NETWORK;
#endif

	ret = nodeport_snat_fwd_ipv6(ctx, &addr, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, 0, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);

	send_trace_notify(ctx, obs_point, 0, 0, 0, 0, TRACE_REASON_UNKNOWN, 0);

	return ret;
}

static __always_inline int
__handle_nat_fwd_ipv6(struct __ctx_buff *ctx, struct trace_ctx *trace)
{
	int ret;

	ret = nodeport_rev_dnat_fwd_ipv6(ctx, trace);
	if (IS_ERR(ret))
		return ret;

#if !defined(ENABLE_DSR) ||						\
    (defined(ENABLE_DSR) && defined(ENABLE_DSR_HYBRID))
	if (!ctx_snat_done(ctx)) {
		ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_SNAT_FWD);
		ret = DROP_MISSED_TAIL_CALL;
	}
#endif

	return ret;
}

static __always_inline int handle_nat_fwd_ipv6(struct __ctx_buff *ctx)
{
	struct trace_ctx trace;

	return __handle_nat_fwd_ipv6(ctx, &trace);
}

declare_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
			       is_defined(ENABLE_IPV6)),
			 __and(is_defined(ENABLE_HOST_FIREWALL),
			       is_defined(IS_BPF_HOST))),
		    CILIUM_CALL_IPV6_NODEPORT_NAT_FWD)
int tail_handle_nat_fwd_ipv6(struct __ctx_buff *ctx)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	int ret;
	enum trace_point obs_point;

#ifdef IS_BPF_OVERLAY
	obs_point = TRACE_TO_OVERLAY;
#else
	obs_point = TRACE_TO_NETWORK;
#endif

	ret = handle_nat_fwd_ipv6(ctx);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);

	send_trace_notify(ctx, obs_point, 0, 0, 0, 0, trace.reason,
			  trace.monitor);

	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline bool nodeport_uses_dsr4(const struct ipv4_ct_tuple *tuple)
{
	return nodeport_uses_dsr(tuple->nexthdr);
}

static __always_inline int nodeport_snat_fwd_ipv4(struct __ctx_buff *ctx,
						  __u32 cluster_id __maybe_unused,
						  __s8 *ext_err)
{
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.addr = 0, /* set by snat_v4_prepare_state() */
		.egress_gateway = 0,
#if defined(ENABLE_CLUSTER_AWARE_ADDRESSING) && defined(ENABLE_INTER_CLUSTER_SNAT)
		.cluster_id = cluster_id,
#endif
	};
	int ret = CTX_ACT_OK;
	bool snat_needed;

	snat_needed = snat_v4_prepare_state(ctx, &target);
	if (snat_needed)
		ret = snat_v4_nat(ctx, &target, ext_err);
	if (ret == NAT_PUNT_TO_STACK)
		ret = CTX_ACT_OK;

	/* If multiple netdevs process an outgoing packet, then this packets will
	 * be handled multiple times by the "to-netdev" section. This can lead
	 * to multiple SNATs. To prevent from that, set the SNAT done flag.
	 */
	ctx_snat_done_set(ctx);

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
			     ctx_adjust_hroom_flags()))
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
	if (ipv4_csum_update_by_diff(ctx, l3_off, sum) < 0)
		return DROP_CSUM_L3;
	return 0;
}
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
static __always_inline int dsr_set_opt4(struct __ctx_buff *ctx,
					struct iphdr *ip4, __be32 svc_addr,
					__be16 svc_port, __be16 *ohead)
{
	__u32 iph_old, iph_new;
	struct dsr_opt_v4 opt;
	__u16 tot_len = bpf_ntohs(ip4->tot_len) + sizeof(opt);
	__be32 sum;

	if (ip4->protocol == IPPROTO_TCP) {
		union tcp_flags tcp_flags = { .value = 0 };

		if (l4_load_tcp_flags(ctx, ETH_HLEN + ipv4_hdrlen(ip4), &tcp_flags) < 0)
			return DROP_CT_INVALID_HDR;

		/* Setting the option is required only for the first packet
		 * (SYN), in the case of TCP, as for further packets of the
		 * same connection a remote node will use a NAT entry to
		 * reverse xlate a reply.
		 */
		if (!(tcp_flags.value & (TCP_FLAG_SYN)))
			return 0;
	}

	if (ipv4_hdrlen(ip4) + sizeof(opt) > sizeof(struct iphdr) + MAX_IPOPTLEN)
		return DROP_CT_INVALID_HDR;

	if (dsr_is_too_big(ctx, tot_len)) {
		*ohead = sizeof(opt);
		return DROP_FRAG_NEEDED;
	}

	iph_old = *(__u32 *)ip4;
	ip4->ihl += sizeof(opt) >> 2;
	ip4->tot_len = bpf_htons(tot_len);
	iph_new = *(__u32 *)ip4;

	opt.type = DSR_IPV4_OPT_TYPE;
	opt.len = sizeof(opt);
	opt.port = bpf_htons(svc_port);
	opt.addr = bpf_htonl(svc_addr);

	sum = csum_diff(&iph_old, 4, &iph_new, 4, 0);
	sum = csum_diff(NULL, 0, &opt, sizeof(opt), sum);

	if (ctx_adjust_hroom(ctx, sizeof(opt), BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_flags()))
		return DROP_INVALID;

	if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(*ip4),
			    &opt, sizeof(opt), 0) < 0)
		return DROP_INVALID;
	if (ipv4_csum_update_by_diff(ctx, ETH_HLEN, sum) < 0)
		return DROP_CSUM_L3;

	return 0;
}
#elif DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
static __always_inline int encap_geneve_dsr_opt4(struct __ctx_buff *ctx,
						 struct iphdr *ip4, __be32 svc_addr,
						 __be16 svc_port, int *ifindex, __be16 *ohead)
{
	__be16 src_port = tunnel_gen_src_port_v4();
	struct geneve_dsr_opt4 gopt;
	bool need_opt = true;
	__u16 encap_len = sizeof(struct iphdr) + sizeof(struct udphdr) +
		sizeof(struct genevehdr) + ETH_HLEN;
	__u32 dst_sec_identity;
	__be32 tunnel_endpoint;
	__u16 total_len = 0;

#ifdef ENABLE_HIGH_SCALE_IPCACHE
	tunnel_endpoint = ip4->daddr;
	dst_sec_identity = 0;
#else
	struct remote_endpoint_info *info;

	info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN, 0);
	if (!info || info->tunnel_endpoint == 0)
		return DROP_NO_TUNNEL_ENDPOINT;

	tunnel_endpoint = info->tunnel_endpoint;
	dst_sec_identity = info->sec_identity;
#endif

	if (ip4->protocol == IPPROTO_TCP) {
		union tcp_flags tcp_flags = { .value = 0 };

		if (l4_load_tcp_flags(ctx, ETH_HLEN + ipv4_hdrlen(ip4), &tcp_flags) < 0)
			return DROP_CT_INVALID_HDR;

		/* The GENEVE option is required only for the first packet
		 * (SYN), in the case of TCP, as for further packets of the
		 * same connection a remote node will use a NAT entry to
		 * reverse xlate a reply.
		 */
		if (!(tcp_flags.value & (TCP_FLAG_SYN)))
			need_opt = false;
	}

	if (need_opt) {
		encap_len += sizeof(struct geneve_dsr_opt4);
		set_geneve_dsr_opt4(svc_port, svc_addr, &gopt);
	}

	total_len = encap_len + bpf_ntohs(ip4->tot_len);

	if (dsr_is_too_big(ctx, total_len)) {
		*ohead = encap_len;
		return DROP_FRAG_NEEDED;
	}

	if (need_opt)
		return  __encap_with_nodeid_opt(ctx,
						IPV4_DIRECT_ROUTING,
						src_port,
						tunnel_endpoint,
						WORLD_ID,
						dst_sec_identity,
						NOT_VTEP_DST,
						&gopt,
						sizeof(gopt),
						(enum trace_reason)CT_NEW,
						TRACE_PAYLOAD_LEN,
						ifindex);

	return __encap_with_nodeid(ctx,
				   IPV4_DIRECT_ROUTING,
				   src_port,
				   tunnel_endpoint,
				   WORLD_ID,
				   dst_sec_identity,
				   NOT_VTEP_DST,
				   (enum trace_reason)CT_NEW,
				   TRACE_PAYLOAD_LEN,
				   ifindex);
}
#endif /* DSR_ENCAP_MODE */

static __always_inline int
nodeport_extract_dsr_v4(struct __ctx_buff *ctx,
			const struct iphdr *ip4 __maybe_unused,
			const struct ipv4_ct_tuple *tuple, int l4_off,
			__be32 *addr, __be16 *port, bool *dsr)
{
	struct ipv4_ct_tuple tmp = *tuple;

	/* Parse DSR info from the packet, to get the addr/port of the
	 * addressed service. We need this for RevDNATing the backend's replies.
	 *
	 * TCP connections have the DSR Option only in their SYN packet.
	 * To identify that a non-SYN packet belongs to a DSR connection,
	 * we need to check whether a corresponding CT entry with .dsr flag exists.
	 */
	if (tuple->nexthdr == IPPROTO_TCP) {
		union tcp_flags tcp_flags = {};

		if (l4_load_tcp_flags(ctx, l4_off, &tcp_flags) < 0)
			return DROP_CT_INVALID_HDR;

		ipv4_ct_tuple_reverse(&tmp);

		if (!(tcp_flags.value & TCP_FLAG_SYN)) {
			/* If the packet belongs to a tracked DSR connection,
			 * trigger a CT update.
			 * We don't have any DSR info to report back, and that's ok.
			 */
			*dsr = ct_has_dsr_egress_entry4(get_ct_map4(&tmp), &tmp);
			*port = 0;
			return 0;
		}
	}

#if defined(IS_BPF_OVERLAY)
	{
		struct geneve_dsr_opt4 gopt;
		int ret = 0;

		ret = ctx_get_tunnel_opt(ctx, &gopt, sizeof(gopt));

		if (ret > 0) {
			if (gopt.hdr.opt_class == bpf_htons(DSR_GENEVE_OPT_CLASS) &&
			    gopt.hdr.type == DSR_GENEVE_OPT_TYPE) {
				*dsr = true;
				*port = gopt.port;
				*addr = gopt.addr;
				return 0;
			}
		}
	}
#else
	/* Check whether IPv4 header contains a 64-bit option (IPv4 header
	 * w/o option (5 x 32-bit words) + the DSR option (2 x 32-bit words)).
	 */
	if (ip4->ihl >= 0x7) {
		struct dsr_opt_v4 opt;

		if (ctx_load_bytes(ctx, ETH_HLEN + sizeof(struct iphdr),
				   &opt, sizeof(opt)) < 0)
			return DROP_INVALID;

		if (opt.type == DSR_IPV4_OPT_TYPE && opt.len == sizeof(opt)) {
			*dsr = true;
			*addr = bpf_ntohl(opt.addr);
			*port = bpf_ntohs(opt.port);
			return 0;
		}
	}
#endif

	/* SYN for a new connection that's not / no longer DSR.
	 * If it's reopened, avoid sending subsequent traffic down the DSR path.
	 */
	if (tuple->nexthdr == IPPROTO_TCP)
		ct_update_dsr(get_ct_map4(&tmp), &tmp, false);

	return 0;
}

static __always_inline int xlate_dsr_v4(struct __ctx_buff *ctx,
					const struct ipv4_ct_tuple *tuple,
					int l4_off, bool has_l4_header)
{
	struct ipv4_ct_tuple nat_tup = *tuple;
	struct ipv4_nat_entry *entry;

	nat_tup.flags = NAT_DIR_EGRESS;
	nat_tup.sport = tuple->dport;
	nat_tup.dport = tuple->sport;

	entry = snat_v4_lookup(&nat_tup);
	if (!entry)
		return 0;

	ctx_snat_done_set(ctx);
	return snat_v4_rewrite_egress(ctx, &nat_tup, entry, l4_off, has_l4_header);
}

static __always_inline int dsr_reply_icmp4(struct __ctx_buff *ctx,
					   struct iphdr *ip4 __maybe_unused,
					   __be32 svc_addr __maybe_unused,
					   __be16 dport __maybe_unused,
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

	struct iphdr inner_ip_hdr __align_stack_8 = *ip4;
	__s32 l4_dport_offset;

	/* DSR changes the destination address from service ip to pod ip and
	 * destination port from service port to pod port. While resppnding
	 * back with ICMP error, it is necessary to set it to original ip and
	 * port.
	 * We do recompute the whole checksum here. Another way would be to
	 * unfold checksum and then do the math adding the diff.
	 */
	inner_ip_hdr.daddr = svc_addr;
	inner_ip_hdr.check = 0;
	inner_ip_hdr.check = csum_fold(csum_diff(NULL, 0, &inner_ip_hdr,
						 sizeof(inner_ip_hdr), 0));

	if (inner_ip_hdr.protocol == IPPROTO_UDP)
		l4_dport_offset = UDP_DPORT_OFF;
	else if (inner_ip_hdr.protocol == IPPROTO_TCP)
		l4_dport_offset = TCP_DPORT_OFF;

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

	memcpy(tmp, &inner_ip_hdr, sizeof(inner_ip_hdr));
	memcpy(tmp + sizeof(inner_ip_hdr) + l4_dport_offset, &dport, sizeof(dport));

	icmp.checksum = csum_fold(csum_diff(NULL, 0, tmp, sizeof(tmp),
					    csum_diff(NULL, 0, &icmp,
						      sizeof(icmp), 0)));

	if (ctx_adjust_troom(ctx, -(len_old - len_new)) < 0)
		goto drop_err;
	if (ctx_adjust_hroom(ctx, sizeof(ip) + sizeof(icmp),
			     BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_flags()) < 0)
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
	if (ctx_store_bytes(ctx, off + sizeof(ip) + sizeof(icmp),
			    &inner_ip_hdr, sizeof(inner_ip_hdr), 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, off + sizeof(ip) + sizeof(icmp)
			    + sizeof(inner_ip_hdr) + l4_dport_offset,
			    &dport, sizeof(dport), 0) < 0)
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
	void *data, *data_end;
	struct iphdr *ip4;
	int ret, oif = 0;
	__be16 ohead = 0;
	__s8 ext_err = 0;
	__be32 addr;
	__be16 port;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}
	addr = ctx_load_meta(ctx, CB_ADDR_V4);
	port = (__be16)ctx_load_meta(ctx, CB_PORT);

#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	ret = dsr_set_ipip4(ctx, ip4,
			    addr,
			    ctx_load_meta(ctx, CB_HINT), &ohead);
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
	ret = dsr_set_opt4(ctx, ip4,
			   addr,
			   port, &ohead);
#elif DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
	ret = encap_geneve_dsr_opt4(ctx, ip4, addr, port, &oif, &ohead);
	if (!IS_ERR(ret)) {
		if (ret == CTX_ACT_REDIRECT && oif) {
			cilium_capture_out(ctx);
			return ctx_redirect(ctx, oif, 0);
		}
	}
#else
# error "Invalid load balancer DSR encapsulation mode!"
#endif
	if (IS_ERR(ret)) {
		if (dsr_fail_needs_reply(ret))
			return dsr_reply_icmp4(ctx, ip4, addr, port, ret, ohead);
		goto drop_err;
	}
	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}
	ret = fib_redirect_v4(ctx, ETH_HLEN, ip4, true, &ext_err,
			      ctx_get_ifindex(ctx), &oif);
	if (fib_ok(ret)) {
		cilium_capture_out(ctx);
		return ret;
	}
drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err,
					  CTX_ACT_DROP, METRIC_EGRESS);
}

declare_tailcall_if(__not(is_defined(IS_BPF_LXC)), CILIUM_CALL_IPV4_NODEPORT_DSR_INGRESS)
int tail_nodeport_dsr_ingress_ipv4(struct __ctx_buff *ctx)
{
	struct ct_state ct_state_new = {};
	struct ipv4_ct_tuple tuple = {};
	struct ct_state ct_state = {};
	void *data, *data_end;
	bool has_l4_header;
	struct iphdr *ip4;
	__u32 monitor = 0;
	bool dsr = false;
	int ret, l4_off;
	__be32 addr = 0;
	__be16 port = 0;
	__s8 ext_err = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	has_l4_header = ipv4_has_l4_header(ip4);

	ret = lb4_extract_tuple(ctx, ip4, ETH_HLEN, &l4_off, &tuple);
	if (IS_ERR(ret))
		goto drop_err;

	ret = nodeport_extract_dsr_v4(ctx, ip4, &tuple, l4_off, &addr, &port, &dsr);
	if (IS_ERR(ret))
		goto drop_err;
	if (!dsr) {
		/* nodeport_lb4() already determined that the packet belongs
		 * to a DSR connection.
		 */
		ret = DROP_INVALID;
		goto drop_err;
	}

	ret = ct_lazy_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off,
			      has_l4_header, ACTION_CREATE, CT_EGRESS, &ct_state, &monitor);
	switch (ret) {
	case CT_NEW:
	/* Maybe we can be a bit more selective about CT_REOPENED?
	 * But we have to assume that both the CT and the SNAT entry are stale.
	 */
	case CT_REOPENED:
create_ct:
		if (port == 0) {
			/* Not expected at all - nodeport_extract_dsr_v4() said
			 * there would be a CT entry! Without DSR info we can't
			 * do anything smart here.
			 */
			ret = DROP_INVALID;
			goto drop_err;
		}

		ct_state_new.src_sec_id = WORLD_ID;
		ct_state_new.dsr = 1;
		ct_state_new.ifindex = (__u16)NATIVE_DEV_IFINDEX;
		ret = ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx,
				 CT_EGRESS, &ct_state_new, false, false, &ext_err);
		if (!IS_ERR(ret))
			ret = snat_v4_create_dsr(&tuple, addr, port);

		if (IS_ERR(ret))
			goto drop_err;
		break;
	case CT_ESTABLISHED:
		/* For TCP we only expect DSR info on the SYN, so CT_ESTABLISHED
		 * is unexpected and we need to refresh the CT entry.
		 *
		 * Otherwise we tolerate DSR info on an established connection.
		 * TODO: how do we know if we need to refresh the SNAT entry?
		 */
		if ((tuple.nexthdr == IPPROTO_TCP && port) || !ct_state.dsr)
			goto create_ct;
		break;
	case CT_REPLY:
		/* We're not expecting DSR info on replies, must be a stale flow.
		 * Recreate the CT entry.
		 */
		ipv4_ct_tuple_reverse(&tuple);
		goto create_ct;
	default:
		ret = DROP_UNKNOWN_CT;
		goto drop_err;
	}

	/* Recircle, so packet can continue on its way to the local backend: */
	ctx_skip_nodeport_set(ctx);
	ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_NETDEV);
	ret = DROP_MISSED_TAIL_CALL;

drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err, CTX_ACT_DROP, METRIC_INGRESS);
}
#endif /* ENABLE_DSR */

declare_tailcall_if(__not(is_defined(IS_BPF_LXC)), CILIUM_CALL_IPV4_NODEPORT_NAT_INGRESS)
int tail_nodeport_nat_ingress_ipv4(struct __ctx_buff *ctx)
{
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.src_from_world = true,
	};
	__s8 ext_err = 0;
	int ret;

	ret = snat_v4_rev_nat(ctx, &target, &ext_err);
	if (IS_ERR(ret)) {
		if (ret == NAT_PUNT_TO_STACK ||
		    /* DROP_NAT_NO_MAPPING is unwanted behavior in a
		     * rev-SNAT context. Let's continue to passing it up
		     * to the host and revisiting this later if
		     * needed.
		     */
		    ret == DROP_NAT_NO_MAPPING) {
			/* In case of no mapping, recircle back to
			 * main path. SNAT is very expensive in terms
			 * of instructions and
			 * complexity. Consequently, this is done
			 * inside a tail call here (because we don't
			 * have BPF to BPF calls).
			 */
			ctx_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_NETDEV);
			ret = DROP_MISSED_TAIL_CALL;
		}
		goto drop_err;
	}

	ctx_snat_done_set(ctx);

	/* At this point we know that a reverse SNAT mapping exists.
	 * Otherwise, we would have tail-called back to
	 * CALL_IPV4_FROM_NETDEV in the code above.
	 */
#if !defined(ENABLE_DSR) || (defined(ENABLE_DSR) && defined(ENABLE_DSR_HYBRID)) ||	\
    (defined(ENABLE_EGRESS_GATEWAY) && !defined(TUNNEL_MODE))
	/* If we're not in full DSR mode, reply traffic from remote backends
	 * might pass back through the LB node and requires revDNAT.
	 *
	 * Also let rev_nodeport_lb4() redirect EgressGW reply traffic into
	 * tunnel (see there for details).
	 */
	ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_REVNAT);
#else
	/* There's no reason to continue in the RevDNAT path, just recircle back. */
	ctx_skip_nodeport_set(ctx);
	ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_NETDEV);
#endif
	ret = DROP_MISSED_TAIL_CALL;

 drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err, CTX_ACT_DROP,
					  METRIC_INGRESS);
}

declare_tailcall_if(__not(is_defined(IS_BPF_LXC)), CILIUM_CALL_IPV4_NODEPORT_NAT_EGRESS)
int tail_nodeport_nat_egress_ipv4(struct __ctx_buff *ctx)
{
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.src_from_world = true,
		/* Unfortunately, the bpf_fib_lookup() is not able to set src IP addr.
		 * So we need to assume that the direct routing device is going to be
		 * used to fwd the NodePort request, thus SNAT-ing to its IP addr.
		 * This will change once we have resolved GH#17158.
		 */
		.addr = IPV4_DIRECT_ROUTING,
	};
	int ret, oif = 0;
	void *data, *data_end;
	struct iphdr *ip4;
	__s8 ext_err = 0;
#ifdef TUNNEL_MODE
	struct remote_endpoint_info *info;
	__be32 tunnel_endpoint = 0;
	__u32 dst_sec_identity = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN, 0);
	if (info && info->tunnel_endpoint != 0) {
		tunnel_endpoint = info->tunnel_endpoint;
		dst_sec_identity = info->sec_identity;

		target.addr = IPV4_GATEWAY;
	}
#endif
	ret = snat_v4_nat(ctx, &target, &ext_err);
	if (IS_ERR(ret) && ret != NAT_PUNT_TO_STACK)
		goto drop_err;

	ctx_snat_done_set(ctx);
#ifdef TUNNEL_MODE
	if (tunnel_endpoint) {
		__be16 src_port = tunnel_gen_src_port_v4();

		/* The request came from outside, so we need to
		 * set the security id in the tunnel header to WORLD_ID.
		 * Otherwise, the remote node will assume, that the
		 * request originated from a cluster node which will
		 * bypass any netpol which disallows LB requests from
		 * outside.
		 */
		ret = __encap_with_nodeid(ctx,
					  IPV4_DIRECT_ROUTING,
					  src_port,
					  tunnel_endpoint,
					  WORLD_ID,
					  dst_sec_identity,
					  NOT_VTEP_DST,
					  (enum trace_reason)CT_NEW,
					  TRACE_PAYLOAD_LEN, &oif);
		if (IS_ERR(ret))
			goto drop_err;

		if (ret == CTX_ACT_REDIRECT && oif) {
			cilium_capture_out(ctx);
			return ctx_redirect(ctx, oif, 0);
		}
	}
#endif
	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	ret = fib_redirect_v4(ctx, ETH_HLEN, ip4, true, &ext_err,
			      ctx_get_ifindex(ctx), &oif);
	if (fib_ok(ret)) {
		cilium_capture_out(ctx);
		return ret;
	}
drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err,
					  CTX_ACT_DROP, METRIC_EGRESS);
}

/* Main node-port entry point for host-external ingressing node-port traffic
 * which handles the case of: i) backend is local EP, ii) backend is remote EP,
 * iii) reply from remote backend EP.
 */
static __always_inline int nodeport_lb4(struct __ctx_buff *ctx,
					__u32 src_sec_identity,
					__s8 *ext_err)
{
	bool backend_local, has_l4_header;
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	int ret,  l3_off = ETH_HLEN, l4_off;
	bool is_svc_proto = true;
	struct lb4_service *svc;
	struct lb4_key key = {};
	struct ct_state ct_state_new = {};
	__u32 cluster_id = 0;
	__u32 monitor = 0;

	cilium_capture_in(ctx);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	has_l4_header = ipv4_has_l4_header(ip4);

	ret = lb4_extract_tuple(ctx, ip4, ETH_HLEN, &l4_off, &tuple);
	if (IS_ERR(ret)) {
		if (ret == DROP_NO_SERVICE) {
			is_svc_proto = false;
			goto skip_service_lookup;
		}
		if (ret == DROP_UNKNOWN_L4) {
			ctx_set_xfer(ctx, XFER_PKT_NO_SVC);
			return CTX_ACT_OK;
		}
		return ret;
	}

	lb4_fill_key(&key, &tuple);

	svc = lb4_lookup_service(&key, false, false);
	if (svc) {
		const bool skip_l3_xlate = DSR_ENCAP_MODE == DSR_ENCAP_IPIP;

		if (!lb4_src_range_ok(svc, ip4->saddr))
			return DROP_NOT_IN_SRC_RANGE;
#if defined(ENABLE_L7_LB)
		if (lb4_svc_is_l7loadbalancer(svc) && svc->l7_lb_proxy_port > 0) {
#if __ctx_is == __ctx_xdp
			/* We cannot redirect from the XDP layer to cilium_host.
			 * Therefore, let the bpf_host to handle the L7 ingress
			 * request.
			 */
			return CTX_ACT_OK;
#endif
			send_trace_notify(ctx, TRACE_TO_PROXY, src_sec_identity, 0,
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
					&key, &tuple, svc, &ct_state_new,
					has_l4_header, skip_l3_xlate, &cluster_id,
					ext_err);
		}
		if (IS_ERR(ret))
			return ret;

		if (!lb4_svc_is_routable(svc))
			return DROP_IS_CLUSTER_IP;
	} else {
skip_service_lookup:
#ifdef ENABLE_NAT_46X64_GATEWAY
		if (ip4->daddr != IPV4_DIRECT_ROUTING) {
			ep_tail_call(ctx, CILIUM_CALL_IPV46_RFC8215);
			return DROP_MISSED_TAIL_CALL;
		}
#endif
		/* The packet is not destined to a service but it can be a reply
		 * packet from a remote backend, in which case we need to perform
		 * the reverse NAT.
		 */
		ctx_set_xfer(ctx, XFER_PKT_NO_SVC);

#ifdef ENABLE_DSR
		if (nodeport_uses_dsr4(&tuple)) {
#if (defined(IS_BPF_OVERLAY) && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE) || \
	(!defined(IS_BPF_OVERLAY) && DSR_ENCAP_MODE != DSR_ENCAP_GENEVE)
			bool dsr = false;

			/* Check if packet has embedded DSR info, or belongs to
			 * an established DSR connection:
			 */
			ret = nodeport_extract_dsr_v4(ctx, ip4, &tuple,
						      l4_off, &key.address,
						      &key.dport, &dsr);
			if (dsr) {
				ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
				ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_DSR_INGRESS);
				return DROP_MISSED_TAIL_CALL;
			}

			if (IS_ERR(ret))
				return ret;
#endif
#ifndef ENABLE_MASQUERADE
			/* The packet is DSR-eligible, so we know for sure that it is
			 * not reply traffic by a remote backend which would require
			 * forwarding / revDNAT. If BPF-Masquerading is off, there is no
			 * other reason to tail-call CILIUM_CALL_IPV4_NODEPORT_NAT_INGRESS.
			 */
			return CTX_ACT_OK;
#endif
		}
#endif /* ENABLE_DSR */

		ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
		/* For NAT64 we might see an IPv4 reply from the backend to
		 * the LB entering this path. Thus, transform back to IPv6.
		 */
		if (is_svc_proto && snat_v6_has_v4_match(&tuple)) {
			ret = lb4_to_lb6(ctx, ip4, l3_off);
			if (ret)
				return ret;
			ctx_store_meta(ctx, CB_NAT_46X64, 0);
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT_INGRESS);
#ifdef ENABLE_NAT_46X64_GATEWAY
		} else if (is_svc_proto &&
			   snat_v6_has_v4_match_rfc8215(&tuple)) {
			ret = snat_remap_rfc8215(ctx, ip4, l3_off);
			if (ret)
				return ret;
			ctx_store_meta(ctx, CB_NAT_46X64, NAT46x64_MODE_ROUTE);
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT_INGRESS);
#endif
		} else {
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_NAT_INGRESS);
		}
		return DROP_MISSED_TAIL_CALL;
	}

	backend_local = __lookup_ip4_endpoint(tuple.daddr);
	if (!backend_local && lb4_svc_is_hostport(svc))
		return DROP_INVALID;
	/* Reply from DSR packet is never seen on this node again
	 * hence no need to track in here.
	 */
	if (backend_local || !nodeport_uses_dsr4(&tuple)) {
		struct ct_state ct_state = {};

		ret = ct_lazy_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, has_l4_header,
				      ACTION_CREATE, CT_EGRESS, &ct_state, &monitor);
		switch (ret) {
		case CT_REPLY:
			/* SVC request should never be considered a reply, so this
			 * must be a stale CT entry.
			 *
			 * Tuple needs to be manually flipped for ct_create4():
			 */
			ipv4_ct_tuple_reverse(&tuple);
		case CT_NEW:
redo:
			ct_state_new.src_sec_id = WORLD_ID;
			ct_state_new.node_port = 1;
			ct_state_new.ifindex = (__u16)NATIVE_DEV_IFINDEX;
			ret = ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx,
					 CT_EGRESS, &ct_state_new, false, false, ext_err);
			if (IS_ERR(ret))
				return ret;
			break;
		case CT_REOPENED:
		case CT_ESTABLISHED:
			/* Recreate CT entries, as the existing one is stale and
			 * belongs to a flow which target a different svc.
			 */
			if (unlikely(ct_state.rev_nat_index !=
				     ct_state_new.rev_nat_index))
				goto redo;
			break;
		default:
			return DROP_UNKNOWN_CT;
		}

		if (backend_local) {
			ctx_set_xfer(ctx, XFER_PKT_NO_SVC);
			return CTX_ACT_OK;
		}

		ret = neigh_record_ip4(ctx);
		if (ret < 0)
			return ret;
	}

	/* TX request to remote backend: */
	edt_set_aggregate(ctx, 0);
	if (nodeport_uses_dsr4(&tuple)) {
#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
		ctx_store_meta(ctx, CB_HINT,
			       ((__u32)tuple.sport << 16) | tuple.dport);
		ctx_store_meta(ctx, CB_ADDR_V4, tuple.daddr);
#elif DSR_ENCAP_MODE == DSR_ENCAP_GENEVE || DSR_ENCAP_MODE == DSR_ENCAP_NONE
		ctx_store_meta(ctx, CB_PORT, key.dport);
		ctx_store_meta(ctx, CB_ADDR_V4, key.address);
#endif /* DSR_ENCAP_MODE */
		ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_DSR);
	} else {
		ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_NAT_EGRESS);
	}
	return DROP_MISSED_TAIL_CALL;
}

static __always_inline int
nodeport_rev_dnat_fwd_ipv4(struct __ctx_buff *ctx, struct trace_ctx *trace)
{
	int ret, l3_off = ETH_HLEN, l4_off;
	struct ipv4_ct_tuple tuple = {};
	struct ct_state ct_state = {};
	void *data, *data_end;
	bool has_l4_header;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	has_l4_header = ipv4_has_l4_header(ip4);

	ret = lb4_extract_tuple(ctx, ip4, ETH_HLEN, &l4_off, &tuple);
	if (ret < 0) {
		/* If it's not a SVC protocol, we don't need to check for RevDNAT: */
		if (ret == DROP_NO_SERVICE || ret == DROP_UNKNOWN_L4)
			return CTX_ACT_OK;
		return ret;
	}

	if (!ct_has_nodeport_egress_entry4(get_ct_map4(&tuple), &tuple,
					   is_defined(ENABLE_DSR)))
		return CTX_ACT_OK;

	ret = ct_lazy_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, has_l4_header,
			      ACTION_CREATE, CT_INGRESS, &ct_state, &trace->monitor);
	if (ret == CT_REPLY) {
		trace->reason = TRACE_REASON_CT_REPLY;

		/* Reply by local backend: */
		if (ct_state.node_port && ct_state.rev_nat_index) {
			ret = lb4_rev_nat(ctx, l3_off, l4_off, &ct_state,
					  &tuple, REV_NAT_F_TUPLE_SADDR,
					  has_l4_header);
			if (IS_ERR(ret))
				return ret;

			ctx_snat_done_set(ctx);
#ifdef ENABLE_DSR
		/* Reply by DSR backend: */
		} else if (ct_state.dsr) {
			ret = xlate_dsr_v4(ctx, &tuple, l4_off, has_l4_header);
			if (IS_ERR(ret))
				return ret;

 #if defined(ENABLE_HIGH_SCALE_IPCACHE) &&				\
     defined(IS_BPF_OVERLAY) &&						\
     DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
			/* For HS IPCache, we also need to revDNAT the OuterSrcIP: */
			{
				struct bpf_tunnel_key key;

				if (ctx_get_tunnel_key(ctx, &key, sizeof(key), 0) < 0)
					return DROP_NO_TUNNEL_KEY;

				if (!revalidate_data(ctx, &data, &data_end, &ip4))
					return DROP_INVALID;

				/* kernel returns addresses in flipped locations: */
				key.remote_ipv4 = key.local_ipv4;
				key.local_ipv4 = bpf_ntohl(ip4->saddr);

				if (ctx_set_tunnel_key(ctx, &key, sizeof(key),
						       BPF_F_ZERO_CSUM_TX) < 0)
					return DROP_WRITE_ERROR;
			}
 #endif
#endif
		}
	}

	return CTX_ACT_OK;
}

/* Reverse NAT handling of node-port traffic for the case where the
 * backend i) was a local EP and bpf_lxc redirected to us, ii) was
 * a remote backend and we got here after reverse SNAT from the
 * tail_nodeport_nat_ingress_ipv4().
 *
 * Also, reverse NAT handling return path egress-gw traffic.
 *
 * CILIUM_CALL_IPV{4,6}_NODEPORT_REVNAT is plugged into CILIUM_MAP_CALLS
 * of the bpf_host, bpf_overlay and of the bpf_lxc.
 */
static __always_inline int rev_nodeport_lb4(struct __ctx_buff *ctx, __s8 *ext_err)
{
	enum trace_reason __maybe_unused reason = TRACE_REASON_UNKNOWN;
	int ifindex = 0, ret, l3_off = ETH_HLEN, l4_off;
	struct ipv4_ct_tuple tuple = {};
	struct ct_state ct_state = {};
	void *data, *data_end;
	struct iphdr *ip4;
	__u32 monitor = TRACE_PAYLOAD_LEN;
	__u32 tunnel_endpoint __maybe_unused = 0;
	__u32 dst_sec_identity __maybe_unused = 0;
	__be16 src_port __maybe_unused = 0;
	bool has_l4_header;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
#if defined(ENABLE_EGRESS_GATEWAY) && !defined(TUNNEL_MODE)
	/* If we are not using TUNNEL_MODE, the gateway node needs to manually steer
	 * any reply traffic for a remote pod into the tunnel (to avoid iptables
	 * potentially dropping the packets).
	 */
	if (egress_gw_reply_needs_redirect(ip4, &tunnel_endpoint, &dst_sec_identity))
		goto encap_redirect;
#endif /* ENABLE_EGRESS_GATEWAY */

	has_l4_header = ipv4_has_l4_header(ip4);

	ret = lb4_extract_tuple(ctx, ip4, ETH_HLEN, &l4_off, &tuple);
	if (ret < 0) {
		/* If it's not a SVC protocol, we don't need to check for RevDNAT: */
		if (ret == DROP_NO_SERVICE || ret == DROP_UNKNOWN_L4)
			goto out;
		return ret;
	}

	if (!ct_has_nodeport_egress_entry4(get_ct_map4(&tuple), &tuple, false))
		goto out;

	ret = ct_lazy_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, has_l4_header,
			      ACTION_CREATE, CT_INGRESS, &ct_state, &monitor);
	if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {
		reason = TRACE_REASON_CT_REPLY;
		ret = lb4_rev_nat(ctx, l3_off, l4_off, &ct_state, &tuple,
				  REV_NAT_F_TUPLE_SADDR, has_l4_header);
		if (IS_ERR(ret))
			return ret;
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		ctx_snat_done_set(ctx);
		ifindex = ct_state.ifindex;
#if defined(TUNNEL_MODE)
		{
			struct remote_endpoint_info *info;

			info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN, 0);
			if (info != NULL && info->tunnel_endpoint != 0) {
				tunnel_endpoint = info->tunnel_endpoint;
				dst_sec_identity = info->sec_identity;
				goto encap_redirect;
			}
		}
#endif

		goto fib_lookup;
	}
out:
	if (bpf_skip_recirculation(ctx))
		return DROP_NAT_NO_MAPPING;

	ctx_skip_nodeport_set(ctx);
	ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_NETDEV);
	return DROP_MISSED_TAIL_CALL;
#if defined(ENABLE_EGRESS_GATEWAY) || defined(TUNNEL_MODE)
encap_redirect:
	src_port = tunnel_gen_src_port_v4();

	ret = __encap_with_nodeid(ctx, IPV4_DIRECT_ROUTING, src_port,
				  tunnel_endpoint, SECLABEL, dst_sec_identity,
				  NOT_VTEP_DST, reason, monitor, &ifindex);
	if (IS_ERR(ret))
		return ret;

	if (ret == CTX_ACT_REDIRECT && ifindex)
		return ctx_redirect(ctx, ifindex, 0);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
#endif

fib_lookup:
	return fib_redirect_v4(ctx, l3_off, ip4, true, ext_err,
			       ctx_get_ifindex(ctx), &ifindex);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_REVNAT)
int tail_rev_nodeport_lb4(struct __ctx_buff *ctx)
{
	__s8 ext_err = 0;
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

	ret = ipv4_host_policy_ingress(ctx, &src_id, &trace, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);
	/* We don't want to enforce host policies a second time if we jump back to
	 * bpf_host's handle_ipv6.
	 */
	ctx_skip_host_fw_set(ctx);
#endif
	ret = rev_nodeport_lb4(ctx, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, 0, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);
	edt_set_aggregate(ctx, 0);
	cilium_capture_out(ctx);
	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_SNAT_FWD)
int tail_handle_snat_fwd_ipv4(struct __ctx_buff *ctx)
{
	__u32 cluster_id = ctx_load_meta(ctx, CB_CLUSTER_ID_EGRESS);
	enum trace_point obs_point;
	int ret;
	__s8 ext_err = 0;

	ctx_store_meta(ctx, CB_CLUSTER_ID_EGRESS, 0);

#ifdef IS_BPF_OVERLAY
	obs_point = TRACE_TO_OVERLAY;
#else
	obs_point = TRACE_TO_NETWORK;
#endif

	ret = nodeport_snat_fwd_ipv4(ctx, cluster_id, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, 0, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);

	send_trace_notify(ctx, obs_point, 0, 0, 0, 0, TRACE_REASON_UNKNOWN, 0);

	return ret;
}

static __always_inline int
__handle_nat_fwd_ipv4(struct __ctx_buff *ctx, __u32 cluster_id __maybe_unused,
		      struct trace_ctx *trace)
{
	int ret;

	ret = nodeport_rev_dnat_fwd_ipv4(ctx, trace);
	if (IS_ERR(ret))
		return ret;

#if !defined(ENABLE_DSR) ||						\
    (defined(ENABLE_DSR) && defined(ENABLE_DSR_HYBRID)) ||		\
     defined(ENABLE_MASQUERADE) ||					\
    (defined(ENABLE_CLUSTER_AWARE_ADDRESSING) && defined(ENABLE_INTER_CLUSTER_SNAT))
	if (!ctx_snat_done(ctx)) {
		ctx_store_meta(ctx, CB_CLUSTER_ID_EGRESS, cluster_id);
		ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_SNAT_FWD);
		ret = DROP_MISSED_TAIL_CALL;
	}
#endif

	return ret;
}

static __always_inline int handle_nat_fwd_ipv4(struct __ctx_buff *ctx)
{
	struct trace_ctx trace;
	__u32 cluster_id = ctx_load_meta(ctx, CB_CLUSTER_ID_EGRESS);

	ctx_store_meta(ctx, CB_CLUSTER_ID_EGRESS, 0);

	return __handle_nat_fwd_ipv4(ctx, cluster_id, &trace);
}

declare_tailcall_if(__or4(__and(is_defined(ENABLE_IPV4),
				is_defined(ENABLE_IPV6)),
			  __and(is_defined(ENABLE_HOST_FIREWALL),
				is_defined(IS_BPF_HOST)),
			  __and(is_defined(ENABLE_CLUSTER_AWARE_ADDRESSING),
				is_defined(ENABLE_INTER_CLUSTER_SNAT)),
			  is_defined(ENABLE_EGRESS_GATEWAY)),
		    CILIUM_CALL_IPV4_NODEPORT_NAT_FWD)
int tail_handle_nat_fwd_ipv4(struct __ctx_buff *ctx)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	int ret;
	enum trace_point obs_point;
	__u32 cluster_id = ctx_load_meta(ctx, CB_CLUSTER_ID_EGRESS);

	ctx_store_meta(ctx, CB_CLUSTER_ID_EGRESS, 0);

#ifdef IS_BPF_OVERLAY
	obs_point = TRACE_TO_OVERLAY;
#else
	obs_point = TRACE_TO_NETWORK;
#endif

	ret = __handle_nat_fwd_ipv4(ctx, cluster_id, &trace);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);

	send_trace_notify(ctx, obs_point, 0, 0, 0, 0, trace.reason,
			  trace.monitor);

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
	key.tunnel_ttl = IPDEFTTL;

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
	key.tunnel_ttl = IPDEFTTL;

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

static __always_inline int handle_nat_fwd(struct __ctx_buff *ctx, __u32 cluster_id)
{
	int ret = CTX_ACT_OK;
	__u16 proto;

	ctx_store_meta(ctx, CB_CLUSTER_ID_EGRESS, cluster_id);

	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		invoke_tailcall_if(__or4(__and(is_defined(ENABLE_IPV4),
					       is_defined(ENABLE_IPV6)),
					 __and(is_defined(ENABLE_HOST_FIREWALL),
					       is_defined(IS_BPF_HOST)),
					 __and(is_defined(ENABLE_CLUSTER_AWARE_ADDRESSING),
					       is_defined(ENABLE_INTER_CLUSTER_SNAT)),
					 is_defined(ENABLE_EGRESS_GATEWAY)),
				   CILIUM_CALL_IPV4_NODEPORT_NAT_FWD,
				   handle_nat_fwd_ipv4);
		break;
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
					      is_defined(ENABLE_IPV6)),
					__and(is_defined(ENABLE_HOST_FIREWALL),
					      is_defined(IS_BPF_HOST))),
				   CILIUM_CALL_IPV6_NODEPORT_NAT_FWD,
				   handle_nat_fwd_ipv6);
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
