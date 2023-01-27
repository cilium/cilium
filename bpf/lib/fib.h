/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_FIB_H_
#define __LIB_FIB_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "common.h"
#include "neigh.h"
#include "l3.h"

#ifndef IS_L3_DEV
# define IS_L3_DEV(ifindex)	false
#endif

static __always_inline int
maybe_add_l2_hdr(struct __ctx_buff *ctx __maybe_unused,
		 __u32 ifindex __maybe_unused,
		 bool *l2_hdr_required __maybe_unused)
{
	if (IS_L3_DEV(ifindex)) {
		/* The packet is going to be redirected to L3 dev, so
		 * skip L2 addr settings.
		 */
		*l2_hdr_required = false;
	} else if (ETH_HLEN == 0) {
		/* The packet is going to be redirected from L3 to L2
		 * device, so we need to create L2 header first.
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
static __always_inline int
fib_redirect_v6(struct __ctx_buff *ctx, int l3_off,
		struct ipv6hdr *ip6, const bool needs_l2_check,
		__s8 *fib_err, int iif, int *oif)
{
	bool no_neigh = false;
	struct bpf_redir_neigh nh_params;
	struct bpf_fib_lookup fib_params = {
		.family		= AF_INET6,
		.ifindex	= iif,
	};
	int ret;

	ipv6_addr_copy((union v6addr *)&fib_params.ipv6_src,
		       (union v6addr *)&ip6->saddr);
	ipv6_addr_copy((union v6addr *)&fib_params.ipv6_dst,
		       (union v6addr *)&ip6->daddr);

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT);
	if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
		*fib_err = (__s8)ret;
		if (likely(ret == BPF_FIB_LKUP_RET_NO_NEIGH)) {
			nh_params.nh_family = fib_params.family;
			__bpf_memcpy_builtin(&nh_params.ipv6_nh,
					     &fib_params.ipv6_dst,
					     sizeof(nh_params.ipv6_nh));
			no_neigh = true;
		} else {
			return DROP_NO_FIB;
		}
	}

	*oif = fib_params.ifindex;

	ret = ipv6_l3(ctx, l3_off, NULL, NULL, METRIC_EGRESS);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
	if (needs_l2_check) {
		bool l2_hdr_required = true;

		ret = maybe_add_l2_hdr(ctx, *oif, &l2_hdr_required);
		if (ret != 0)
			return ret;
		if (!l2_hdr_required)
			goto out_send;
	}
	if (no_neigh) {
		if (neigh_resolver_available()) {
			return redirect_neigh(*oif, &nh_params,
					      sizeof(nh_params), 0);
		} else {
			union macaddr *dmac, smac =
				NATIVE_DEV_MAC_BY_IFINDEX(fib_params.ifindex);
			dmac = nh_params.nh_family == AF_INET ?
			       neigh_lookup_ip4(&fib_params.ipv4_dst) :
			       neigh_lookup_ip6((void *)&fib_params.ipv6_dst);
			if (!dmac) {
				*fib_err = BPF_FIB_MAP_NO_NEIGH;
				return DROP_NO_FIB;
			}
			if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr_aligned(ctx, smac.addr, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	} else {
		if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
			return DROP_WRITE_ERROR;
		if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
			return DROP_WRITE_ERROR;
	}
out_send:
	return ctx_redirect(ctx, *oif, 0);
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int
fib_redirect_v4(struct __ctx_buff *ctx, int l3_off,
		struct iphdr *ip4, const bool needs_l2_check,
		__s8 *fib_err, int iif, int *oif)
{
	bool no_neigh = false;
	struct bpf_redir_neigh nh_params;
	struct bpf_fib_lookup fib_params = {
		.family		= AF_INET,
		.ifindex	= iif,
		.ipv4_src	= ip4->saddr,
		.ipv4_dst	= ip4->daddr,
	};
	int ret;

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT);
	if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
		*fib_err = (__s8)ret;
		if (likely(ret == BPF_FIB_LKUP_RET_NO_NEIGH)) {
			/* GW could also be v6, so copy union. */
			nh_params.nh_family = fib_params.family;
			__bpf_memcpy_builtin(&nh_params.ipv6_nh,
					     &fib_params.ipv6_dst,
					     sizeof(nh_params.ipv6_nh));
			no_neigh = true;
		} else {
			return DROP_NO_FIB;
		}
	}

	*oif = fib_params.ifindex;

	ret = ipv4_l3(ctx, l3_off, NULL, NULL, ip4);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
	if (needs_l2_check) {
		bool l2_hdr_required = true;

		ret = maybe_add_l2_hdr(ctx, *oif, &l2_hdr_required);
		if (ret != 0)
			return ret;
		if (!l2_hdr_required)
			goto out_send;
	}
	if (no_neigh) {
		if (neigh_resolver_available()) {
			return redirect_neigh(*oif, &nh_params,
					      sizeof(nh_params), 0);
		} else {
			union macaddr *dmac, smac =
				NATIVE_DEV_MAC_BY_IFINDEX(fib_params.ifindex);
			dmac = nh_params.nh_family == AF_INET6 ?
			       neigh_lookup_ip6((void *)&fib_params.ipv6_dst) :
			       neigh_lookup_ip4(&fib_params.ipv4_dst);
			if (!dmac) {
				*fib_err = BPF_FIB_MAP_NO_NEIGH;
				return DROP_NO_FIB;
			}
			if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr_aligned(ctx, smac.addr, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	} else {
		if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
			return DROP_WRITE_ERROR;
		if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
			return DROP_WRITE_ERROR;
	}
out_send:
	return ctx_redirect(ctx, *oif, 0);
}
#endif /* ENABLE_IPV4 */
#endif /* __LIB_FIB_H_ */
