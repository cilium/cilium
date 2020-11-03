/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef __LIB_FIB_H_
#define __LIB_FIB_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "common.h"
#include "l3.h"

#ifdef ENABLE_IPV6
static __always_inline int
redirect_direct_v6(struct __ctx_buff *ctx __maybe_unused,
		   int l3_off __maybe_unused,
		   struct ipv6hdr *ip6 __maybe_unused)
{
	bool no_neigh = is_defined(ENABLE_SKIP_FIB);
	int ret, oif = DIRECT_ROUTING_DEV_IFINDEX;
	struct bpf_redir_neigh *nh = NULL;
# ifndef ENABLE_SKIP_FIB
	struct bpf_redir_neigh nh_params;
	struct bpf_fib_lookup fib_params = {
		.family		= AF_INET6,
		.ifindex	= ctx->ingress_ifindex,
	};

	ipv6_addr_copy((union v6addr *)&fib_params.ipv6_src,
		       (union v6addr *)&ip6->saddr);
	ipv6_addr_copy((union v6addr *)&fib_params.ipv6_dst,
		       (union v6addr *)&ip6->daddr);

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT);
	switch (ret) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		break;
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		nh_params.nh_family = fib_params.family;
		__bpf_memcpy_builtin(&nh_params.ipv6_nh, &fib_params.ipv6_dst,
				     sizeof(nh_params.ipv6_nh));
		no_neigh = true;
		nh = &nh_params;
		break;
	default:
		return CTX_ACT_DROP;
	}

	oif = fib_params.ifindex;
# endif /* ENABLE_SKIP_FIB */

	ret = ipv6_l3(ctx, l3_off, NULL, NULL, METRIC_EGRESS);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
	if (no_neigh)
		return redirect_neigh(oif, nh, nh ? sizeof(*nh) : 0, 0);
# ifndef ENABLE_SKIP_FIB
	if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
		return CTX_ACT_DROP;
	if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
		return CTX_ACT_DROP;
	return redirect(oif, 0);
# endif /* ENABLE_SKIP_FIB */
	return CTX_ACT_DROP;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int
redirect_direct_v4(struct __ctx_buff *ctx __maybe_unused,
		   int l3_off __maybe_unused,
		   struct iphdr *ip4 __maybe_unused)
{
	/* For deployments with just single external dev, redirect_neigh()
	 * will resolve the GW and do L2 resolution for us. For multi-device
	 * deployments we perform a FIB lookup prior to the redirect. If the
	 * neigh entry cannot be resolved, we ask redirect_neigh() to do it,
	 * otherwise we can directly call redirect().
	 */
	bool no_neigh = is_defined(ENABLE_SKIP_FIB);
	int ret, oif = DIRECT_ROUTING_DEV_IFINDEX;
	struct bpf_redir_neigh *nh = NULL;
# ifndef ENABLE_SKIP_FIB
	struct bpf_redir_neigh nh_params;
	struct bpf_fib_lookup fib_params = {
		.family		= AF_INET,
		.ifindex	= ctx->ingress_ifindex,
		.ipv4_src	= ip4->saddr,
		.ipv4_dst	= ip4->daddr,
	};

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT);
	switch (ret) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		break;
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		/* GW could also be v6, so copy union. */
		nh_params.nh_family = fib_params.family;
		__bpf_memcpy_builtin(&nh_params.ipv6_nh, &fib_params.ipv6_dst,
				     sizeof(nh_params.ipv6_nh));
		no_neigh = true;
		nh = &nh_params;
		break;
	default:
		return CTX_ACT_DROP;
	}

	oif = fib_params.ifindex;
# endif /* ENABLE_SKIP_FIB */

	ret = ipv4_l3(ctx, l3_off, NULL, NULL, ip4);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
	if (no_neigh)
		return redirect_neigh(oif, nh, nh ? sizeof(*nh) : 0, 0);
# ifndef ENABLE_SKIP_FIB
	if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
		return CTX_ACT_DROP;
	if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
		return CTX_ACT_DROP;
	return redirect(oif, 0);
# endif /* ENABLE_SKIP_FIB */
	return CTX_ACT_DROP;
}
#endif /* ENABLE_IPV4 */

#endif /* __LIB_FIB_H_ */
