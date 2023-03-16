/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_FIB_H_
#define __LIB_FIB_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "common.h"
#include "neigh.h"
#include "l3.h"

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

static __always_inline bool fib_ok(int ret)
{
	return likely(ret == CTX_ACT_TX || ret == CTX_ACT_REDIRECT);
}

/* fib_redirect() is common helper code which performs fib lookup, populates
 * the corresponding hardware addresses and pushes the packet to a target
 * device for the next hop. Calling fib_redirect_v{4,6} is preferred unless
 * due to NAT46x64 struct bpf_fib_lookup_padded needs to be prepared at the
 * callsite. oif must be 0 if otherwise not passed in from the BPF CT. The
 * needs_l2_check must be true if the packet could transition between L2->L3
 * or L3->L2 device.
 */
static __always_inline int
fib_redirect(struct __ctx_buff *ctx, const bool needs_l2_check,
	     struct bpf_fib_lookup_padded *fib_params, __s8 *fib_err, int *oif)
{
	struct bpf_redir_neigh nh_params;
	struct bpf_redir_neigh *nh = NULL;
	bool no_neigh = is_defined(ENABLE_SKIP_FIB);
	int ret;

#ifndef ENABLE_SKIP_FIB
	ret = fib_lookup(ctx, &fib_params->l, sizeof(fib_params->l), 0);
	if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
		*fib_err = (__s8)ret;
		if (likely(ret == BPF_FIB_LKUP_RET_NO_NEIGH)) {
			nh_params.nh_family = fib_params->l.family;
			__bpf_memcpy_builtin(&nh_params.ipv6_nh,
					     &fib_params->l.ipv6_dst,
					     sizeof(nh_params.ipv6_nh));
			nh = &nh_params;
			no_neigh = true;
			/* For kernels without d1c362e1dd68 ("bpf: Always
			 * return target ifindex in bpf_fib_lookup") we
			 * fall back to use the caller-provided oif when
			 * necessary.
			 */
			if (!is_defined(HAVE_FIB_IFINDEX) && *oif > 0)
				goto skip_oif;
		} else {
			return DROP_NO_FIB;
		}
	}
	*oif = fib_params->l.ifindex;
skip_oif:
#else
	*oif = DIRECT_ROUTING_DEV_IFINDEX;
#endif /* ENABLE_SKIP_FIB */
	if (needs_l2_check) {
		bool l2_hdr_required = true;

		ret = maybe_add_l2_hdr(ctx, *oif, &l2_hdr_required);
		if (ret != 0)
			return ret;
		if (!l2_hdr_required)
			goto out_send;
	}
	if (no_neigh) {
		/* If we are able to resolve neighbors on demand, always
		 * prefer that over the BPF neighbor map since the latter
		 * might be less accurate in some asymmetric corner cases.
		 */
		if (neigh_resolver_available()) {
			if (nh)
				return redirect_neigh(*oif, &nh_params,
						      sizeof(nh_params), 0);
			else
				return redirect_neigh(*oif, NULL, 0, 0);
		} else {
			union macaddr *dmac, smac = NATIVE_DEV_MAC_BY_IFINDEX(*oif);

			/* The neigh_record_ip{4,6} locations are mainly from
			 * inbound client traffic on the load-balancer where we
			 * know that replies need to go back to them.
			 */
			dmac = fib_params->l.family == AF_INET ?
			       neigh_lookup_ip4(&fib_params->l.ipv4_dst) :
			       neigh_lookup_ip6((void *)&fib_params->l.ipv6_dst);
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
		if (eth_store_daddr(ctx, fib_params->l.dmac, 0) < 0)
			return DROP_WRITE_ERROR;
		if (eth_store_saddr(ctx, fib_params->l.smac, 0) < 0)
			return DROP_WRITE_ERROR;
	}
out_send:
	return ctx_redirect(ctx, *oif, 0);
}

#ifdef ENABLE_IPV6
static __always_inline int
fib_redirect_v6(struct __ctx_buff *ctx, int l3_off,
		struct ipv6hdr *ip6, const bool needs_l2_check,
		__s8 *fib_err, int iif, int *oif)
{
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET6,
			.ifindex	= iif,
		},
	};
	int ret;

	ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_src,
		       (union v6addr *)&ip6->saddr);
	ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_dst,
		       (union v6addr *)&ip6->daddr);

	ret = ipv6_l3(ctx, l3_off, NULL, NULL, METRIC_EGRESS);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;

	return fib_redirect(ctx, needs_l2_check, &fib_params, fib_err, oif);
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int
fib_redirect_v4(struct __ctx_buff *ctx, int l3_off,
		struct iphdr *ip4, const bool needs_l2_check,
		__s8 *fib_err, int iif, int *oif)
{
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET,
			.ifindex	= iif,
			.ipv4_src	= ip4->saddr,
			.ipv4_dst	= ip4->daddr,
		},
	};
	int ret;

	ret = ipv4_l3(ctx, l3_off, NULL, NULL, ip4);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;

	return fib_redirect(ctx, needs_l2_check, &fib_params, fib_err, oif);
}
#endif /* ENABLE_IPV4 */
#endif /* __LIB_FIB_H_ */
