/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

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

 /* fib_do_redirect will redirect the ctx to a particular output interface.
  * @arg ctx			packet
  * @arg needs_l2_check		check for L3 -> L2 redirect
  * @arg fib_params		FIB lookup parameters
  * @arg allow_neigh_map	fallback to neighbour map for DMAC
  * @arg fib_result		result of a preceding FIB lookup
  * @arg oif			egress interface index
  * @arg ext_err		extended error
  *
  * Returns:
  *   - result of BPF redirect
  *   - DROP_NO_FIB when DMAC couldn't be resolved
  *   - other DROP reasons
  * the redirect can occur with or without a previous call to fib_lookup.
  *
  * if a previous fib_lookup was performed, this function will attempt to redirect
  * to the output interface in the provided 'fib_params', as long as 'fib_ret'
  * is set to 'BPF_FIB_LKUP_RET_SUCCESS'
  *
  * if a previous fib_lookup was performed and the return was 'BPF_FIB_LKUP_NO_NEIGH'
  * this function will then attempt to copy the af_family and destination address
  * out of 'fib_params' and into 'redir_neigh' struct then perform a
  * 'redirect_neigh'.
  *
  * if no previous fib_lookup was performed, and the desire is to simply use
  * 'redirect_neigh' then set 'fib_params' to nil and 'fib_ret' to
  * 'BPF_FIB_LKUP_RET_NO_NEIGH'.
  * in this case, the 'oif' value will be used for the 'redirect_neigh' call.
  *
  * in a special case, if a previous fib_lookup was performed, and the return
  * was 'BPF_FIB_LKUP_RET_NO_NEIGH', and we are on a kernel version where
  * the target interface for the fib lookup is not returned
  * (due to ARP failing, see Kernel commit d1c362e1dd68) the provided 'oif'
  * will be used as output interface for redirect.
  */
static __always_inline int
fib_do_redirect(struct __ctx_buff *ctx, const bool needs_l2_check,
		const struct bpf_fib_lookup_padded *fib_params,
		bool allow_neigh_map, int fib_result, int *oif, __s8 *ext_err)
{
	/* determine which oif to use before needs_l2_check determines if layer 2
	 * header needs to be pushed.
	 */
	if (fib_params) {
		if (fib_result == BPF_FIB_LKUP_RET_NO_NEIGH &&
		    !is_defined(HAVE_FIB_IFINDEX) && *oif) {
			/* For kernels without d1c362e1dd68 ("bpf: Always
			 * return target ifindex in bpf_fib_lookup") we
			 * fall back to use the caller-provided oif when
			 * necessary.
			 * no-op
			 */
		} else {
			*oif = fib_params->l.ifindex;
		}
	}

	/* determine if we need to append layer 2 header */
	if (needs_l2_check) {
		bool l2_hdr_required = true;
		int ret;

		ret = maybe_add_l2_hdr(ctx, *oif, &l2_hdr_required);
		if (ret != 0)
			return ret;
		if (!l2_hdr_required)
			goto out_send;
	}

	/* determine if we are performing redirect or redirect_neigh*/
	switch (fib_result) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		if (eth_store_daddr(ctx, fib_params->l.dmac, 0) < 0)
			return DROP_WRITE_ERROR;
		if (eth_store_saddr(ctx, fib_params->l.smac, 0) < 0)
			return DROP_WRITE_ERROR;
		break;
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		/* If we are able to resolve neighbors on demand, always
		 * prefer that over the BPF neighbor map since the latter
		 * might be less accurate in some asymmetric corner cases.
		 */
		if (neigh_resolver_available()) {
			if (fib_params) {
				struct bpf_redir_neigh nh_params;

				nh_params.nh_family = fib_params->l.family;
				__bpf_memcpy_builtin(&nh_params.ipv6_nh,
						     &fib_params->l.ipv6_dst,
						     sizeof(nh_params.ipv6_nh));

				return redirect_neigh(*oif, &nh_params,
						sizeof(nh_params), 0);
			}

			return redirect_neigh(*oif, NULL, 0, 0);
		} else {
			union macaddr smac = NATIVE_DEV_MAC_BY_IFINDEX(*oif);
			union macaddr *dmac = NULL;

			if (allow_neigh_map) {
				/* The neigh_record_ip{4,6} locations are mainly from
				 * inbound client traffic on the load-balancer where we
				 * know that replies need to go back to them.
				 */
				dmac = fib_params->l.family == AF_INET ?
					neigh_lookup_ip4(&fib_params->l.ipv4_dst) :
					neigh_lookup_ip6((void *)&fib_params->l.ipv6_dst);
			}

			if (!dmac) {
				*ext_err = BPF_FIB_MAP_NO_NEIGH;
				return DROP_NO_FIB;
			}
			if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr_aligned(ctx, smac.addr, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	};
out_send:
	return ctx_redirect(ctx, *oif, 0);
}

static __always_inline int
fib_redirect(struct __ctx_buff *ctx, const bool needs_l2_check,
	     struct bpf_fib_lookup_padded *fib_params __maybe_unused,
	     bool use_neigh_map, __s8 *ext_err __maybe_unused, int *oif)
{
#ifdef ENABLE_SKIP_FIB
	*oif = DIRECT_ROUTING_DEV_IFINDEX;
#endif

	if (!is_defined(ENABLE_SKIP_FIB) || !neigh_resolver_available()) {
		int ret;

		ret = fib_lookup(ctx, &fib_params->l, sizeof(fib_params->l), 0);
		switch (ret) {
		case BPF_FIB_LKUP_RET_SUCCESS:
		case BPF_FIB_LKUP_RET_NO_NEIGH:
			break;
		default:
			*ext_err = (__s8)ret;
			return DROP_NO_FIB;
		}

		return fib_do_redirect(ctx, needs_l2_check, fib_params, use_neigh_map,
				       ret, oif, ext_err);
	}

	return fib_do_redirect(ctx, needs_l2_check, NULL, use_neigh_map,
			       BPF_FIB_LKUP_RET_NO_NEIGH, oif, ext_err);
}

#ifdef ENABLE_IPV6
/* fib_lookup_v6 will perform a fib lookup with the src and dest addresses
 * provided.
 *
 * after the function returns 'fib_params' will have the results of the fib lookup
 * if successful.
 */
static __always_inline int
fib_lookup_v6(struct __ctx_buff *ctx, struct bpf_fib_lookup_padded *fib_params,
	      const struct in6_addr *ipv6_src, const struct in6_addr *ipv6_dst,
	      int flags)
{
	fib_params->l.family	= AF_INET6;
	fib_params->l.ifindex	= ctx_get_ifindex(ctx);

	ipv6_addr_copy((union v6addr *)&fib_params->l.ipv6_src,
		       (union v6addr *)ipv6_src);
	ipv6_addr_copy((union v6addr *)&fib_params->l.ipv6_dst,
		       (union v6addr *)ipv6_dst);

	return fib_lookup(ctx, &fib_params->l, sizeof(fib_params->l), flags);
};

static __always_inline int
fib_redirect_v6(struct __ctx_buff *ctx, int l3_off,
		struct ipv6hdr *ip6 __maybe_unused, const bool needs_l2_check,
		bool allow_neigh_map, __s8 *ext_err __maybe_unused, int *oif)
{
	struct bpf_fib_lookup_padded fib_params __maybe_unused = {0};
	int ret;

#ifdef ENABLE_SKIP_FIB
	*oif = DIRECT_ROUTING_DEV_IFINDEX;
#endif

	if (!is_defined(ENABLE_SKIP_FIB) || !neigh_resolver_available()) {
		int fib_result;

		fib_result = fib_lookup_v6(ctx, &fib_params, &ip6->saddr, &ip6->daddr, 0);
		switch (fib_result) {
		case BPF_FIB_LKUP_RET_SUCCESS:
		case BPF_FIB_LKUP_RET_NO_NEIGH:
			break;
		default:
			*ext_err = (__s8)fib_result;
			return DROP_NO_FIB;
		}

		ret = ipv6_l3(ctx, l3_off, NULL, NULL, METRIC_EGRESS);
		if (unlikely(ret != CTX_ACT_OK))
			return ret;

		return fib_do_redirect(ctx, needs_l2_check, &fib_params, allow_neigh_map,
				       fib_result, oif, ext_err);
	}

	ret = ipv6_l3(ctx, l3_off, NULL, NULL, METRIC_EGRESS);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;

	return fib_do_redirect(ctx, needs_l2_check, NULL, allow_neigh_map,
			       BPF_FIB_LKUP_RET_NO_NEIGH, oif, ext_err);
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
/* fib_lookup_v4 will perform a fib lookup with the src and dest addresses
 * provided.
 *
 * after the function returns 'fib_params' will have the results of the fib lookup
 * if successful.
 */
static __always_inline int
fib_lookup_v4(struct __ctx_buff *ctx, struct bpf_fib_lookup_padded *fib_params,
	      __be32 ipv4_src, __be32 ipv4_dst, int flags) {
	fib_params->l.family	= AF_INET;
	fib_params->l.ifindex	= ctx_get_ifindex(ctx);
	fib_params->l.ipv4_src	= ipv4_src;
	fib_params->l.ipv4_dst	= ipv4_dst;

	return fib_lookup(ctx, &fib_params->l, sizeof(fib_params->l), flags);
}

static __always_inline int
fib_redirect_v4(struct __ctx_buff *ctx, int l3_off,
		struct iphdr *ip4 __maybe_unused, const bool needs_l2_check,
		bool allow_neigh_map, __s8 *ext_err __maybe_unused, int *oif)
{
	struct bpf_fib_lookup_padded fib_params __maybe_unused = {0};
	int ret;

#ifdef ENABLE_SKIP_FIB
	*oif = DIRECT_ROUTING_DEV_IFINDEX;
#endif

	if (!is_defined(ENABLE_SKIP_FIB) || !neigh_resolver_available()) {
		int fib_result;

		fib_result = fib_lookup_v4(ctx, &fib_params, ip4->saddr, ip4->daddr, 0);
		switch (fib_result) {
		case BPF_FIB_LKUP_RET_SUCCESS:
		case BPF_FIB_LKUP_RET_NO_NEIGH:
			break;
		default:
			*ext_err = (__s8)fib_result;
			return DROP_NO_FIB;
		}

		ret = ipv4_l3(ctx, l3_off, NULL, NULL, ip4);
		if (unlikely(ret != CTX_ACT_OK))
			return ret;

		return fib_do_redirect(ctx, needs_l2_check, &fib_params, allow_neigh_map,
				       fib_result, oif, ext_err);
	}

	ret = ipv4_l3(ctx, l3_off, NULL, NULL, ip4);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;

	return fib_do_redirect(ctx, needs_l2_check, NULL, allow_neigh_map,
			       BPF_FIB_LKUP_RET_NO_NEIGH, oif, ext_err);
}
#endif /* ENABLE_IPV4 */
