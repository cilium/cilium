/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __WIREGUARD_H_
#define __WIREGUARD_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "tailcall.h"
#include "common.h"
#include "overloadable.h"

static __always_inline int
wg_maybe_redirect_to_encrypt(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info *info;
	void *data, *data_end;
	__u16 proto = 0;
#ifdef ENABLE_IPV6
	struct ipv6hdr *ip6;
#endif
#ifdef ENABLE_IPV4
	struct iphdr *ip4;
#endif

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
		info = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr);
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		info = lookup_ip4_remote_endpoint(ip4->daddr);
		break;
#endif
	default:
		goto out;
	}

	/* Redirect to the WireGuard tunnel device if the encryption is
	 * required.
	 *
	 * After the packet has been encrypted, the WG tunnel device
	 * will set the MARK_MAGIC_WG_ENCRYPTED skb mark. So, to avoid
	 * looping forever (e.g., bpf_host@eth0 => cilium_wg0 =>
	 * bpf_host@eth0 => ...; this happens when eth0 is used to send
	 * encrypted WireGuard UDP packets), we check whether the mark
	 * is set before the redirect.
	 */
	if (((ctx->mark & MARK_MAGIC_WG_ENCRYPTED) !=
	     MARK_MAGIC_WG_ENCRYPTED) && info && info->key)
		return ctx_redirect(ctx, WG_IFINDEX, 0);

out:
	return CTX_ACT_OK;
}

#endif /* __WIREGUARD_H_ */
