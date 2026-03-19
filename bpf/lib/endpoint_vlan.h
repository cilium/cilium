/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/if_ether.h>
#include "common.h"
#include "eps.h"
#include "dbg.h"

DECLARE_CONFIG(bool, enable_endpoint_vlan,
	       "Enable per-endpoint 802.1Q VLAN tagging")

/* Push 802.1Q VLAN tag for endpoint traffic on egress (to_netdev).
 * Looks up source endpoint by IP; if it has a vlan_id, pushes the tag.
 * Returns CTX_ACT_OK on success (including no-op), or a negative DROP reason.
 */
static __always_inline int
ep_vlan_push_egress(struct __ctx_buff *ctx __maybe_unused,
		    __be16 proto __maybe_unused)
{
#ifdef ENABLE_IPV4
	if (proto == bpf_htons(ETH_P_IP)) {
		const struct endpoint_info *ep;
		void *data, *data_end;
		struct iphdr *ip4;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		ep = __lookup_ip4_endpoint(ip4->saddr);
		if (ep && ep->vlan_id)
			return skb_vlan_push(ctx, bpf_htons(ETH_P_8021Q),
					     ep->vlan_id);
		return CTX_ACT_OK;
	}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
	if (proto == bpf_htons(ETH_P_IPV6)) {
		const struct endpoint_info *ep;
		void *data, *data_end;
		struct ipv6hdr *ip6;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
		ep = __lookup_ip6_endpoint((union v6addr *)&ip6->saddr);
		if (ep && ep->vlan_id)
			return skb_vlan_push(ctx, bpf_htons(ETH_P_8021Q),
					     ep->vlan_id);
		return CTX_ACT_OK;
	}
#endif /* ENABLE_IPV6 */

	return CTX_ACT_OK;
}
