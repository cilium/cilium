/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

#pragma once

#ifdef ENABLE_EXTLB_IPIP_TERMINATION
static __always_inline int
decap_ipv4(struct __ctx_buff *ctx)
{
	struct iphdr *outer_ip4;
	void *data, *data_end;

	int outer_ip4_len;

	if (!revalidate_data_pull(ctx, &data, &data_end, &outer_ip4))
		return DROP_INVALID;
	if (outer_ip4->protocol != IPPROTO_IPIP)
		return CTX_ACT_OK;

	outer_ip4_len = ipv4_hdrlen(outer_ip4);

	if (ctx_adjust_hroom(ctx, -outer_ip4_len,
			     BPF_ADJ_ROOM_MAC, ctx_adjust_hroom_flags()))
		return DROP_INVALID;

	return CTX_ACT_OK;
}

static __always_inline int
decap_ipip(struct __ctx_buff *ctx)
{
	__u16 proto = 0;

	if (!validate_ethertype(ctx, &proto))
		return DROP_INVALID;

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		return decap_ipv4(ctx);
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		/* TODO: support ipv6 */
		return DROP_INVALID;
#endif
	default:
		return CTX_ACT_OK;
	}

	return CTX_ACT_OK;
}
#endif /* ENABLE_EXTLB_IPIP_TERMINATION*/
