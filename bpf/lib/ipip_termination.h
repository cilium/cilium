/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */


#ifndef __LIB_IPIP_TERMINATION_H_
#define __LIB_IPIP_TERMINATION_H_

#ifdef ENABLE_IPIP_TERMINATION

static __always_inline int
decap_ipv4(struct __ctx_buff *ctx)
{
	struct iphdr *outer_ip4;
	struct iphdr inner_ip4;
	void *data, *data_end;

	struct ipv4_ct_tuple tuple = {};
	int ret, inner_ip4_off, outer_ip4_off = ETH_HLEN, outer_ip4_len, l4_off;

	struct lb4_key key = {};
	struct lb4_service *svc;

	if (!revalidate_data_pull(ctx, &data, &data_end, &outer_ip4))
		return DROP_INVALID;
	if (outer_ip4->protocol != IPPROTO_IPIP) {
		return CTX_ACT_OK;
	}

	outer_ip4_len = ipv4_hdrlen(outer_ip4);
	inner_ip4_off = outer_ip4_off + outer_ip4_len;

	if (ctx_load_bytes(ctx, inner_ip4_off, &inner_ip4, sizeof(inner_ip4)) < 0)
		return DROP_INVALID;

	ret = lb4_extract_tuple(ctx, &inner_ip4, inner_ip4_off, &l4_off, &tuple);
	if (IS_ERR(ret)) {
		/* Bypass */
		return CTX_ACT_OK;
	}

	lb4_fill_key(&key, &tuple);

	svc = lb4_lookup_service(&key, false);
	if (svc) {
		if (!lb4_svc_is_loadbalancer(svc))
			return CTX_ACT_OK;

		if (ctx_adjust_hroom(ctx, -outer_ip4_len, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO))
			return DROP_INVALID;
	}

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
#endif
	default:
		return CTX_ACT_OK;
	}

	return CTX_ACT_OK;
}
#endif /* ENABLE_IPIP_TERMINATION */
#endif /* __LIB_IPIP_TERMINATION_H_ */
