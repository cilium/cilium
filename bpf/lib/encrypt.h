/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef __LIB_ENCRYPT_H_
#define __LIB_ENCRYPT_H_

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include "lib/common.h"
#include "lib/ipv6.h"
#include "lib/l3.h"
#include "lib/eth.h"

#ifdef ENABLE_IPSEC
#define IPV4_SIP_FOO 16843009

#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

#if 0
static __always_inline int 
rewrite_ipsec_sip(struct __ctx_buff *ctx)
{
	int ret = 0;
	void *data, *data_end;
	__u32 tunnel_source = IPV4_SIP_FOO;
	struct iphdr *iphdr;
	__be32 sum;

	if (!revalidate_data(ctx, &data, &data_end, &iphdr)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	sum = csum_diff(&iphdr->saddr, 4, &tunnel_source, 4, 0);
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr),
	    &tunnel_source, 4, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
	    0, sum, 0) < 0) {
		ret = DROP_CSUM_L3;
		goto drop_err;
	}
drop_err:
	return ret;
}
#endif


static __always_inline int
do_decrypt(struct __ctx_buff *ctx, __u16 proto)
{
	void *data, *data_end;
	__u8 protocol = 0;
	bool decrypted;
#ifdef ENABLE_IPV6
	struct ipv6hdr *ip6;
#endif
#ifdef ENABLE_IPV4
	struct iphdr *ip4;
#endif

	decrypted = ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6)) {
			ctx->mark = 0;
			bpf_printk("mark 0 data pull ipv6 issue %d\n", ctx->mark);
			return CTX_ACT_OK;
		}
		protocol = ip6->nexthdr;
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
			ctx->mark = 0;
			bpf_printk("mark 0 data pull ipv4 issue %d\n", ctx->mark);
			return CTX_ACT_OK;
		}
		protocol = ip4->protocol;
		break;
#endif
	default:
		return CTX_ACT_OK;
	}

	if (!decrypted) {
		/* Allow all non-ESP packets up the stack per normal case
		 * without encryption enabled.
		 */
		if (protocol != IPPROTO_ESP)
			return CTX_ACT_OK;

		/* Rewrite srcIP to fooIP to match ingress rules and avoid
		 * creating stacks of IPSec In rules.
		 */
		//rewrite_ipsec_sip(ctx);

		/* We are going to pass this up the stack for IPsec decryption
		 * but eth_type_trans may already have labeled this as an
		 * OTHERHOST type packet. To avoid being dropped by IP stack
		 * before IPSec can be processed mark as a HOST packet.
		 */
		ctx_change_type(ctx, PACKET_HOST);

		/* Decrypt "key" is determined by SPI */
		ctx->mark = MARK_MAGIC_DECRYPT;
		bpf_printk("mark the decrypt magic %d\n", ctx->mark);

		return CTX_ACT_OK;
	}
	bpf_printk("received an encrypted packet %d\n", ctx->mark);
	ctx_change_type(ctx, PACKET_HOST);
	ctx->mark = 0;
//	return redirect(CILIUM_IFINDEX, 0);
	return CTX_ACT_OK;
}
#else
static __always_inline int
do_decrypt(struct __ctx_buff __maybe_unused *ctx, __u16 __maybe_unused proto)
{
	return CTX_ACT_OK;
}
#endif /* ENABLE_IPSEC */
#endif /* __LIB_ENCRYPT_H_ */

