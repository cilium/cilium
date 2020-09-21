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
static __always_inline int
do_decrypt(struct __ctx_buff *ctx, __u16 proto)
{
	bool decrypted;

	decrypted = ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);
	if (!decrypted) {
		void *data, *data_end;
		__u8 protocol = 0;
#ifdef ENABLE_IPV6
		struct ipv6hdr *ip6;
#endif
#ifdef ENABLE_IPV4
		struct iphdr *ip4;
#endif

		switch (proto) {
#ifdef ENABLE_IPV6
		case bpf_htons(ETH_P_IPV6):
			if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
				break;
			protocol = ip6->nexthdr;
			break;
#endif
#ifdef ENABLE_IPV4
		case bpf_htons(ETH_P_IP):
			if (!revalidate_data(ctx, &data, &data_end, &ip4))
				break;

			protocol = ip4->protocol;
			break;
#endif
		}

		if (protocol == IPPROTO_ESP) {
			/* Decrypt "key" is determined by SPI */
			ctx->mark = MARK_MAGIC_DECRYPT;
			/* We are going to pass this up the stack for IPsec decryption
			 * but eth_type_trans may already have labeled this as an
			 * OTHERHOST type packet. To avoid being dropped by IP stack
			 * before IPSec can be processed mark as a HOST packet.
			 */
			ctx_change_type(ctx, PACKET_HOST);
			return 0;
		}
	}
	return -ENOENT;
}
#else
static __always_inline int
do_decrypt(struct __ctx_buff __maybe_unused *ctx, __u16 __maybe_unused proto)
{
	return -ENOENT;
}
#endif /* ENABLE_IPSEC */
#endif /* __LIB_ENCRYPT_H_ */

