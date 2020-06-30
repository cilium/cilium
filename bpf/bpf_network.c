// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019-2020 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/trace.h"
#include "lib/l3.h"
#include "lib/drop.h"

#ifdef ENABLE_IPV6
static __always_inline int handle_ipv6(struct __ctx_buff *ctx)
{
#ifdef ENABLE_IPSEC
	void *data_end, *data;
	struct ipv6hdr *ip6;
	bool decrypted;

	decrypted = ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);
	if (!revalidate_data_first(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	if (!decrypted) {
		/* IPSec is not currently enforce (feature coming soon)
		 * so for now just handle normally
		 */
		if (ip6->nexthdr != IPPROTO_ESP)
			return 0;

		/* Decrypt "key" is determined by SPI */
		ctx->mark = MARK_MAGIC_DECRYPT;

		/* We are going to pass this up the stack for IPsec decryption
		 * but eth_type_trans may already have labeled this as an
		 * OTHERHOST type packet. To avoid being dropped by IP stack
		 * before IPSec can be processed mark as a HOST packet.
		 */
		ctx_change_type(ctx, PACKET_HOST);
		return CTX_ACT_OK;
	}

	ctx->mark = 0;
	return redirect(CILIUM_IFINDEX, 0);
#endif
	return 0;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int handle_ipv4(struct __ctx_buff *ctx)
{
#ifdef ENABLE_IPSEC
	void *data_end, *data;
	struct iphdr *ip4;
	bool decrypted;

	decrypted = ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);
	if (!revalidate_data_first(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	if (!decrypted) {
		/* IPSec is not currently enforce (feature coming soon)
		 * so for now just handle normally
		 */
		if (ip4->protocol != IPPROTO_ESP)
			goto out;
		/* Decrypt "key" is determined by SPI */
		ctx->mark = MARK_MAGIC_DECRYPT;
		ctx_change_type(ctx, PACKET_HOST);
		return CTX_ACT_OK;
	}

	ctx->mark = 0;
	return redirect(CILIUM_IFINDEX, 0);
out:
#endif
	return 0;
}
#endif

__section("from-network")
int from_network(struct __ctx_buff *ctx)
{
	__u16 proto;
	int ret = 0;

	bpf_clear_meta(ctx);

#ifdef ENABLE_IPSEC
	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT) {
		send_trace_notify(ctx, TRACE_FROM_NETWORK, get_identity(ctx), 0, 0,
				  ctx->ingress_ifindex,
				  TRACE_REASON_ENCRYPTED, TRACE_PAYLOAD_LEN);
	} else
#endif
	{
		send_trace_notify(ctx, TRACE_FROM_NETWORK, 0, 0, 0,
				  ctx->ingress_ifindex, 0, TRACE_PAYLOAD_LEN);
	}

	if (!validate_ethertype(ctx, &proto)) {
		/* Pass unknown traffic to the stack */
		ret = CTX_ACT_OK;
		return ret;
	}

	switch (proto) {
	case bpf_htons(ETH_P_IPV6):
#ifdef ENABLE_IPV6
		ret = handle_ipv6(ctx);
#endif
		break;

	case bpf_htons(ETH_P_IP):
#ifdef ENABLE_IPV4
		ret = handle_ipv4(ctx);
#endif
		break;

	default:
		/* Pass unknown traffic to the stack */
		ret = CTX_ACT_OK;
	}
	return ret;
}

BPF_LICENSE("GPL");
