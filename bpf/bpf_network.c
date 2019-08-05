/*
 *  Copyright (C) 2019 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <node_config.h>
#include <netdev_config.h>

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include <linux/if_packet.h>

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
static inline int handle_ipv6(struct __sk_buff *skb)
{
#ifdef ENABLE_IPSEC
	void *data_end, *data;
	struct ipv6hdr *ip6;
	bool decrypted;

	decrypted = ((skb->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);
	if (!revalidate_data_first(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	if (!decrypted) {
		/* IPSec is not currently enforce (feature coming soon)
		 * so for now just handle normally
		 */
		if (ip6->nexthdr != IPPROTO_ESP)
			return 0;

		/* Decrypt "key" is determined by SPI */
		skb->mark = MARK_MAGIC_DECRYPT;

		/* We are going to pass this up the stack for IPsec decryption
		 * but eth_type_trans may already have labeled this as an
		 * OTHERHOST type packet. To avoid being dropped by IP stack
		 * before IPSec can be processed mark as a HOST packet.
		 */
		skb_change_type(skb, PACKET_HOST);
		return TC_ACT_OK;
	} else{
		skb->mark = 0;
		return redirect(CILIUM_IFINDEX, 0);
	}
#endif
	return 0;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static inline int handle_ipv4(struct __sk_buff *skb)
{
#ifdef ENABLE_IPSEC
	void *data_end, *data;
	struct iphdr *ip4;
	bool decrypted;

	decrypted = ((skb->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);
	if (!revalidate_data_first(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	if (!decrypted) {
		/* IPSec is not currently enforce (feature coming soon)
		 * so for now just handle normally
		 */
		if (ip4->protocol != IPPROTO_ESP)
			goto out;
		/* Decrypt "key" is determined by SPI */
		skb->mark = MARK_MAGIC_DECRYPT;
		skb_change_type(skb, PACKET_HOST);
		return TC_ACT_OK;
	} else {
		skb->mark = 0;
		return redirect(CILIUM_IFINDEX, 0);
	}
out:
#endif
	return 0;
}
#endif

__section("from-network")
int from_network(struct __sk_buff *skb)
{
	__u16 proto;
	int ret = 0;

	bpf_clear_cb(skb);

#ifdef ENABLE_IPSEC
	if ((skb->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT) {
		send_trace_notify(skb, TRACE_FROM_NETWORK, get_identity(skb), 0, 0,
				  skb->ingress_ifindex,
				  TRACE_REASON_ENCRYPTED, TRACE_PAYLOAD_LEN);
	} else
#endif
	{
		send_trace_notify(skb, TRACE_FROM_NETWORK, 0, 0, 0,
				  skb->ingress_ifindex, 0, TRACE_PAYLOAD_LEN);
	}

	if (!validate_ethertype(skb, &proto)) {
		/* Pass unknown traffic to the stack */
		ret = TC_ACT_OK;
		return ret;
	}

	switch (proto) {
	case bpf_htons(ETH_P_IPV6):
#ifdef ENABLE_IPV6
		ret = handle_ipv6(skb);
#endif
		break;

	case bpf_htons(ETH_P_IP):
#ifdef ENABLE_IPV4
		ret = handle_ipv4(skb);
#endif
		break;

	default:
		/* Pass unknown traffic to the stack */
		ret = TC_ACT_OK;
	}
	return ret;
}

BPF_LICENSE("GPL");
