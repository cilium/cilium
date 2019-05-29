/*
 *  Copyright (C) 2016-2019 Authors of Cilium
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

/**
 * Description: Standalone loadbalancer that can be attached to any
 *              net_device. Will perform a map lookup on the destination
 *              IP and optional destination port for every IPv4 and
 *              IPv6 packet received. If a matching entry is found, the
 *              destination address will be written to one of the
 *              configures slaves. Optionally the destination port can be
 *              mapped to a slave specific port as well. The packet is
 *              then passed back to the stack.
 *
 * Configuration:
 *  - LB_REDIRECT     - Redirect to an ifindex
 *  - LB_L4           - Enable L4 matching and mapping
 */

#define DISABLE_LOOPBACK_LB

#include <node_config.h>
#include <netdev_config.h>

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/l4.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/drop.h"
#include "lib/lb.h"

#ifdef ENABLE_IPV6
static inline int handle_ipv6(struct __sk_buff *skb)
{
	void *data, *data_end;
	struct lb6_key_v2 key = {};
	struct lb6_service_v2 *svc;
	struct lb6_backend *backend;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	int l3_off, l4_off, ret, hdrlen;
	union v6addr new_dst;
	__u8 nexthdr;
	__u16 slave;

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	cilium_dbg_capture(skb, DBG_CAPTURE_FROM_LB, skb->ingress_ifindex);

	nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&key.address, (union v6addr *) &ip6->daddr);
	l3_off = ETH_HLEN;
	hdrlen = ipv6_hdrlen(skb, ETH_HLEN, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = ETH_HLEN + hdrlen;
	csum_l4_offset_and_flags(nexthdr, &csum_off);

#ifdef LB_L4
	ret = extract_l4_port(skb, nexthdr, l4_off, &key.dport);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNKNOWN_L4) {
			/* Pass unknown L4 to stack */
			return TC_ACT_OK;
		} else
			return ret;
	}
#endif

	svc = lb6_lookup_service_v2(skb, &key);
	if (svc == NULL) {
		/* Pass packets to the stack which should not be loadbalanced */
		return TC_ACT_OK;
	}

	slave = lb6_select_slave(skb, svc->count, svc->weight);
	if (!(svc = lb6_lookup_slave_v2(skb, &key, slave)))
		return DROP_NO_SERVICE;
	if (!(backend = lb6_lookup_backend(skb, svc->backend_id)))
		return DROP_NO_SERVICE;

	ipv6_addr_copy(&new_dst, &backend->address);
	if (svc->rev_nat_index)
		new_dst.p4 |= svc->rev_nat_index;

	ret = lb6_xlate_v2(skb, &new_dst, nexthdr, l3_off, l4_off, &csum_off, &key,
						svc, backend);
	if (IS_ERR(ret))
		return ret;

	return TC_ACT_REDIRECT;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static inline int handle_ipv4(struct __sk_buff *skb)
{
	void *data;
	void *data_end;
	struct lb4_key_v2 key = {};
	struct lb4_service_v2 *svc;
	struct lb4_backend *backend;
	struct iphdr *ip;
	struct csum_offset csum_off = {};
	int l3_off, l4_off, ret;
	__be32 new_dst;
	__u8 nexthdr;
	__u16 slave;

	if (!revalidate_data(skb, &data, &data_end, &ip))
		return DROP_INVALID;

	cilium_dbg_capture(skb, DBG_CAPTURE_FROM_LB, skb->ingress_ifindex);

	nexthdr = ip->protocol;
	key.address = ip->daddr;
	l3_off = ETH_HLEN;
	l4_off = ETH_HLEN + ipv4_hdrlen(ip);
	csum_l4_offset_and_flags(nexthdr, &csum_off);

#ifdef LB_L4
	ret = extract_l4_port(skb, nexthdr, l4_off, &key.dport);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNKNOWN_L4) {
			/* Pass unknown L4 to stack */
			return TC_ACT_OK;
		} else
			return ret;
	}
#endif

	svc = lb4_lookup_service_v2(skb, &key);
	if (svc == NULL) {
		/* Pass packets to the stack which should not be loadbalanced */
		return TC_ACT_OK;
	}

	slave = lb4_select_slave(skb, svc->count, svc->weight);
	if (!(svc = lb4_lookup_slave_v2(skb, &key, slave)))
		return DROP_NO_SERVICE;
	if (!(backend = lb4_lookup_backend(skb, svc->backend_id)))
		return DROP_NO_SERVICE;

	new_dst = backend->address;
	ret = lb4_xlate_v2(skb, &new_dst, NULL, NULL, nexthdr, l3_off, l4_off,
						&csum_off, &key, svc, backend);
	if (IS_ERR(ret))
		return ret;

	return TC_ACT_REDIRECT;
}
#endif /* ENABLE_IPV4 */

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	__u16 proto;
	int ret;

	bpf_clear_cb(skb);

	if (!validate_ethertype(skb, &proto))
		/* Pass unknown traffic to the stack */
		return TC_ACT_OK;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = handle_ipv6(skb);
		break;
#endif

#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = handle_ipv4(skb);
		break;
#endif

	default:
		/* Pass unknown traffic to the stack */
		return TC_ACT_OK;
	}

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, METRIC_INGRESS);

#ifdef LB_REDIRECT
	if (ret == TC_ACT_REDIRECT) {
		int ifindex = LB_REDIRECT;
#ifdef LB_DSTMAC
		union macaddr mac = LB_DSTMAC;

		if (eth_store_daddr(skb, (__u8 *) &mac.addr, 0) < 0)
			ret = DROP_WRITE_ERROR;
#endif
		cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, ifindex);
		return redirect(ifindex, 0);
	}
#endif
	cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, 0);
	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
