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

#ifndef __NODEPORT_H_
#define __NODEPORT_H_

#include "csum.h"
#include "conntrack.h"

#ifdef ENABLE_NODEPORT
#ifdef ENABLE_IPV6
/* See comment in tail_rev_nodeport_lb4(). */
static inline int rev_nodeport_lb6(struct __sk_buff *skb)
{
	int ret, ret2, l3_off = ETH_HLEN, l4_off, hdrlen;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	struct ct_state ct_state = {};
	struct bpf_fib_lookup fib_params = {};
	__u32 monitor = 0;

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(skb, l3_off, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = l3_off + hdrlen;
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup6(get_ct_map6(&tuple), &tuple, skb, l4_off, CT_INGRESS, &ct_state,
			 &monitor);

	if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {
		ret2 = lb6_rev_nat(skb, l4_off, &csum_off, ct_state.rev_nat_index,
				   &tuple, REV_NAT_F_TUPLE_SADDR);
		if (IS_ERR(ret2))
			return ret2;

		if (!revalidate_data(skb, &data, &data_end, &ip6))
			return DROP_INVALID;

		fib_params.family = AF_INET6;
		fib_params.ifindex = NATIVE_DEV_IFINDEX;

		ipv6_addr_copy((union v6addr *) &fib_params.ipv6_src, &tuple.saddr);
		ipv6_addr_copy((union v6addr *) &fib_params.ipv6_dst, &tuple.daddr);

		int rc = fib_lookup(skb, &fib_params, sizeof(fib_params),
				    BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
		if (rc != 0)
			return DROP_NO_FIB;

		if (eth_store_daddr(skb, fib_params.dmac, 0) < 0)
			return DROP_WRITE_ERROR;
		if (eth_store_saddr(skb, fib_params.smac, 0) < 0)
			return DROP_WRITE_ERROR;
	}

	return TC_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_REVNAT)
int tail_rev_nodeport_lb6(struct __sk_buff *skb)
{
	int ret = rev_nodeport_lb6(skb);
	if (IS_ERR(ret))
		return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, METRIC_EGRESS);
	return redirect(NATIVE_DEV_IFINDEX, 0);
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
/* Reverse NAT handling of node-port traffic for the case where the
 * backend i) was a local EP and bpf_lxc redirected to us, ii) was
 * a remote backend and we got here after reverse SNAT from the
 * tail_nodeport_nat_ipv4().
 *
 * CILIUM_CALL_IPV{4,6}_NODEPORT_REVNAT is plugged into CILIUM_MAP_CALLS
 * of the bpf_netdev and of the bpf_lxc.
 */
static inline int rev_nodeport_lb4(struct __sk_buff *skb)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct csum_offset csum_off = {};
	int ret, ret2, l3_off = ETH_HLEN, l4_off;
	struct ct_state ct_state = {};
	struct bpf_fib_lookup fib_params = {};
	__u32 monitor = 0;

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, skb, l4_off, CT_INGRESS, &ct_state,
			 &monitor);

	if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {
		ret2 = lb4_rev_nat(skb, l3_off, l4_off, &csum_off,
				   &ct_state, &tuple,
				   REV_NAT_F_TUPLE_SADDR);
		if (IS_ERR(ret2))
			return ret2;

		if (!revalidate_data(skb, &data, &data_end, &ip4))
			return DROP_INVALID;

		fib_params.family = AF_INET;
		fib_params.ifindex = NATIVE_DEV_IFINDEX;

		fib_params.ipv4_src = ip4->saddr;
		fib_params.ipv4_dst = ip4->daddr;

		int rc = fib_lookup(skb, &fib_params, sizeof(fib_params),
				    BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
		if (rc != 0)
			return DROP_NO_FIB;

		if (eth_store_daddr(skb, fib_params.dmac, 0) < 0)
			return DROP_WRITE_ERROR;
		if (eth_store_saddr(skb, fib_params.smac, 0) < 0)
			return DROP_WRITE_ERROR;
	}

	return TC_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_REVNAT)
int tail_rev_nodeport_lb4(struct __sk_buff *skb)
{
	int ret = rev_nodeport_lb4(skb);
	if (IS_ERR(ret))
		return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, METRIC_EGRESS);
	return redirect(NATIVE_DEV_IFINDEX, 0);
}
#endif /* ENABLE_IPV4 */
#endif /* ENABLE_NODEPORT */
#endif /* __NODEPORT_H_ */
