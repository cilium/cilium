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

#include "nat.h"
#include "lb.h"
#include "conntrack.h"
#include "csum.h"

#define CB_SRC_IDENTITY	0

/* No nodeport on cilium_host interface. */
#ifdef FROM_HOST
# undef ENABLE_NODEPORT
#endif

static inline void tc_index_clear_nodeport(struct __sk_buff *skb)
{
#ifdef ENABLE_NODEPORT
	skb->tc_index &= ~TC_INDEX_F_SKIP_NODEPORT;
#endif
}

#ifdef ENABLE_NODEPORT
static inline bool __inline__ tc_index_skip_nodeport(struct __sk_buff *skb)
{
	volatile __u32 tc_index = skb->tc_index;
	tc_index_clear_nodeport(skb);
	return tc_index & TC_INDEX_F_SKIP_NODEPORT;
}
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_NODEPORT
#ifdef ENABLE_IPV6
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_NAT)
int tail_nodeport_nat_ipv6(struct __sk_buff *skb)
{
	struct bpf_fib_lookup fib_params = {};
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.force_range = true,
	};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, dir = skb->cb[CB_NAT];

	BPF_V6(target.addr, IPV6_NODEPORT);

	ret = snat_v6_process(skb, dir, &target);
	if (IS_ERR(ret)) {
		/* In case of no mapping, recircle back to main path. SNAT is very
		 * expensive in terms of instructions (since we don't have BPF to
		 * BPF calls as we use tail calls) and complexity, hence this is
		 * done inside a tail call here.
		 */
		if (dir == NAT_DIR_INGRESS) {
			skb->tc_index |= TC_INDEX_F_SKIP_NODEPORT;
			ep_tail_call(skb, CILIUM_CALL_IPV6_FROM_LXC);
			ret = DROP_MISSED_TAIL_CALL;
		}
		goto drop_err;
	}

	if (dir == NAT_DIR_INGRESS) {
		ep_tail_call(skb, CILIUM_CALL_IPV6_NODEPORT_REVNAT);
		ret = DROP_MISSED_TAIL_CALL;
		goto drop_err;
	}

	if (!revalidate_data(skb, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	fib_params.family = AF_INET6;
	fib_params.ifindex = NATIVE_DEV_IFINDEX;
	ipv6_addr_copy((union v6addr *) &fib_params.ipv6_src, (union v6addr *) &ip6->saddr);
	ipv6_addr_copy((union v6addr *) &fib_params.ipv6_dst, (union v6addr *) &ip6->daddr);

	ret = fib_lookup(skb, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (ret != 0) {
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	if (eth_store_daddr(skb, fib_params.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(skb, fib_params.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}

	return redirect(fib_params.ifindex, 0);
drop_err:
	return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT,
				      dir == NAT_DIR_INGRESS ?
				      METRIC_INGRESS : METRIC_EGRESS);
}

/* See nodeport_lb4(). */
static inline int nodeport_lb6(struct __sk_buff *skb, __u32 src_identity)
{
	int ret, l3_off = ETH_HLEN, l4_off, hdrlen;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	struct lb6_service_v2 *svc;
	struct lb6_key_v2 key = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	bool backend_local;
	__u32 monitor = 0;
	__u16 service_port;

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(skb, l3_off, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = l3_off + hdrlen;

	ret = lb6_extract_key_v2(skb, &tuple, l4_off, &key, &csum_off, CT_EGRESS);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNKNOWN_L4)
			return TC_ACT_OK;
		else
			return ret;
	}

	service_port = bpf_ntohs(key.dport);
	if (service_port < NODEPORT_PORT_MIN ||
	    service_port > NODEPORT_PORT_MAX) {
		if (service_port >= NODEPORT_PORT_MIN_NAT &&
		    service_port <= NODEPORT_PORT_MAX_NAT) {
			skb->cb[CB_NAT] = NAT_DIR_INGRESS;
			skb->cb[CB_SRC_IDENTITY] = src_identity;
			ep_tail_call(skb, CILIUM_CALL_IPV6_NODEPORT_NAT);
			return DROP_MISSED_TAIL_CALL;
		}
		return TC_ACT_OK;
	}

	ct_state_new.orig_dport = key.dport;

	if ((svc = lb6_lookup_service_v2(skb, &key)) != NULL) {
		ret = lb6_local(get_ct_map6(&tuple), skb, l3_off, l4_off,
				&csum_off, &key, &tuple, svc, &ct_state_new);
		if (IS_ERR(ret))
			return ret;
	} else {
		return TC_ACT_OK;
	}

	ret = ct_lookup6(get_ct_map6(&tuple), &tuple, skb, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;
	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	backend_local = lookup_ip6_endpoint(ip6);

	switch (ret) {
	case CT_NEW:
		ct_state_new.src_sec_id = SECLABEL;
		ct_state_new.node_port = 1;
		ret = ct_create6(get_ct_map6(&tuple), &tuple, skb, CT_EGRESS,
				 &ct_state_new);
		if (IS_ERR(ret))
			return ret;
		if (backend_local) {
			ct_flip_tuple_dir6(&tuple);
			ct_state_new.rev_nat_index = 0;
			ret = ct_create6(get_ct_map6(&tuple), &tuple, skb,
					 CT_INGRESS, &ct_state_new);
			if (IS_ERR(ret))
				return ret;
		}
		break;

	case CT_ESTABLISHED:
	case CT_REPLY:
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	if (!backend_local) {
		skb->cb[CB_NAT] = NAT_DIR_EGRESS;
		ep_tail_call(skb, CILIUM_CALL_IPV6_NODEPORT_NAT);
		return DROP_MISSED_TAIL_CALL;
	}

	return TC_ACT_OK;
}

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
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_NAT)
int tail_nodeport_nat_ipv4(struct __sk_buff *skb)
{
	struct bpf_fib_lookup fib_params = {};
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.addr = IPV4_NODEPORT,
		.force_range = true,
	};
	void *data, *data_end;
	struct iphdr *ip4;
	int ret, dir = skb->cb[CB_NAT];

	ret = snat_v4_process(skb, dir, &target);
	if (IS_ERR(ret)) {
		/* In case of no mapping, recircle back to main path. SNAT is very
		 * expensive in terms of instructions (since we don't have BPF to
		 * BPF calls as we use tail calls) and complexity, hence this is
		 * done inside a tail call here.
		 */
		if (dir == NAT_DIR_INGRESS) {
			skb->tc_index |= TC_INDEX_F_SKIP_NODEPORT;
			ep_tail_call(skb, CILIUM_CALL_IPV4_FROM_LXC);
			ret = DROP_MISSED_TAIL_CALL;
		}
		goto drop_err;
	}

	if (dir == NAT_DIR_INGRESS) {
		ep_tail_call(skb, CILIUM_CALL_IPV4_NODEPORT_REVNAT);
		ret = DROP_MISSED_TAIL_CALL;
		goto drop_err;
	}

	if (!revalidate_data(skb, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	fib_params.family = AF_INET;
	fib_params.ifindex = NATIVE_DEV_IFINDEX;
	fib_params.ipv4_src = ip4->saddr;
	fib_params.ipv4_dst = ip4->daddr;

	ret = fib_lookup(skb, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (ret != 0) {
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	if (eth_store_daddr(skb, fib_params.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(skb, fib_params.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}

	return redirect(fib_params.ifindex, 0);
drop_err:
	return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT,
				      dir == NAT_DIR_INGRESS ?
				      METRIC_INGRESS : METRIC_EGRESS);
}

/* Main node-port entry point for host-external ingressing node-port traffic
 * which handles the case of: i) backend is local EP, ii) backend is remote EP,
 * iii) reply from remote backend EP.
 */
static inline int nodeport_lb4(struct __sk_buff *skb, __u32 src_identity)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	int ret,  l3_off = ETH_HLEN, l4_off;
	struct csum_offset csum_off = {};
	struct lb4_service_v2 *svc;
	struct lb4_key_v2 key = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	bool backend_local;
	__u32 monitor = 0;
	__u16 service_port;

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);

	ret = lb4_extract_key_v2(skb, &tuple, l4_off, &key, &csum_off, CT_EGRESS);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNKNOWN_L4)
			return TC_ACT_OK;
		else
			return ret;
	}

	service_port = bpf_ntohs(key.dport);
	if (service_port < NODEPORT_PORT_MIN ||
	    service_port > NODEPORT_PORT_MAX) {
		if (service_port >= NODEPORT_PORT_MIN_NAT &&
		    service_port <= NODEPORT_PORT_MAX_NAT) {
			skb->cb[CB_NAT] = NAT_DIR_INGRESS;
			skb->cb[CB_SRC_IDENTITY] = src_identity;
			ep_tail_call(skb, CILIUM_CALL_IPV4_NODEPORT_NAT);
			return DROP_MISSED_TAIL_CALL;
		}
		return TC_ACT_OK;
	}

	ct_state_new.orig_dport = key.dport;

	if ((svc = lb4_lookup_service_v2(skb, &key)) != NULL) {
		ret = lb4_local(get_ct_map4(&tuple), skb, l3_off, l4_off, &csum_off,
				&key, &tuple, svc, &ct_state_new, ip4->saddr);
		if (IS_ERR(ret))
			return ret;
	} else {
		return TC_ACT_OK;
	}

	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, skb, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;
	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	backend_local = lookup_ip4_endpoint(ip4);

	switch (ret) {
	case CT_NEW:
		ct_state_new.src_sec_id = SECLABEL;
		ct_state_new.node_port = 1;
		ret = ct_create4(get_ct_map4(&tuple), &tuple, skb, CT_EGRESS,
				 &ct_state_new);
		if (IS_ERR(ret))
			return ret;
		if (backend_local) {
			ct_flip_tuple_dir4(&tuple);
			ct_state_new.rev_nat_index = 0;
			ret = ct_create4(get_ct_map4(&tuple), &tuple, skb,
					 CT_INGRESS, &ct_state_new);
			if (IS_ERR(ret))
				return ret;
		}
		break;

	case CT_ESTABLISHED:
	case CT_REPLY:
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	if (!backend_local) {
		skb->cb[CB_NAT] = NAT_DIR_EGRESS;
		ep_tail_call(skb, CILIUM_CALL_IPV4_NODEPORT_NAT);
		return DROP_MISSED_TAIL_CALL;
	}

	return TC_ACT_OK;
}

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
