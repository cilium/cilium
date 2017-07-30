/*
 *  Copyright (C) 2016-2017 Authors of Cilium
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

/* Disable special case where traffic from a local endpoint is loadbalanced
 * back into the same endpoint */
#define DISABLE_LOOPBACK_LB

#define QUIET_LB

#ifndef CONNTRACK
#define CONNTRACK
#endif

/* These are configuartion options which have a default value in their
 * respective header files and must thus be defined beforehand:
 *
 * Pass unknown ICMPv6 NS to stack */
#define ACTION_UNKNOWN_ICMP6_NS TC_ACT_OK

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/l4.h"
#include "lib/lb.h"
#include "lib/policy.h"
#include "lib/drop.h"
#include "lib/encap.h"
#include "lib/conntrack.h"
#include "lib/proxy.h"

/* cb[] mapping for CILIUM_CALL_IPV4 */
#define CB_REVNAT 0

static inline int __inline__ handle_redirect(struct __sk_buff *skb, int ret)
{
#ifdef LB_REDIRECT
	if (ret == TC_ACT_REDIRECT) {
		int ifindex = LB_REDIRECT;
#ifdef LB_DSTMAC
		union macaddr mac = LB_DSTMAC;

		if (eth_store_daddr(skb, (__u8 *) &mac.addr, 0) < 0)
			ret = DROP_WRITE_ERROR;
#endif
		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, ifindex);
		return redirect(ifindex, 0);
	}
#endif

	return TC_ACT_OK;
}

static inline __u32 derive_sec_ctx(struct __sk_buff *skb, const union v6addr *node_ip,
				   struct ipv6hdr *ip6)
{
#ifdef FIXED_SRC_SECCTX
	return FIXED_SRC_SECCTX;
#else
	if (ipv6_match_prefix_64((union v6addr *) &ip6->saddr, node_ip)) {
		/* Read initial 4 bytes of header and then extract flowlabel */
		__u32 *tmp = (__u32 *) ip6;
		return bpf_ntohl(*tmp & IPV6_FLOWLABEL_MASK);
	}

	return WORLD_ID;
#endif
}

#ifdef LB_IP6
static inline int __inline__ svc_lookup6(struct __sk_buff *skb, struct ipv6hdr *ip6,
					 int l4_off, __u32 secctx)
{
	struct ipv6_ct_tuple tuple = {};
	struct lb6_key key = {};
	struct lb6_service *svc;
	struct csum_offset csum_off = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	int ret, verdict = TC_ACT_OK;
	bool svc_hit = false;
	union v6addr new_dst;
	__u16 slave;

	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&key.address, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

#ifdef LB_L4
	ret = extract_l4_port(skb, tuple.nexthdr, l4_off, &key.dport);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNKNOWN_L4)
			return TC_ACT_OK;
		else
			return ret;
	}
#endif

	ct_state_new.orig_dport = key.dport;

	if (!(svc = lb6_lookup_service(skb, &key)))
		return TC_ACT_OK;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_LB, skb->ingress_ifindex);

	slave = lb6_select_slave(skb, &key, svc->count, svc->weight);
	if (!(svc = lb6_lookup_slave(skb, &key, slave))) {
		/* skip CT here, we had a match on the main service ip, this
		 * can't be a reply */
		return TC_ACT_OK;
	}

	ipv6_addr_copy(&new_dst, &svc->target);
	if (svc->rev_nat_index)
		new_dst.p4 |= svc->rev_nat_index;

	ret = lb6_xlate(skb, &new_dst, tuple.nexthdr, ETH_HLEN, l4_off, &csum_off, &key, svc);
	if (IS_ERR(ret))
		return ret;

	svc_hit = true;
	ct_state_new.rev_nat_index = svc->rev_nat_index;
	tuple.daddr = svc->target;

	verdict = TC_ACT_REDIRECT;

	ret = ct_lookup6(&CT_MAP6, &tuple, skb, l4_off, CT_INGRESS, &ct_state);
	if (ret < 0)
		return TC_ACT_OK;

	switch (ret) {
	case CT_NEW:
		/* CT entry is only created if packet was loadbalanced.  This
		 * allows to store the reverse NAT index which will perform the
		 * reverse translation of reply packets
		 */
		if (svc_hit) {
			ct_state_new.src_sec_id = secctx;
			ret = ct_create6(&CT_MAP6, &tuple, skb, CT_INGRESS, &ct_state_new, false);
			if (IS_ERR(ret))
				return TC_ACT_OK;
		}
		break;

	case CT_ESTABLISHED:
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(skb);

		if (ct_state.rev_nat_index) {
			ret = lb6_rev_nat(skb, l4_off, &csum_off,
					  ct_state.rev_nat_index, &tuple, 0);
			if (IS_ERR(ret))
				return TC_ACT_OK;
		}
		break;
	}

	return verdict;
}
#endif

static inline int handle_ipv6(struct __sk_buff *skb)
{
	union v6addr node_ip = { };
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	union v6addr *dst = (union v6addr *) &ip6->daddr;
	int l4_off;
	struct endpoint_info *ep;
	__u8 nexthdr;
	__u32 flowlabel;

	if (data + ETH_HLEN + sizeof(*ip6) > data_end)
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	l4_off = ETH_HLEN + ipv6_hdrlen(skb, ETH_HLEN, &nexthdr);

	dst = (union v6addr *) &ip6->daddr;

#ifdef HANDLE_NS
	if (unlikely(nexthdr == IPPROTO_ICMPV6)) {
		int ret = icmp6_handle(skb, ETH_HLEN, ip6);
		if (IS_ERR(ret))
			return ret;
	}
#endif

	BPF_V6(node_ip, ROUTER_IP);

	flowlabel = derive_sec_ctx(skb, &node_ip, ip6);
#ifdef FROM_HOST
	/* For packets from the host, the identity can be specified via skb->mark */
	if (skb->mark) {
		flowlabel = skb->mark;
	}
#endif

	if (likely(ipv6_match_prefix_96(dst, &node_ip))) {
		cilium_trace_capture(skb, DBG_CAPTURE_FROM_NETDEV, skb->ingress_ifindex);

#ifdef FROM_HOST
		int ret = reverse_proxy6(skb, l4_off, ip6, ip6->nexthdr);
		if (IS_ERR(ret))
			return ret;

		data = (void *) (long) skb->data;
		data_end = (void *) (long) skb->data_end;
		ip6 = data + ETH_HLEN;
		if (data + sizeof(*ip6) + ETH_HLEN > data_end)
			return DROP_INVALID;
#endif

		/* Lookup IPv4 address in list of local endpoints */
		if ((ep = lookup_ip6_endpoint(ip6)) != NULL) {
			/* Let through packets to the node-ip so they are
			 * processed by the local ip stack */
			if (ep->flags & ENDPOINT_F_HOST)
				return TC_ACT_OK;

			return ipv6_local_delivery(skb, ETH_HLEN, l4_off, flowlabel, ip6, nexthdr, ep);
		} else {
#ifdef ENCAP_IFINDEX
			struct endpoint_key key = {};

			/* IPv6 lookup key: daddr/96 */
			dst = (union v6addr *) &ip6->daddr;
			key.ip6.p1 = dst->p1;
			key.ip6.p2 = dst->p2;
			key.ip6.p3 = dst->p3;
			key.ip6.p4 = 0;
			key.family = ENDPOINT_KEY_IPV6;

			return encap_and_redirect(skb, &key, flowlabel);
#endif
		}
	}

	return TC_ACT_OK;
}

#ifdef LB_IP6
static inline int handle_lb_ip6(struct __sk_buff *skb)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	union v6addr node_ip = { };
	int l4_off;
	__u8 nexthdr;
	__u32 flowlabel;
	int ret;

	if (data + ETH_HLEN + sizeof(*ip6) > data_end)
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	l4_off = ETH_HLEN + ipv6_hdrlen(skb, ETH_HLEN, &nexthdr);
	BPF_V6(node_ip, ROUTER_IP);
	flowlabel = derive_sec_ctx(skb, &node_ip, ip6);

	/* Will look for match in list of services, on match, DIP and DPORT will
	 * be translated on TC_ACT_REDIRECT will be returned. On match, CT
	 * entry will be created.
	 */
	ret = svc_lookup6(skb, ip6, l4_off, flowlabel);
	if (IS_ERR(ret))
		return ret;
	else if (ret == TC_ACT_REDIRECT) {
		ret = handle_redirect(skb, ret);
		if (ret != TC_ACT_OK) {
			return ret;
		}
	}

	ep_tail_call(skb, CILIUM_CALL_IPV6);
	return DROP_MISSED_TAIL_CALL;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_LB_IP6) int tail_handle_lb_ip6(struct __sk_buff *skb)
{
	int ret = handle_lb_ip6(skb);

	if (IS_ERR(ret)) {
		/* On error, report the error but pass the packet to the stack */
		return send_drop_notify_error(skb, ret, TC_ACT_OK);
	}

	return ret;
}
#endif /* LB_IP6 */

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6) int tail_handle_ipv6(struct __sk_buff *skb)
{
	int ret = handle_ipv6(skb);

	if (IS_ERR(ret)) {
		/* On error, report the error but pass the packet to the stack */
		return send_drop_notify_error(skb, ret, TC_ACT_OK);
	}

	return ret;
}

#ifdef ENABLE_IPV4
static inline __u32 derive_ipv4_sec_ctx(struct __sk_buff *skb, struct iphdr *ip4)
{
#ifdef FIXED_SRC_SECCTX
	return FIXED_SRC_SECCTX;
#else
	__u32 secctx = WORLD_ID;

	if ((ip4->saddr & IPV4_CLUSTER_MASK) == IPV4_CLUSTER_RANGE) {
		/* FIXME: Derive */
	}
	return secctx;
#endif
}

#ifdef LB_IP4
static inline int __inline__ svc_lookup4(struct __sk_buff *skb, struct iphdr *ip4,
					 int l4_off, __u32 secctx)

{
	struct ipv4_ct_tuple tuple = {};
	struct lb4_key key = {};
	struct lb4_service *svc;
	struct csum_offset csum_off = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	__be32 new_dst;
	__u16 slave;
	int ret, verdict = TC_ACT_OK;
	bool svc_hit = false;

	key.address = ip4->daddr;
	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

#ifdef LB_L4
	ret = extract_l4_port(skb, tuple.nexthdr, l4_off, &key.dport);
	if (IS_ERR(ret))
		return TC_ACT_OK;
#endif

	ct_state_new.orig_dport = key.dport;

	if (!(svc = lb4_lookup_service(skb, &key)))
		return TC_ACT_OK;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_LB, skb->ingress_ifindex);

	slave = lb4_select_slave(skb, &key, svc->count, svc->weight);
	if (!(svc = lb4_lookup_slave(skb, &key, slave))) {
		/* skip CT here, we had a match on the main service ip, this
		 * can't be a reply */
		return TC_ACT_OK;
	}

	ct_state_new.addr = new_dst = svc->target;
	ret = lb4_xlate(skb, &new_dst, NULL, NULL, tuple.nexthdr, ETH_HLEN, l4_off, &csum_off, &key, svc);
	if (IS_ERR(ret))
		return ret;

	svc_hit = true;

	skb->cb[CB_REVNAT] = svc->rev_nat_index;
	ct_state_new.rev_nat_index = svc->rev_nat_index;
	tuple.daddr = svc->target;

	verdict = TC_ACT_REDIRECT;

	ret = ct_lookup4(&CT_MAP4, &tuple, skb, l4_off, CT_INGRESS, &ct_state);
	if (ret < 0)
		return TC_ACT_OK;

	switch (ret) {
	case CT_NEW:
		/* CT entry is only created if packet was loadbalanced. This
		 * allows to store the reverse NAT index which will perform
		 * the reverse translation of reply packets
		 */
		if (svc_hit) {
			ct_state_new.src_sec_id = secctx;
			ret = ct_create4(&CT_MAP4, &tuple, skb, CT_INGRESS, &ct_state_new, false);
			if (IS_ERR(ret))
				return TC_ACT_OK;
		}
		break;

	case CT_ESTABLISHED:
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(skb);

		if (ct_state.rev_nat_index) {
			ret = lb4_rev_nat(skb, ETH_HLEN, l4_off, &csum_off,
					  &ct_state, &tuple, 0);
			if (IS_ERR(ret))
				return TC_ACT_OK;
		}
		break;
	}

	return verdict;
}

static inline int handle_lb_ip4(struct __sk_buff *skb)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct iphdr *ip4 = data + ETH_HLEN;
	int l4_off, ret;
	__u32 secctx;

	if (data + sizeof(*ip4) + ETH_HLEN > data_end)
		return DROP_INVALID;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	secctx = derive_ipv4_sec_ctx(skb, ip4);

	/* Will look for match in list of services, on match, DIP and DPORT will
	 * be translated on TC_ACT_REDIRECT will be returned. On match, CT
	 * entry will be created.
	 */
	ret = svc_lookup4(skb, ip4, l4_off, secctx);
	if (IS_ERR(ret))
		return ret;
	else if (ret == TC_ACT_REDIRECT) {
		ret = handle_redirect(skb, ret);
		if (ret != TC_ACT_OK) {
			return ret;
		}
	}

	ep_tail_call(skb, CILIUM_CALL_IPV4);
	return DROP_MISSED_TAIL_CALL;
}
#endif /* LB_IP4 */

static inline int handle_ipv4(struct __sk_buff *skb, __u32 revnat)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct iphdr *ip4 = data + ETH_HLEN;
	int l4_off;

        data = (void *) (long) skb->data;
        data_end = (void *) (long) skb->data_end;
        ip4 = data + ETH_HLEN;
        if (data + sizeof(*ip4) + ETH_HLEN > data_end)
                return DROP_INVALID;

#ifdef ENABLE_IPV4
	/* Check if destination is within our cluster prefix */
	if ((ip4->daddr & IPV4_CLUSTER_MASK) == IPV4_CLUSTER_RANGE) {
		struct ipv4_ct_tuple tuple = {};
		struct endpoint_info *ep;
		__u32 secctx;

		cilium_trace_capture(skb, DBG_CAPTURE_FROM_NETDEV, skb->ingress_ifindex);

		l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
		secctx = derive_ipv4_sec_ctx(skb, ip4);
#ifdef FROM_HOST
		if (skb->mark) {
			/* For packets from the host, the identity can be specified via skb->mark */
			secctx = skb->mark;
		}
#endif
		tuple.nexthdr = ip4->protocol;

		cilium_trace(skb, DBG_NETDEV_IN_CLUSTER, secctx, 0);

#ifdef FROM_HOST
		int ret = reverse_proxy(skb, l4_off, ip4, &tuple);
		/* DIRECT PACKET READ INVALID */
		if (IS_ERR(ret))
			return ret;

		data = (void *) (long) skb->data;
		data_end = (void *) (long) skb->data_end;
		ip4 = data + ETH_HLEN;
		if (data + sizeof(*ip4) + ETH_HLEN > data_end)
			return DROP_INVALID;
#endif

		/* Lookup IPv4 address in list of local endpoints */
		if ((ep = lookup_ip4_endpoint(ip4)) != NULL) {
			/* Let through packets to the node-ip so they are
			 * processed by the local ip stack */
			if (ep->flags & ENDPOINT_F_HOST)
				return TC_ACT_OK;

			return ipv4_local_delivery(skb, ETH_HLEN, l4_off, secctx, ip4, ep);
		} else {
#ifdef ENCAP_IFINDEX
			/* IPv4 lookup key: daddr & IPV4_MASK */
			struct endpoint_key key = {};

			key.ip4 = ip4->daddr & IPV4_MASK;
			key.family = ENDPOINT_KEY_IPV4;

			if (revnat)
				secctx = (revnat & MD_ID_MASK) | MD_F_REVNAT;

			cilium_trace(skb, DBG_NETDEV_ENCAP4, key.ip4, secctx);
			return encap_and_redirect(skb, &key, secctx);
#endif /* ENCAP_IFINDEX */
		}
	}
#endif

	return TC_ACT_OK;
}

#ifdef LB_IP4
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_LB_IP4) int tail_handle_lb_ip4(struct __sk_buff *skb)
{
	int ret = handle_lb_ip4(skb);

	if (IS_ERR(ret)) {
		/* On error, report the error but pass the packet to the stack */
		return send_drop_notify_error(skb, ret, TC_ACT_OK);
	}

	return handle_redirect(skb, ret);
}
#endif /* LB_IP4 */

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4) int tail_handle_ipv4(struct __sk_buff *skb)
{
	/* revnat ID is passed in frmo CILIUM_CALL_LB_IP4 if available */
	__u32 revnat = skb->cb[CB_REVNAT];
	int ret = handle_ipv4(skb, revnat);

	if (IS_ERR(ret)) {
		/* On error, report the error but pass the packet to the stack */
		return send_drop_notify_error(skb, ret, TC_ACT_OK);
	}

	return ret;
}

#endif

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	bpf_clear_cb(skb);

	switch (skb->protocol) {
	case bpf_htons(ETH_P_IPV6):
#ifdef LB_IP4
		ep_tail_call(skb, CILIUM_CALL_LB_IP6);
#else
		ep_tail_call(skb, CILIUM_CALL_IPV6);
#endif
		break;

	case bpf_htons(ETH_P_IP):
#if defined LB_IP4
		ep_tail_call(skb, CILIUM_CALL_LB_IP4);
#elif defined ENABLE_IPV4
		ep_tail_call(skb, CILIUM_CALL_IPV4);
#endif
		break;

	default:
		/* Pass unknown traffic to the stack */
		return TC_ACT_OK;
	}

	/* We are not returning an error here to always allow traffic to
	 * the stack in case maps have become unavailable.
	 *
	 * Note: Since drop notification requires a tail call as well,
	 * this notification is unlikely to be reported
	 */
	return send_drop_notify_error(skb, DROP_MISSED_TAIL_CALL, TC_ACT_OK);
}

struct bpf_elf_map __section_maps POLICY_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct policy_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 1024,
};

static inline int __inline__ ipv6_policy(struct __sk_buff *skb, int ifindex, __u32 src_label)
{
	struct ipv6_ct_tuple tuple = {};
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	struct csum_offset csum_off = {};
	int ret, l4_off, verdict;
	struct ct_state ct_state = {};
	struct ct_state ct_state_new = {};

	if (data + sizeof(struct ipv6hdr) + ETH_HLEN > data_end)
		return DROP_INVALID;

	policy_clear_mark(skb);
	tuple.nexthdr = ip6->nexthdr;

	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);

	l4_off = ETH_HLEN + ipv6_hdrlen(skb, ETH_HLEN, &tuple.nexthdr);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup6(&CT_MAP6, &tuple, skb, l4_off, CT_EGRESS, &ct_state);
	if (ret < 0 && ret != DROP_CT_CANT_CREATE)
		return ret;

	if (unlikely(ct_state.rev_nat_index)) {
		int ret2;

		ret2 = lb6_rev_nat(skb, l4_off, &csum_off,
				   ct_state.rev_nat_index, &tuple, 0);
		if (IS_ERR(ret2))
			return ret2;
	}

	/* Policy lookup is done on every packet to account for packets that
	 * passed through the allowed consumer. */
	verdict = policy_can_access(&POLICY_MAP, skb, src_label, sizeof(tuple.saddr), &tuple.saddr);
	if (unlikely(ret == CT_NEW)) {
		if (verdict != TC_ACT_OK)
			return DROP_POLICY;

		ct_state_new.orig_dport = tuple.dport;
		ct_state_new.src_sec_id = src_label;
		/* ignore error for now */
		ct_create6(&CT_MAP6, &tuple, skb, CT_EGRESS, &ct_state_new, false);
	}

	if (verdict != TC_ACT_OK && !(ret == CT_REPLY || ret == CT_RELATED))
		return DROP_POLICY;

	return 0;
}

static inline int __inline__ ipv4_policy(struct __sk_buff *skb, int ifindex, __u32 src_label)
{
	struct ipv4_ct_tuple tuple = {};
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct iphdr *ip4 = data + ETH_HLEN;
	struct csum_offset csum_off = {};
	int ret, verdict, l4_off;
	struct ct_state ct_state = {};
	struct ct_state ct_state_new = {};

	if (data + sizeof(*ip4) + ETH_HLEN > data_end)
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;

	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup4(&CT_MAP4, &tuple, skb, l4_off, CT_EGRESS, &ct_state);
	if (ret < 0 && ret != DROP_CT_CANT_CREATE)
		return ret;

	if (unlikely(ret == CT_REPLY && ct_state.rev_nat_index)) {
		int ret2;

		ret2 = lb4_rev_nat(skb, ETH_HLEN, l4_off, &csum_off,
				   &ct_state, &tuple,
				   REV_NAT_F_TUPLE_SADDR);
		if (IS_ERR(ret2))
			return ret2;

	}

	/* Policy lookup is done on every packet to account for packets that
	 * passed through the allowed consumer. */
	verdict = policy_can_access(&POLICY_MAP, skb, src_label, sizeof(tuple.saddr), &tuple.saddr);
	if (unlikely(ret == CT_NEW)) {
		if (verdict != TC_ACT_OK)
			return DROP_POLICY;

		ct_state_new.orig_dport = tuple.dport;
		ct_state_new.src_sec_id = src_label;
		/* ignore error for now */
		ct_create4(&CT_MAP4, &tuple, skb, CT_EGRESS, &ct_state_new, false);

		/* NOTE: tuple has been invalidated after this */
	}

	if (verdict != TC_ACT_OK && !(ret == CT_REPLY || ret == CT_RELATED))
		return DROP_POLICY;

	return 0;
}

__section_tail(CILIUM_MAP_RES_POLICY, SECLABEL) int handle_policy(struct __sk_buff *skb)
{
	__u32 src_label = skb->cb[CB_SRC_LABEL];
	int ret, ifindex = skb->cb[CB_IFINDEX];

	switch (skb->protocol) {
	case bpf_htons(ETH_P_IPV6):
		ret = ipv6_policy(skb, ifindex, src_label);
		break;

	case bpf_htons(ETH_P_IP):
		ret = ipv4_policy(skb, ifindex, src_label);
		break;

	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

	if (IS_ERR(ret)) {
		if (ret == DROP_POLICY)
			return send_drop_notify(skb, src_label, SECLABEL, 0,
						ifindex, TC_ACT_SHOT);
		else
			return send_drop_notify_error(skb, ret, TC_ACT_SHOT);
	}

	cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, ifindex);

	/* ifindex 0 indicates passing down to the stack */
	if (ifindex == 0)
		return TC_ACT_OK;
	else
		return redirect(ifindex, 0);
}

BPF_LICENSE("GPL");
