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

static inline int __inline__
reverse_proxy6(struct __sk_buff *skb, int l4_off, struct ipv6hdr *ip6, __u8 nh)
{
	struct proxy6_tbl_value *val;
	struct proxy6_tbl_key key = {
		.nexthdr = nh,
	};
	union v6addr new_saddr, old_saddr;
	struct csum_offset csum = {};
	__be16 new_sport, old_sport;
	int ret;

	switch (nh) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		/* load sport + dport in reverse order, sport=dport, dport=sport */
		if (skb_load_bytes(skb, l4_off, &key.dport, 4) < 0)
			return DROP_CT_INVALID_HDR;
		break;
	default:
		/* ignore */
		return 0;
	}

	ipv6_addr_copy(&key.saddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&old_saddr, (union v6addr *) &ip6->saddr);
	csum_l4_offset_and_flags(nh, &csum);

	val = map_lookup_elem(&cilium_proxy6, &key);
	if (!val)
		return 0;

	ipv6_addr_copy(&new_saddr, (union v6addr *)&val->orig_daddr);
	new_sport = val->orig_dport;
	old_sport = key.dport;

	ret = l4_modify_port(skb, l4_off, TCP_SPORT_OFF, &csum, new_sport, old_sport);
	if (ret < 0)
		return DROP_WRITE_ERROR;

	ret = ipv6_store_saddr(skb, new_saddr.addr, ETH_HLEN);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	if (csum.offset) {
		__be32 sum = csum_diff(old_saddr.addr, 16, new_saddr.addr, 16, 0);

		if (csum_l4_replace(skb, l4_off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

	return 0;
}

#ifdef LB_IP6
static inline int __inline__ svc_lookup6(struct __sk_buff *skb, struct ipv6hdr *ip6, int l4_off)
{
	struct lb6_key key = {};
	struct lb6_service *svc;
	union v6addr *dst = (union v6addr *) &ip6->daddr;
	struct csum_offset csum_off = {};
	int ret;
	union v6addr new_dst;
	__u8 nexthdr;
	__u16 slave;

	nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&key.address, dst);
	csum_l4_offset_and_flags(nexthdr, &csum_off);

#ifdef LB_L4
	ret = extract_l4_port(skb, nexthdr, l4_off, &key.dport);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNKNOWN_L4)
			return TC_ACT_OK;
		else
			return ret;
	}
#endif

	if (!(svc = lb6_lookup_service(skb, &key)))
		return TC_ACT_OK;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_LB, skb->ingress_ifindex);

	slave = lb6_select_slave(skb, &key, svc->count, svc->weight);
	if (!(svc = lb6_lookup_slave(skb, &key, slave)))
		return TC_ACT_OK;

	ipv6_addr_copy(&new_dst, &svc->target);
	if (svc->rev_nat_index)
		new_dst.p4 |= svc->rev_nat_index;

	ret = lb6_xlate(skb, &new_dst, nexthdr, ETH_HLEN, l4_off, &csum_off, &key, svc);
	if (IS_ERR(ret))
		return ret;

	return TC_ACT_REDIRECT;
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
	int ret;

	if (data + ETH_HLEN + sizeof(*ip6) > data_end)
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	l4_off = ETH_HLEN + ipv6_hdrlen(skb, ETH_HLEN, &nexthdr);

#ifdef LB_IP6
	ret = svc_lookup6(skb, ip6, l4_off);
	if (IS_ERR(ret))
		return ret;
	else if (ret == TC_ACT_REDIRECT)
		return ret;

	/* DIRECT READ ACCESS INVALIDATED */
	data = (void *) (long) skb->data;
	data_end = (void *) (long) skb->data_end;
	ip6 = data + ETH_HLEN;

	if (data + ETH_HLEN + sizeof(*ip6) > data_end)
		return DROP_INVALID;
#endif
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

		ret = reverse_proxy6(skb, l4_off, ip6, ip6->nexthdr);
		if (IS_ERR(ret))
			return ret;

		data = (void *) (long) skb->data;
		data_end = (void *) (long) skb->data_end;
		ip6 = data + ETH_HLEN;
		if (data + sizeof(*ip6) + ETH_HLEN > data_end)
			return DROP_INVALID;

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

static inline int __inline__
reverse_proxy(struct __sk_buff *skb, int l4_off, struct iphdr *ip4,
	      struct ipv4_ct_tuple *tuple)
{
	struct proxy4_tbl_value *val;
	struct proxy4_tbl_key key = {
		.saddr = ip4->daddr,
		.nexthdr = tuple->nexthdr,
	};
	__be32 new_saddr, old_saddr = ip4->saddr;
	__be16 new_sport, old_sport;
	struct csum_offset csum = {};

	switch (tuple->nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		/* load sport + dport in reverse order, sport=dport, dport=sport */
		if (skb_load_bytes(skb, l4_off, &key.dport, 4) < 0)
			return DROP_CT_INVALID_HDR;
		break;
	default:
		/* ignore */
		return 0;
	}

	csum_l4_offset_and_flags(tuple->nexthdr, &csum);

	cilium_trace3(skb, DBG_REV_PROXY_LOOKUP, key.sport << 16 | key.dport,
		      key.saddr, key.nexthdr);

	val = map_lookup_elem(&cilium_proxy4, &key);
	if (!val)
		return 0;

	new_saddr = val->orig_daddr;
	new_sport = val->orig_dport;
	old_sport = key.dport;

	cilium_trace(skb, DBG_REV_PROXY_FOUND, new_saddr, bpf_ntohs(new_sport));
	cilium_trace_capture(skb, DBG_CAPTURE_PROXY_PRE, 0);

	if (l4_modify_port(skb, l4_off, TCP_SPORT_OFF, &csum, new_sport, old_sport) < 0)
		return DROP_WRITE_ERROR;

	if (skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &new_saddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;

	if (l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), old_saddr, new_saddr, 4) < 0)
		return DROP_CSUM_L3;

	if (csum.offset &&
	    csum_l4_replace(skb, l4_off, &csum, old_saddr, new_saddr, 4 | BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	cilium_trace_capture(skb, DBG_CAPTURE_PROXY_POST, 0);

	return 0;
}

#ifdef LB_IP4
static inline int __inline__ svc_lookup4(struct __sk_buff *skb, struct iphdr *ip4, int l4_off)
{
	struct lb4_key key = {};
	struct lb4_service *svc;
	struct csum_offset csum_off = {};
	__be32 new_dst;
	__u8 nexthdr;
	__u16 slave;
	int ret;

	nexthdr = ip4->protocol;
	key.address = ip4->daddr;
	csum_l4_offset_and_flags(nexthdr, &csum_off);

#ifdef LB_L4
	ret = extract_l4_port(skb, nexthdr, l4_off, &key.dport);
	if (IS_ERR(ret))
		return TC_ACT_OK;
#endif

	if (!(svc = lb4_lookup_service(skb, &key)))
		return TC_ACT_OK;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_LB, skb->ingress_ifindex);

	slave = lb4_select_slave(skb, &key, svc->count, svc->weight);
	if (!(svc = lb4_lookup_slave(skb, &key, slave)))
		return TC_ACT_OK;

	new_dst = svc->target;
	ret = lb4_xlate(skb, &new_dst, NULL, NULL, nexthdr, ETH_HLEN, l4_off, &csum_off, &key, svc);
	if (IS_ERR(ret))
		return ret;

	return TC_ACT_REDIRECT;
}
#endif

static inline int handle_ipv4(struct __sk_buff *skb)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct iphdr *ip4 = data + ETH_HLEN;
	int l4_off, ret;

	if (data + sizeof(*ip4) + ETH_HLEN > data_end)
		return DROP_INVALID;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

#ifdef LB_IP4
	ret = svc_lookup4(skb, ip4, l4_off);
	if (IS_ERR(ret))
		return ret;
	else if (ret == TC_ACT_REDIRECT)
		return ret;

	/* DIRECT READ ACCESS INVALIDATED */
        data = (void *) (long) skb->data;
        data_end = (void *) (long) skb->data_end;
        ip4 = data + ETH_HLEN;
        if (data + sizeof(*ip4) + ETH_HLEN > data_end)
                return DROP_INVALID;
#endif

#ifdef ENABLE_IPV4
	/* Check if destination is within our cluster prefix */
	if ((ip4->daddr & IPV4_CLUSTER_MASK) == IPV4_CLUSTER_RANGE) {
		struct ipv4_ct_tuple tuple = {};
		struct endpoint_info *ep;
		__u32 secctx;

		cilium_trace_capture(skb, DBG_CAPTURE_FROM_NETDEV, skb->ingress_ifindex);

		secctx = derive_ipv4_sec_ctx(skb, ip4);
#ifdef FROM_HOST
		if (skb->mark) {
			/* For packets from the host, the identity can be specified via skb->mark */
			secctx = skb->mark;
		}
#endif
		tuple.nexthdr = ip4->protocol;

		cilium_trace(skb, DBG_NETDEV_IN_CLUSTER, secctx, 0);

		ret = reverse_proxy(skb, l4_off, ip4, &tuple);
		/* DIRECT PACKET READ INVALID */
		if (IS_ERR(ret))
			return ret;

		data = (void *) (long) skb->data;
		data_end = (void *) (long) skb->data_end;
		ip4 = data + ETH_HLEN;
		if (data + sizeof(*ip4) + ETH_HLEN > data_end)
			return DROP_INVALID;

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

			cilium_trace(skb, DBG_NETDEV_ENCAP4, key.ip4, secctx);
			return encap_and_redirect(skb, &key, secctx);
#endif
		}
	}
#endif

	return TC_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4) int tail_handle_ipv4(struct __sk_buff *skb)
{
	int ret = handle_ipv4(skb);

	if (IS_ERR(ret)) {
		/* On error, report the error but pass the packet to the stack */
		return send_drop_notify_error(skb, ret, TC_ACT_OK);
	}

	return handle_redirect(skb, ret);
}

#endif

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	int ret;

	bpf_clear_cb(skb);

	switch (skb->protocol) {
	case bpf_htons(ETH_P_IPV6):
		/* This is considered the fast path, no tail call */
		ret = handle_ipv6(skb);
		ret = handle_redirect(skb, ret);

		/* On error, report the error but pass the packet to the stack */
		if (IS_ERR(ret))
			return send_drop_notify_error(skb, ret, TC_ACT_OK);
		break;

#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ep_tail_call(skb, CILIUM_CALL_IPV4);
		/* We are not returning an error here to always allow traffic to
		 * the stack in case maps have become unavailable.
		 *
		 * Note: Since drop notification requires a tail call as well,
		 * this notification is unlikely to succeed. */
		return send_drop_notify_error(skb, DROP_MISSED_TAIL_CALL, TC_ACT_OK);
#endif

	default:
		/* Pass unknown traffic to the stack */
		ret = TC_ACT_OK;
	}

	return ret;
}

struct bpf_elf_map __section_maps POLICY_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct policy_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 1024,
};

__section_tail(CILIUM_MAP_RES_POLICY, SECLABEL) int handle_policy(struct __sk_buff *skb)
{
	__u32 src_label = skb->cb[CB_SRC_LABEL];
	int ifindex = skb->cb[CB_IFINDEX];

	if (policy_can_access(&POLICY_MAP, skb, src_label, 0, NULL) != TC_ACT_OK) {
		return send_drop_notify(skb, src_label, SECLABEL, 0,
					ifindex, TC_ACT_SHOT);
	} else {
		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, ifindex);

		/* ifindex 0 indicates passing down to the stack */
		if (ifindex == 0)
			return TC_ACT_OK;
		else
			return redirect(ifindex, 0);
	}
}

BPF_LICENSE("GPL");
