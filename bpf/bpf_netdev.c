/*
 *  Copyright (C) 2016-2018 Authors of Cilium
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

/* These are configuartion options which have a default value in their
 * respective header files and must thus be defined beforehand:
 *
 * Pass unknown ICMPv6 NS to stack */
#define ACTION_UNKNOWN_ICMP6_NS TC_ACT_OK

/* Include policy_can_access_ingress() */
#define REQUIRES_CAN_ACCESS

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/arp.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/trace.h"
#include "lib/l3.h"
#include "lib/l4.h"
#include "lib/policy.h"
#include "lib/drop.h"
#include "lib/encap.h"


#if defined FROM_HOST && (defined ENABLE_IPV4 || defined ENABLE_IPV6)
static inline int rewrite_dmac_to_host(struct __sk_buff *skb)
{
	/* When attached to cilium_host, we rewrite the DMAC to the mac of
	 * cilium_host (peer) to ensure the packet is being considered to be
	 * addressed to the host (PACKET_HOST) */
	union macaddr cilium_net_mac = CILIUM_NET_MAC;

	/* Rewrite to destination MAC of cilium_net (remote peer) */
	if (eth_store_daddr(skb, (__u8 *) &cilium_net_mac.addr, 0) < 0)
		return send_drop_notify_error(skb, DROP_WRITE_ERROR, TC_ACT_OK, METRIC_INGRESS);

	return TC_ACT_OK;
}
#endif


#ifdef ENABLE_IPV6
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

#ifdef FROM_HOST
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

	val = map_lookup_elem(&PROXY6_MAP, &key);
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

	/* Packets which have been translated back from the proxy must
	 * skip any potential ingress proxy at the endpoint
	 */
	skb->tc_index |= TC_INDEX_F_SKIP_PROXY;

	return 0;
}
#endif

static inline int handle_ipv6(struct __sk_buff *skb, __u32 src_identity)
{
	struct remote_endpoint_info *info;
	union v6addr node_ip = { };
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr *dst;
	int l4_off, l3_off = ETH_HLEN, hdrlen;
	struct endpoint_info *ep;
	__u8 nexthdr;
	__u32 flowlabel;

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(skb, l3_off, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = l3_off + hdrlen;

#ifdef HANDLE_NS
	if (unlikely(nexthdr == IPPROTO_ICMPV6)) {
		int ret = icmp6_handle(skb, ETH_HLEN, ip6, METRIC_INGRESS);
		if (IS_ERR(ret))
			return ret;
	}
#endif

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(src_identity)) {
		union v6addr *src = (union v6addr *) &ip6->saddr;
		info = ipcache_lookup6(&IPCACHE_MAP, src, V6_CACHE_KEY_LEN);
		if (info != NULL) {
			__u32 sec_label = info->sec_label;
			if (sec_label)
				src_identity = info->sec_label;
		}
		cilium_dbg(skb, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   ((__u32 *) src)[3], src_identity);
	}

	BPF_V6(node_ip, ROUTER_IP);
	flowlabel = derive_sec_ctx(skb, &node_ip, ip6);

#ifdef FROM_HOST
	if (1) {
		int ret;

		flowlabel = src_identity;
		ret = reverse_proxy6(skb, l4_off, ip6, ip6->nexthdr);
		/* DIRECT PACKET READ INVALID */
		if (IS_ERR(ret))
			return ret;

		/* If we are attached to cilium_host at egress, this will
		 * rewrite the destination mac address to the MAC of cilium_net */
		ret = rewrite_dmac_to_host(skb);
		/* DIRECT PACKET READ INVALID */
		if (IS_ERR(ret))
			return ret;
	}

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;
#endif

	/* Lookup IPv4 address in list of local endpoints */
	if ((ep = lookup_ip6_endpoint(ip6)) != NULL) {
		/* Let through packets to the node-ip so they are
		 * processed by the local ip stack */
		if (ep->flags & ENDPOINT_F_HOST)
			return TC_ACT_OK;

		return ipv6_local_delivery(skb, l3_off, l4_off, flowlabel, ip6, nexthdr, ep, METRIC_INGRESS);
	}

#ifdef ENCAP_IFINDEX
	dst = (union v6addr *) &ip6->daddr;
	info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
	if (info != NULL && info->tunnel_endpoint != 0) {
		return encap_and_redirect_with_nodeid(skb, info->tunnel_endpoint,
						      flowlabel, TRACE_PAYLOAD_LEN);
	} else if (likely(ipv6_match_prefix_96(dst, &node_ip))) {
		struct endpoint_key key = {};
		int ret;

		/* IPv6 lookup key: daddr/96 */
		dst = (union v6addr *) &ip6->daddr;
		key.ip6.p1 = dst->p1;
		key.ip6.p2 = dst->p2;
		key.ip6.p3 = dst->p3;
		key.ip6.p4 = 0;
		key.family = ENDPOINT_KEY_IPV6;

		ret = encap_and_redirect(skb, &key, flowlabel, TRACE_PAYLOAD_LEN);
		if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif

#ifdef FROM_HOST
	/* The destination IP address could not be associated with a local
	 * endpoint or a tunnel destination. If it is destined to an IP in
	 * the local range, then we can't route it back to the host as it
	 * will create a routing loop. Drop it. */
	dst = (union v6addr *) &ip6->daddr;
	if (ipv6_match_prefix_96(dst, &node_ip))
		return DROP_NON_LOCAL;
#endif
	return TC_ACT_OK;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static inline __u32 derive_ipv4_sec_ctx(struct __sk_buff *skb, struct iphdr *ip4)
{
#ifdef FIXED_SRC_SECCTX
	return FIXED_SRC_SECCTX;
#else
	return WORLD_ID;
#endif
}

#ifdef FROM_HOST
static inline int __inline__
reverse_proxy(struct __sk_buff *skb, int l4_off, struct iphdr *ip4, __u8 nh)
{
	struct proxy4_tbl_value *val;
	struct proxy4_tbl_key key = {
		.saddr = ip4->daddr,
		.nexthdr = nh,
	};
	__be32 new_saddr, old_saddr = ip4->saddr;
	__be16 new_sport, old_sport;
	struct csum_offset csum = {};

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

	csum_l4_offset_and_flags(nh, &csum);

	cilium_dbg3(skb, DBG_REV_PROXY_LOOKUP, key.sport << 16 | key.dport,
		      key.saddr, key.nexthdr);

	val = map_lookup_elem(&PROXY4_MAP, &key);
	if (!val)
		return 0;

	new_saddr = val->orig_daddr;
	new_sport = val->orig_dport;
	old_sport = key.dport;

	cilium_dbg(skb, DBG_REV_PROXY_FOUND, new_saddr, bpf_ntohs(new_sport));
	cilium_dbg_capture(skb, DBG_CAPTURE_PROXY_PRE, 0);

	if (l4_modify_port(skb, l4_off, TCP_SPORT_OFF, &csum, new_sport, old_sport) < 0)
		return DROP_WRITE_ERROR;

	if (skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &new_saddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;

	if (l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), old_saddr, new_saddr, 4) < 0)
		return DROP_CSUM_L3;

	if (csum.offset &&
	    csum_l4_replace(skb, l4_off, &csum, old_saddr, new_saddr, 4 | BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	/* Packets which have been translated back from the proxy must
	 * skip any potential ingress proxy at the endpoint
	 */
	skb->tc_index |= TC_INDEX_F_SKIP_PROXY;

	cilium_dbg_capture(skb, DBG_CAPTURE_PROXY_POST, 0);

	return 0;
}
#endif

static inline int handle_ipv4(struct __sk_buff *skb, __u32 src_identity)
{
	struct remote_endpoint_info *info;
	struct ipv4_ct_tuple tuple = {};
	struct endpoint_info *ep;
	void *data, *data_end;
	struct iphdr *ip4;
	int l4_off;
	__u32 secctx;

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	secctx = derive_ipv4_sec_ctx(skb, ip4);
	tuple.nexthdr = ip4->protocol;

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(src_identity)) {
		info = ipcache_lookup4(&IPCACHE_MAP, ip4->saddr, V4_CACHE_KEY_LEN);
		if (info != NULL) {
			__u32 sec_label = info->sec_label;
			if (sec_label) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "src_identity"
				 * (passed into this function) reports the src
				 * as the host. So we can ignore the ipcache
				 * if it reports the source as HOST_ID.
				 */
				if (sec_label != HOST_ID)
					src_identity = sec_label;
			}
		}
		cilium_dbg(skb, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->saddr, src_identity);
	}

#ifdef FROM_HOST
	if (1) {
		int ret;

		secctx = src_identity;
		ret = reverse_proxy(skb, l4_off, ip4, tuple.nexthdr);
		/* DIRECT PACKET READ INVALID */
		if (IS_ERR(ret))
			return ret;

		/* If we are attached to cilium_host at egress, this will
		 * rewrite the destination mac address to the MAC of cilium_net */
		ret = rewrite_dmac_to_host(skb);
		/* DIRECT PACKET READ INVALID */
		if (IS_ERR(ret))
			return ret;
	}

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;
#endif

	/* Lookup IPv4 address in list of local endpoints and host IPs */
	if ((ep = lookup_ip4_endpoint(ip4)) != NULL) {
		/* Let through packets to the node-ip so they are
		 * processed by the local ip stack */
		if (ep->flags & ENDPOINT_F_HOST)
#ifdef HOST_REDIRECT_TO_INGRESS
			/* This is required for L7 proxy to send packets to the host. */
			return redirect(HOST_IFINDEX, BPF_F_INGRESS);
#else
			return TC_ACT_OK;
#endif

		return ipv4_local_delivery(skb, ETH_HLEN, l4_off, secctx, ip4, ep, METRIC_INGRESS);
	}

#ifdef ENCAP_IFINDEX
	info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
	if (info != NULL && info->tunnel_endpoint != 0) {
		return encap_and_redirect_with_nodeid(skb, info->tunnel_endpoint,
						      secctx, TRACE_PAYLOAD_LEN);
	} else {
		/* IPv4 lookup key: daddr & IPV4_MASK */
		struct endpoint_key key = {};
		int ret;

		key.ip4 = ip4->daddr & IPV4_MASK;
		key.family = ENDPOINT_KEY_IPV4;

		cilium_dbg(skb, DBG_NETDEV_ENCAP4, key.ip4, secctx);
		ret = encap_and_redirect(skb, &key, secctx, TRACE_PAYLOAD_LEN);
		if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif

#ifdef HOST_REDIRECT_TO_INGRESS
    return redirect(HOST_IFINDEX, BPF_F_INGRESS);
#else

#ifdef FROM_HOST
	/* The destination IP address could not be associated with a local
	 * endpoint or a tunnel destination. If it is destined to an IP in
	 * the local range, then we can't route it back to the host as it
	 * will create a routing loop. Drop it. */
	if ((ip4->daddr & IPV4_MASK) == (IPV4_GATEWAY & IPV4_MASK))
		return DROP_NON_LOCAL;
#endif
	return TC_ACT_OK;
#endif
}

#define CB_SRC_IDENTITY 0

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_LXC) int tail_handle_ipv4(struct __sk_buff *skb)
{
	__u32 proxy_identity = skb->cb[CB_SRC_IDENTITY];
	int ret = handle_ipv4(skb, proxy_identity);

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT, METRIC_INGRESS);

	return ret;
}

#endif /* ENABLE_IPV4 */

#ifdef FROM_HOST
static inline bool __inline__ handle_identity_from_host(struct __sk_buff *skb, __u32 *identity)
{
	__u32 magic = skb->mark & MARK_MAGIC_HOST_MASK;
	bool from_proxy = false;

	/* Packets from the ingress proxy must skip the proxy when the
	 * destination endpoint evaluates the policy. As the packet
	 * would loop otherwise. */
	if (magic == MARK_MAGIC_PROXY_INGRESS) {
		*identity = get_identity_via_proxy(skb);
		skb->tc_index |= TC_INDEX_F_SKIP_PROXY;
		from_proxy = true;
	} else if (magic == MARK_MAGIC_PROXY_EGRESS) {
		*identity = get_identity_via_proxy(skb);
		from_proxy = true;
	} else if (magic == MARK_MAGIC_HOST) {
		*identity = HOST_ID;
	} else {
		*identity = WORLD_ID;
	}

	/* Reset packet mark to avoid hitting routing rules again */
	skb->mark = 0;

	return from_proxy;
}
#endif

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	__u32 identity = 0;
	int ret;

	bpf_clear_cb(skb);

#ifdef FROM_HOST
	if (1) {

#ifdef HOST_REDIRECT_TO_INGRESS
	if (skb->protocol == bpf_htons(ETH_P_ARP)) {
		union macaddr mac = HOST_IFINDEX_MAC;
		return arp_respond(skb, &mac, BPF_F_INGRESS);
	}
#endif

		int trace = TRACE_FROM_HOST;
		bool from_proxy;

		from_proxy = handle_identity_from_host(skb, &identity);
		if (from_proxy)
			trace = TRACE_FROM_PROXY;
		send_trace_notify(skb, trace, identity, 0, 0,
				  skb->ingress_ifindex, 0, TRACE_PAYLOAD_LEN);
	}
#else
	send_trace_notify(skb, TRACE_FROM_STACK, 0, 0, 0, skb->ingress_ifindex,
			  0, TRACE_PAYLOAD_LEN);
#endif

	switch (skb->protocol) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		/* This is considered the fast path, no tail call */
		ret = handle_ipv6(skb, identity);

		/* We should only be seeing an error here for packets which have
		 * been targetting an endpoint managed by us. */
		if (IS_ERR(ret))
			return send_drop_notify_error(skb, ret, TC_ACT_SHOT, METRIC_INGRESS);
		break;
#endif

#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		skb->cb[CB_SRC_IDENTITY] = identity;
		ep_tail_call(skb, CILIUM_CALL_IPV4_FROM_LXC);
		/* We are not returning an error here to always allow traffic to
		 * the stack in case maps have become unavailable.
		 *
		 * Note: Since drop notification requires a tail call as well,
		 * this notification is unlikely to succeed. */
		return send_drop_notify_error(skb, DROP_MISSED_TAIL_CALL,
		                              TC_ACT_OK, METRIC_INGRESS);

#endif

	default:
		/* Pass unknown traffic to the stack */
		ret = TC_ACT_OK;
	}

	return ret;
}

BPF_LICENSE("GPL");
