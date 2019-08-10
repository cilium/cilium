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
#include "lib/nat.h"
#include "lib/lb.h"
#include "lib/nodeport.h"

#if defined FROM_HOST && (defined ENABLE_IPV4 || defined ENABLE_IPV6)
static inline int rewrite_dmac_to_host(struct __sk_buff *skb, __u32 src_identity)
{
	/* When attached to cilium_host, we rewrite the DMAC to the mac of
	 * cilium_host (peer) to ensure the packet is being considered to be
	 * addressed to the host (PACKET_HOST) */
	union macaddr cilium_net_mac = CILIUM_NET_MAC;

	/* Rewrite to destination MAC of cilium_net (remote peer) */
	if (eth_store_daddr(skb, (__u8 *) &cilium_net_mac.addr, 0) < 0)
		return send_drop_notify_error(skb, src_identity, DROP_WRITE_ERROR, TC_ACT_OK, METRIC_INGRESS);

	return TC_ACT_OK;
}
#endif

#if defined ENABLE_IPV4 || defined ENABLE_IPV6
static inline __u32 finalize_sec_ctx(__u32 secctx, __u32 src_identity)
{
#ifdef ENABLE_SECCTX_FROM_IPCACHE
	/* If we could not derive the secctx from the packet itself but
	 * from the ipcache instead, then use the ipcache identity. E.g.
	 * used in ipvlan master device's datapath on ingress.
	 */
	if (secctx == WORLD_ID && !identity_is_reserved(src_identity))
		secctx = src_identity;
#endif /* ENABLE_SECCTX_FROM_IPCACHE */
	return secctx;
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

static inline int handle_ipv6(struct __sk_buff *skb, __u32 src_identity)
{
	struct remote_endpoint_info *info = NULL;
	union v6addr node_ip = { };
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr *dst;
	int l4_off, l3_off = ETH_HLEN, hdrlen;
	struct endpoint_info *ep;
	__u8 nexthdr;
	__u32 secctx;

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

#ifdef ENABLE_NODEPORT
	if (!bpf_skip_nodeport(skb)) {
		int ret = nodeport_lb6(skb, src_identity);
		if (ret < 0)
			return ret;
	}
#if defined(ENCAP_IFINDEX) || defined(NO_REDIRECT)
	/* See IPv4 case for NO_REDIRECT comments */
	return TC_ACT_OK;
#endif /* ENCAP_IFINDEX || NO_REDIRECT */
	/* Verifier workaround: modified ctx access. */
	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;
#endif /* ENABLE_NODEPORT */

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

	BPF_V6(node_ip, ROUTER_IP);
	secctx = derive_sec_ctx(skb, &node_ip, ip6);

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

	secctx = finalize_sec_ctx(secctx, src_identity);
#ifdef FROM_HOST
	if (1) {
		int ret;

		secctx = src_identity;

		/* If we are attached to cilium_host at egress, this will
		 * rewrite the destination mac address to the MAC of cilium_net */
		ret = rewrite_dmac_to_host(skb, secctx);
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

		return ipv6_local_delivery(skb, l3_off, l4_off, secctx, ip6, nexthdr, ep, METRIC_INGRESS);
	}

#ifdef ENCAP_IFINDEX
	dst = (union v6addr *) &ip6->daddr;
	info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
	if (info != NULL && info->tunnel_endpoint != 0) {
		int ret = encap_and_redirect_with_nodeid(skb, info->tunnel_endpoint,
							 info->key,
							 secctx, TRACE_PAYLOAD_LEN);

		/* If IPSEC is needed recirc through ingress to use xfrm stack
		 * and then result will routed back through bpf_netdev on egress
		 * but with encrypt marks.
		 */
		if (ret == IPSEC_ENDPOINT)
			return TC_ACT_OK;
		else
			return ret;
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

		ret = encap_and_redirect_netdev(skb, &key, secctx, TRACE_PAYLOAD_LEN);
		if (ret == IPSEC_ENDPOINT)
			return TC_ACT_OK;
		else if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif

	dst = (union v6addr *) &ip6->daddr;
	info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
#ifdef FROM_HOST
	if (info == NULL) {
		/* We have received a packet for which no ipcache entry exists,
		 * we do not know what to do with this packet, drop it. */
		return DROP_UNROUTABLE;
	}
#endif
#ifdef ENABLE_IPSEC
	if (info && info->key && info->tunnel_endpoint) {
		__u8 key = get_min_encrypt_key(info->key);

		set_encrypt_key_cb(skb, key);
#ifdef IP_POOLS
		set_encrypt_dip(skb, info->tunnel_endpoint);
#else
		set_identity_cb(skb, secctx);
#endif
	}
#endif
	return TC_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_LXC) int tail_handle_ipv6(struct __sk_buff *skb)
{
	__u32 proxy_identity = skb->cb[CB_SRC_IDENTITY];
	int ret;

	skb->cb[CB_SRC_IDENTITY] = 0;
	ret = handle_ipv6(skb, proxy_identity);
	if (IS_ERR(ret))
		return send_drop_notify_error(skb, proxy_identity, ret, TC_ACT_SHOT, METRIC_INGRESS);

	return ret;
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

static inline int handle_ipv4(struct __sk_buff *skb, __u32 src_identity)
{
	struct remote_endpoint_info *info = NULL;
	struct ipv4_ct_tuple tuple = {};
	struct endpoint_info *ep;
	void *data, *data_end;
	struct iphdr *ip4;
	int l4_off;
	__u32 secctx;

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

#ifdef ENABLE_NODEPORT
	if (!bpf_skip_nodeport(skb)) {
		int ret = nodeport_lb4(skb, src_identity);
		if (ret < 0)
			return ret;
	}
#if defined(ENCAP_IFINDEX) || defined(NO_REDIRECT)
	/* We cannot redirect a packet to a local endpoint in the direct
	 * routing mode, as the redirect bypasses nf_conntrack table.
	 * This makes a second reply from the endpoint to be MASQUERADEd or
	 * to be DROPed by k8s's "--ctstate INVALID -j DROP" depending via
	 * which interface it was inputed. */
	return TC_ACT_OK;
#endif /* ENCAP_IFINDEX || NO_REDIRECT */
	/* Verifier workaround: modified ctx access. */
	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;
#endif /* ENABLE_NODEPORT */

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
#ifndef ENABLE_EXTRA_HOST_DEV
				if (sec_label != HOST_ID)
#endif
					src_identity = sec_label;
			}
		}
		cilium_dbg(skb, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->saddr, src_identity);
	}

	secctx = finalize_sec_ctx(secctx, src_identity);
#ifdef FROM_HOST
	if (1) {
		int ret;

		secctx = src_identity;

		/* If we are attached to cilium_host at egress, this will
		 * rewrite the destination mac address to the MAC of cilium_net */
		ret = rewrite_dmac_to_host(skb, secctx);
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
		int ret = encap_and_redirect_with_nodeid(skb, info->tunnel_endpoint,
							 info->key,
							 secctx, TRACE_PAYLOAD_LEN);

		if (ret == IPSEC_ENDPOINT)
			return TC_ACT_OK;
		else
			return ret;
	} else {
		/* IPv4 lookup key: daddr & IPV4_MASK */
		struct endpoint_key key = {};
		int ret;

		key.ip4 = ip4->daddr & IPV4_MASK;
		key.family = ENDPOINT_KEY_IPV4;

		cilium_dbg(skb, DBG_NETDEV_ENCAP4, key.ip4, secctx);
		ret = encap_and_redirect_netdev(skb, &key, secctx, TRACE_PAYLOAD_LEN);
		if (ret == IPSEC_ENDPOINT)
			return TC_ACT_OK;
		else if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif

#ifdef HOST_REDIRECT_TO_INGRESS
    return redirect(HOST_IFINDEX, BPF_F_INGRESS);
#else

	info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
#ifdef FROM_HOST
	if (info == NULL) {
		/* We have received a packet for which no ipcache entry exists,
		 * we do not know what to do with this packet, drop it. */
		return DROP_UNROUTABLE;
	}
#endif
#ifdef ENABLE_IPSEC
	if (info && info->key && info->tunnel_endpoint) {
		__u8 key = get_min_encrypt_key(info->key);

		set_encrypt_key_cb(skb, key);
#ifdef IP_POOLS
		set_encrypt_dip(skb, info->tunnel_endpoint);
#else
		set_identity_cb(skb, secctx);
#endif
	}
#endif
	return TC_ACT_OK;
#endif
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_LXC) int tail_handle_ipv4(struct __sk_buff *skb)
{
	__u32 proxy_identity = skb->cb[CB_SRC_IDENTITY];
	int ret;

	skb->cb[CB_SRC_IDENTITY] = 0;
	ret = handle_ipv4(skb, proxy_identity);
	if (IS_ERR(ret))
		return send_drop_notify_error(skb, proxy_identity, ret, TC_ACT_SHOT, METRIC_INGRESS);

	return ret;
}

#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPSEC
#ifndef ENCAP_IFINDEX
static __always_inline int do_netdev_encrypt_pools(struct __sk_buff *skb)
{
	int ret = 0;
#ifdef IP_POOLS
	__u32 tunnel_endpoint = 0;
	void *data, *data_end;
	__u32 tunnel_source = IPV4_ENCRYPT_IFACE;
	struct iphdr *iphdr;
	__be32 sum;

	tunnel_endpoint = skb->cb[4];
	skb->mark = 0;

	if (!revalidate_data(skb, &data, &data_end, &iphdr)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	/* When IP_POOLS is enabled ip addresses are not
	 * assigned on a per node basis so lacking node
	 * affinity we can not use IP address to assign the
	 * destination IP. Instead rewrite it here from cb[].
	 */
	sum = csum_diff(&iphdr->daddr, 4, &tunnel_endpoint, 4, 0);
	if (skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr),
	    &tunnel_endpoint, 4, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
	    0, sum, 0) < 0) {
		ret = DROP_CSUM_L3;
		goto drop_err;
	}

	if (!revalidate_data(skb, &data, &data_end, &iphdr)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	sum = csum_diff(&iphdr->saddr, 4, &tunnel_source, 4, 0);
	if (skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr),
	    &tunnel_source, 4, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
	    0, sum, 0) < 0) {
		ret = DROP_CSUM_L3;
		goto drop_err;
	}
drop_err:
#endif // IP_POOLS
	return ret;
}

static __always_inline int do_netdev_encrypt_fib(struct __sk_buff *skb, int *encrypt_iface)
{
	int ret = 0;

#ifdef HAVE_FIB_LOOKUP
	struct bpf_fib_lookup fib_params = {};
	void *data, *data_end;
	struct iphdr *iphdr;
	__be32 sum;
	int err;

	if (!revalidate_data(skb, &data, &data_end, &iphdr)) {
		ret = DROP_INVALID;
		goto drop_err_fib;
	}

	fib_params.family = AF_INET;
	fib_params.ifindex = ENCRYPT_IFACE;

	fib_params.ipv4_src = iphdr->saddr;
	fib_params.ipv4_dst = iphdr->daddr;

	err = fib_lookup(skb, &fib_params, sizeof(fib_params),
		    BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (err != 0) {
		ret = DROP_NO_FIB;
		goto drop_err_fib;
	}
	if (eth_store_daddr(skb, fib_params.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err_fib;
	}
	if (eth_store_saddr(skb, fib_params.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err_fib;
	}
	*encrypt_iface = fib_params.ifindex;
drop_err_fib:
#endif /* HAVE_FIB_LOOKUP */
	return ret;
}

static __always_inline int do_netdev_encrypt(struct __sk_buff *skb)
{
	int encrypt_iface;
	int ret = 0;

#ifdef ENCRYPT_NODE
	encrypt_iface = ENCRYPT_IFACE;
#endif

	ret = do_netdev_encrypt_pools(skb);
	if (ret)
		return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, METRIC_INGRESS);

	ret = do_netdev_encrypt_fib(skb, &encrypt_iface);
	if (ret)
		return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, METRIC_INGRESS);

	bpf_clear_cb(skb);
#ifdef ENCRYPT_NODE
	return redirect(encrypt_iface, 0);
#else
	return TC_ACT_OK;
#endif
}

#else /* ENCAP_IFINDEX */
static __always_inline int do_netdev_encrypt_encap(struct __sk_buff *skb)
{
	__u32 seclabel, tunnel_endpoint = 0;

	seclabel = get_identity(skb);
	tunnel_endpoint = skb->cb[4];
	skb->mark = 0;

	bpf_clear_cb(skb);
	return __encap_and_redirect_with_nodeid(skb, tunnel_endpoint, seclabel, TRACE_PAYLOAD_LEN);
}

static __always_inline int do_netdev_encrypt(struct __sk_buff *skb)
{
	return do_netdev_encrypt_encap(skb);
}
#endif /* ENCAP_IFINDEX */
#endif /* ENABLE_IPSEC */

static __always_inline int do_netdev(struct __sk_buff *skb, __u16 proto)
{
	__u32 identity = 0;
	int ret;

#ifdef ENABLE_IPSEC
	if (1) {
		__u32 magic = skb->mark & MARK_MAGIC_HOST_MASK;

		if (magic == MARK_MAGIC_ENCRYPT)
			return do_netdev_encrypt(skb);
	}
#endif
	bpf_clear_cb(skb);
	bpf_clear_nodeport(skb);

#ifdef ENABLE_NODEPORT
	ret = nodeport_nat_rev(skb, false);
	if (IS_ERR(ret) &&
	    ret != DROP_NAT_NO_MAPPING &&
	    ret != DROP_NAT_UNSUPP_PROTO)
		return send_drop_notify_error(skb, identity, ret,
					      TC_ACT_OK, METRIC_INGRESS);
#endif

#ifdef FROM_HOST
	if (1) {

#ifdef HOST_REDIRECT_TO_INGRESS
	if (proto == bpf_htons(ETH_P_ARP)) {
		union macaddr mac = HOST_IFINDEX_MAC;
		return arp_respond(skb, &mac, BPF_F_INGRESS);
	}
#endif

		int trace = TRACE_FROM_HOST;
		bool from_proxy;

		from_proxy = inherit_identity_from_host(skb, &identity);
		if (from_proxy)
			trace = TRACE_FROM_PROXY;
		send_trace_notify(skb, trace, identity, 0, 0,
				  skb->ingress_ifindex, 0, TRACE_PAYLOAD_LEN);
	}
#else
	send_trace_notify(skb, TRACE_FROM_STACK, 0, 0, 0, skb->ingress_ifindex,
			  0, TRACE_PAYLOAD_LEN);
#endif

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		skb->cb[CB_SRC_IDENTITY] = identity;
		ep_tail_call(skb, CILIUM_CALL_IPV6_FROM_LXC);
		/* See comment below for IPv4. */
		return send_drop_notify_error(skb, identity, DROP_MISSED_TAIL_CALL,
					      TC_ACT_OK, METRIC_INGRESS);
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
		return send_drop_notify_error(skb, identity, DROP_MISSED_TAIL_CALL,
		                              TC_ACT_OK, METRIC_INGRESS);
#endif

	default:
		/* Pass unknown traffic to the stack */
		ret = TC_ACT_OK;
	}

	return ret;
}

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	int ret = ret;
	__u16 proto;

	if (!validate_ethertype(skb, &proto))
		/* Pass unknown traffic to the stack */
		return TC_ACT_OK;

#ifdef ENABLE_MASQUERADE
	cilium_dbg_capture(skb, DBG_CAPTURE_SNAT_PRE, skb->ifindex);
	ret = snat_process(skb, BPF_PKT_DIR);
	if (ret != TC_ACT_OK) {
		return ret;
	}
	cilium_dbg_capture(skb, DBG_CAPTURE_SNAT_POST, skb->ifindex);
#endif /* ENABLE_MASQUERADE */

	return do_netdev(skb, proto);
}

__section("to-netdev")
int to_netdev(struct __sk_buff *skb)
{
	/* Cannot compile the section out entriely, test/bpf/verifier-test.sh
	 * workaround.
	 */
	int ret = TC_ACT_OK;
#if defined(ENABLE_NODEPORT) || defined(ENABLE_MASQUERADE)
#ifdef ENABLE_NODEPORT
	if ((skb->mark & MARK_MAGIC_SNAT_DONE) == MARK_MAGIC_SNAT_DONE)
		return TC_ACT_OK;
	ret = nodeport_nat_fwd(skb, false);
	if (IS_ERR(ret))
		return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, METRIC_EGRESS);
#else
	__u16 proto;
	if (!validate_ethertype(skb, &proto))
		/* Pass unknown traffic to the stack */
		return TC_ACT_OK;
	cilium_dbg_capture(skb, DBG_CAPTURE_SNAT_PRE, skb->ifindex);
	ret = snat_process(skb, BPF_PKT_DIR);
	if (!ret)
		cilium_dbg_capture(skb, DBG_CAPTURE_SNAT_POST, skb->ifindex);
#endif /* ENABLE_NODEPORT */
#endif /* ENABLE_NODEPORT || ENABLE_MASQUERADE */
	return ret;
}

BPF_LICENSE("GPL");
