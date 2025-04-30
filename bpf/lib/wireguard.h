/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#ifdef ENABLE_WIREGUARD

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "tailcall.h"
#include "common.h"
#include "overloadable.h"
#include "identity.h"

#include "lib/proxy.h"
#include "lib/l4.h"

/* ctx_is_wireguard is used to check whether ctx is a WireGuard network packet.
 * This function returns true in case all the following conditions are satisfied:
 *
 * - ctx is a UDP packet;
 * - L4 dport == WG_PORT;
 * - L4 sport == dport;
 * - valid identity in cluster.
 */
static __always_inline bool
ctx_is_wireguard(struct __ctx_buff *ctx, int l4_off, __u8 protocol, __u32 identity)
{
	struct {
		__be16 sport;
		__be16 dport;
	} l4;

	/* Non-UDP packets. */
	if (protocol != IPPROTO_UDP)
		return false;

	/* Unable to retrieve L4 ports. */
	if (l4_load_ports(ctx, l4_off + UDP_SPORT_OFF, &l4.sport) < 0)
		return false;

	/* Packet is not for cilium@WireGuard.*/
	if (l4.dport != bpf_htons(WG_PORT))
		return false;

	/* Packet does not come from cilium@WireGuard. */
	if (l4.sport != l4.dport)
		return false;

	/* Identity not in cluster. */
	if (!identity_is_cluster(identity))
		return false;

	/* Cilium-related WireGuard packet to be traced as encrypted. */
	return true;
}

static __always_inline int
wg_maybe_redirect_to_encrypt(struct __ctx_buff *ctx, __be16 proto,
			     __u32 src_sec_identity)
{
	struct remote_endpoint_info *dst = NULL;
	struct remote_endpoint_info __maybe_unused *src = NULL;
	void *data, *data_end;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	__u32 magic __maybe_unused = 0;

	if (!eth_is_supported_ethertype(proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
#ifdef ENABLE_NODE_ENCRYPTION
		/* Previously, ICMPv6 NA (reply to NS) was sent over cilium_wg0,
		 * which resulted in neigh entry not being created due to
		 * IFF_POINTOPOINT | IFF_NOARP set on cilium_wg0. Therefore,
		 * NA should not be sent over WG.
		 *
		 * Note: We account for this in connectivity tests leak checks
		 * by filtering out icmpv6 NA.
		 */
		if (ip6->nexthdr == IPPROTO_ICMPV6) {
			__u8 icmp_type;

			if (data + sizeof(*ip6) + ETH_HLEN +
			    sizeof(struct icmp6hdr) > data_end)
				return DROP_INVALID;

			if (icmp6_load_type(ctx, ETH_HLEN + sizeof(struct ipv6hdr),
					    &icmp_type) < 0)
				return DROP_INVALID;

			if (icmp_type == ICMP6_NA_MSG_TYPE)
				goto out;
		}
#endif
		dst = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);

		if (src_sec_identity == UNKNOWN_ID) {
			src = lookup_ip6_remote_endpoint((union v6addr *)&ip6->saddr, 0);
			if (!src)
				return CTX_ACT_OK;

			src_sec_identity = src->sec_identity;
		}
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
# if defined(HAVE_ENCAP)
		/* In tunneling mode WG needs to encrypt tunnel traffic,
		 * so that src sec ID can be transferred.
		 *
		 * This also handles IPv6, as IPv6 pkts are encapsulated w/
		 * IPv4 tunneling.
		 */
		if (ctx_is_overlay(ctx))
			goto overlay_encrypt;
# endif /* HAVE_ENCAP */

		dst = lookup_ip4_remote_endpoint(ip4->daddr, 0);

		if (src_sec_identity == UNKNOWN_ID) {
			src = lookup_ip4_remote_endpoint(ip4->saddr, 0);
			if (!src)
				return CTX_ACT_OK;

			src_sec_identity = src->sec_identity;
		}
		break;
#endif
	default:
		goto out;
	}

#ifndef ENABLE_NODE_ENCRYPTION
	/* A pkt coming from L7 proxy (i.e., Envoy or the DNS proxy on behalf of
	 * a client pod) has src IP addr of a host, but not of the client pod
	 * (if
	 * --dnsproxy-enable-transparent-mode=false). Such a pkt must be
	 *  encrypted.
	 */
	magic = ctx->mark & MARK_MAGIC_HOST_MASK;
	if (magic == MARK_MAGIC_PROXY_INGRESS || magic == MARK_MAGIC_PROXY_EGRESS)
		goto maybe_encrypt;
#if defined(TUNNEL_MODE)
	/* In tunneling mode the mark might have been reset. Check TC index instead.
	 */
	if (tc_index_from_ingress_proxy(ctx) || tc_index_from_egress_proxy(ctx))
		goto maybe_encrypt;
#endif /* TUNNEL_MODE */

	/* Unless node encryption is enabled, we don't want to encrypt
	 * traffic from the hostns (an exception - L7 proxy traffic).
	 *
	 * NB: if iptables has SNAT-ed the packet, its sec id is HOST_ID.
	 * This means that the packet won't be encrypted. This is fine,
	 * as with --encrypt-node=false we encrypt only pod-to-pod packets.
	 */
	if (src_sec_identity == HOST_ID)
		goto out;
#endif /* !ENABLE_NODE_ENCRYPTION */

	/* We don't want to encrypt any traffic that originates from outside
	 * the cluster. This check excludes DSR traffic from the LB node to a remote backend.
	 */
	if (!identity_is_cluster(src_sec_identity))
		goto out;

	/* If source is remote node we should treat it like outside traffic.
	 * This is possible when connection is done from pod to load balancer with DSR enabled.
	 */
	if (identity_is_remote_node(src_sec_identity))
		goto out;

maybe_encrypt: __maybe_unused
	/* Redirect to the WireGuard tunnel device if the encryption is
	 * required.
	 */
	if (dst && dst->key) {
		set_identity_mark(ctx, src_sec_identity, MARK_MAGIC_IDENTITY);
overlay_encrypt: __maybe_unused
		return ctx_redirect(ctx, WG_IFINDEX, 0);
	}

out:
	return CTX_ACT_OK;
}

#ifdef ENCRYPTION_STRICT_MODE

/* strict_allow checks whether the packet is allowed to pass through the strict mode. */
static __always_inline bool
strict_allow(struct __ctx_buff *ctx, __be16 proto) {
	struct remote_endpoint_info __maybe_unused *dest_info, __maybe_unused *src_info;
	bool __maybe_unused in_strict_cidr = false;
	void *data, *data_end;
#ifdef ENABLE_IPV4
	struct iphdr *ip4;
#endif

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return true;

		/* Allow traffic that is sent from the node:
		 * (1) When encapsulation is used and the destination is a remote pod.
		 * (2) When the destination is a remote-node.
		 */
		if (ip4->saddr == IPV4_GATEWAY || ip4->saddr == IPV4_ENCRYPT_IFACE)
			return true;

		in_strict_cidr = ipv4_is_in_subnet(ip4->daddr,
						   STRICT_IPV4_NET,
						   STRICT_IPV4_NET_SIZE);
		in_strict_cidr &= ipv4_is_in_subnet(ip4->saddr,
						    STRICT_IPV4_NET,
						    STRICT_IPV4_NET_SIZE);

#if defined(TUNNEL_MODE) || defined(STRICT_IPV4_OVERLAPPING_CIDR)
		/* Allow pod to remote-node communication */
		dest_info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (dest_info && identity_is_node(dest_info->sec_identity))
			return true;
#endif /* TUNNEL_MODE || STRICT_IPV4_OVERLAPPING_CIDR */
		return !in_strict_cidr;
#endif /* ENABLE_IPV4 */
	default:
		return true;
	}
}

#endif /* ENCRYPTION_STRICT_MODE */

#endif /* ENABLE_WIREGUARD */
