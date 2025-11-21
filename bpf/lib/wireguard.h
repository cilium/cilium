/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "common.h"
#include "lib/encrypt.h"
#include "overloadable.h"
#include "identity.h"

#include "lib/proxy.h"
#include "lib/l4.h"

#include "linux/icmpv6.h"

DECLARE_CONFIG(__u32, wg_ifindex, "Index of the WireGuard interface.")
DECLARE_CONFIG(__u16, wg_port, "Port for the WireGuard interface.")

#ifdef ENABLE_WIREGUARD

/* wg_do_decrypt is used to mark encrypted network packets for decryption.
 * A packet is marked in case all the following conditions are satisfied:
 *
 * - ctx is a UDP packet;
 * - L4 dport == CONFIG(wg_port);
 * - L4 sport == dport;
 * - valid identity in cluster.
 */
static __always_inline int
wg_do_decrypt(struct __ctx_buff *ctx, __be16 proto, __u32 identity)
{
	void *data __maybe_unused, *data_end __maybe_unused;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} l4;
	__u8 protocol;
	int hdrlen;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			goto out;
		protocol = ip6->nexthdr;
		hdrlen = ipv6_hdrlen(ctx, &protocol);
		if (unlikely(hdrlen <= 0))
			goto out;
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			goto out;
		protocol = ip4->protocol;
		hdrlen = ipv4_hdrlen(ip4);
		break;
#endif
	default:
		goto out;
	}

	/* Non-UDP packets. */
	if (protocol != IPPROTO_UDP)
		goto out;

	/* Unable to retrieve L4 ports. */
	if (l4_load_ports(ctx, ETH_HLEN + hdrlen + UDP_SPORT_OFF, &l4.sport) < 0)
		goto out;

	/* Packet is not for cilium@WireGuard.*/
	if (l4.dport != bpf_htons(CONFIG(wg_port)))
		goto out;

	/* Packet does not come from cilium@WireGuard. */
	if (l4.sport != l4.dport)
		goto out;

	/* Identity not in cluster. */
	if (!identity_is_cluster(identity))
		goto out;

	/* Cilium-related WireGuard packet, let's set decrypt mark. */
	set_decrypt_mark(ctx, 0);
out:
	return CTX_ACT_OK;
}

static __always_inline int
wg_maybe_redirect_to_encrypt(struct __ctx_buff *ctx, __be16 proto,
			     __u32 src_sec_identity)
{
	const struct remote_endpoint_info *dst = NULL;
	const struct remote_endpoint_info __maybe_unused *src = NULL;
	void *data, *data_end;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	__u32 magic __maybe_unused = 0;

# if defined(HAVE_ENCAP)
		/* In tunneling mode WG needs to encrypt tunnel traffic,
		 * so that src sec ID can be transferred.
		 */
		if (ctx_is_overlay(ctx))
			goto overlay_encrypt;
# endif /* HAVE_ENCAP */

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
			struct icmp6hdr *icmp6 = (void *)ip6 + sizeof(*ip6);

			if ((void *)icmp6 + sizeof(*icmp6) > data_end)
				return DROP_INVALID;

			if (icmp6->icmp6_type == ICMPV6_NA_MSG)
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
	/* We want to encrypt all proxy traffic. Looking at the packet mark is
	 * needed for non-transparent connections.
	 *
	 * For connections by the egress proxy (MARK_MAGIC_PROXY_EGRESS) we
	 * can rely on the provided source identity.
	 */
	magic = ctx->mark & MARK_MAGIC_HOST_MASK;
	if (magic == MARK_MAGIC_PROXY_INGRESS ||
	    magic == MARK_MAGIC_SKIP_TPROXY)
		goto maybe_encrypt;
#if defined(TUNNEL_MODE)
	/* In tunneling mode the mark might have been reset. Check TC index instead.
	 * TODO: remove this in v1.20, once we can rely on MARK_MAGIC_SKIP_TPROXY.
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
		return ctx_redirect(ctx, CONFIG(wg_ifindex), 0);
	}

out:
	return CTX_ACT_OK;
}
#endif /* ENABLE_WIREGUARD */
