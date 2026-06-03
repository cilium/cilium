/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "lib/common.h"
#include "lib/eps.h"
#include "lib/ipv4.h"
#include "lib/identity.h"

struct strict_encryption_cfg {
	/* Whether strict encryption mode is enabled for egress traffic. */
	bool enabled;
	/* The IPv4 network CIDR range for which egress encryption is enforced. */
	union v4addr ipv4_net;
	/* The primary IPv4 address of the local node. Used as an exception to
	 * allow host-originated egress traffic in strict mode.
	 */
	union v4addr ipv4_encrypt_iface;
	/* The CIDR prefix size of ipv4_net. */
	__u8 ipv4_net_size;
	/* Whether the IPv4 encryption network overlaps with other networks. */
	bool ipv4_overlapping;
};

DECLARE_CONFIG(struct strict_encryption_cfg, strict_egress_encryption,
	       "Strict encryption mode drops all unencrypted pod-to-pod egress traffic")

#define STRICT_IPV4_NET		CONFIG(strict_egress_encryption).ipv4_net.be32
#define STRICT_IPV4_NET_SIZE	CONFIG(strict_egress_encryption).ipv4_net_size
#define IPV4_ENCRYPT_IFACE	CONFIG(strict_egress_encryption).ipv4_encrypt_iface.be32

static __always_inline void
set_decrypt_mark(struct __ctx_buff *ctx, __u16 node_id)
{
	/* Decrypt "key" is determined by SPI and originating node */
	ctx->mark = MARK_MAGIC_DECRYPT | node_id << 16;
}

/* strict_allow checks whether the packet is allowed to pass through the strict mode. */
static __always_inline bool
strict_allow(struct __ctx_buff __maybe_unused *ctx, __be16 proto) {
	const struct remote_endpoint_info __maybe_unused *dest_info;
	bool __maybe_unused in_strict_cidr = false;
	struct iphdr __maybe_unused *ip4;
	void __maybe_unused *data, *data_end;

	if (!CONFIG(strict_egress_encryption).enabled)
		return true;

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

		if (is_defined(TUNNEL_MODE) || CONFIG(strict_egress_encryption).ipv4_overlapping) {
			/* Allow pod to remote-node communication */
			dest_info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
			if (dest_info && identity_is_remote_node(dest_info->sec_identity))
				return true;
		}
		return !in_strict_cidr;
#endif /* ENABLE_IPV4 */
	default:
		return true;
	}
}

/* checks whether the source endpoint matches the encryption policy */
static __always_inline bool
encrypt_src_matches_policy(__u32 src_sec_identity) {
#ifndef ENABLE_NODE_ENCRYPTION
	/* Unless node encryption is enabled, we don't want to encrypt
	 * traffic from the hostns.
	 *
	 * NB: if iptables has SNAT-ed the packet, its sec id is HOST_ID.
	 * This means that the packet won't be encrypted. This is fine,
	 * as with --encrypt-node=false we encrypt only pod-to-pod packets.
	 */
	if (src_sec_identity == HOST_ID)
		return false;
#endif /* !ENABLE_NODE_ENCRYPTION */

	/* We don't want to encrypt any traffic that originates from outside
	 * the cluster. This check excludes DSR traffic from the LB node to a remote backend.
	 */
	if (!identity_is_cluster(src_sec_identity))
		return false;

	/* If source is remote node we should treat it like outside traffic.
	 * This is possible when connection is done from pod to load balancer with DSR enabled.
	 */
	if (identity_is_remote_node(src_sec_identity))
		return false;

	return true;
}
