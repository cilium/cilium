/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/config/node.h>

#include "dbg.h"
#include "clustermesh.h"
/**
 * get_identity - returns source identity from the mark field
 *
 * Identity stored in the mark is rearranged to place identity in the most
 * significant bits and cluster_id in the least significant bits, separated by 8
 * bits that are used for other options. When retrieving identity from the mark,
 * we need to rearrange it back to the original format.
 *
 * Example mark containing identity, where I is a bit for identity, C is a bit
 * for cluster_id, and X is a bit that should not be touched by this function:
 * IIIIIIII IIIIIIII XXXXXXXX CCCCCCCC
 *
 * This function should return an identity that looks like the following:
 * CCCCCCCC IIIIIIII IIIIIIII
 *
 * The agent flag 'max-connected-clusters' can effect the allocation of bits
 * for identity and cluster_id in the mark (see comment in set_identity_mark).
 */
static __always_inline __maybe_unused int
get_identity(const struct __ctx_buff *ctx __maybe_unused)
{
/* ctx->mark not available in XDP. */
#if __ctx_is == __ctx_skb
	__u32 cluster_id_lower = ctx->mark & CLUSTER_ID_LOWER_MASK;
	__u32 cluster_id_upper = (ctx->mark & get_cluster_id_upper_mask()) >>
				      (8 + IDENTITY_LOCAL_BITS);
	__u32 identity = (ctx->mark >> 16) & IDENTITY_LOCAL_MAX;

	return (cluster_id_lower | cluster_id_upper) << IDENTITY_LOCAL_BITS | identity;
#else /* __ctx_is == __ctx_xdp */
	return 0;
#endif /* __ctx_is == __ctx_xdp */
}

/**
 * set_identity_mark - pushes 24 bit identity into ctx mark value.
 *
 * Identity in the mark looks like the following, where I is a bit for
 * identity, C is a bit for cluster_id, and X is a bit that should not be
 * touched by this function:
 * IIIIIIII IIIIIIII XXXXXXXX CCCCCCCC
 *
 * With the agent flag 'max-connected-clusters', it is possible to extend the
 * cluster_id range by sacrificing some bits of the identity. When this is set
 * to a value other than the default 255, the most significant bits are taken
 * from identity and used for the most significant bits of cluster_id.
 *
 * An agent with 'max-connected-clusters=511' would set identity in the mark
 * like the following:
 * CIIIIIII IIIIIIII XXXXXXXX CCCCCCCC
 */
static __always_inline __maybe_unused void
set_identity_mark(struct __ctx_buff *ctx __maybe_unused, __u32 identity __maybe_unused,
		  __u32 magic __maybe_unused)
{
#if __ctx_is == __ctx_skb
	__u32 cluster_id = (identity >> IDENTITY_LOCAL_BITS) & CLUSTER_ID_MAX;

	ctx->mark = format_cluster_id_mark(cluster_id);
	ctx->mark |= magic & MARK_MAGIC_KEY_MASK;
	ctx->mark |= (identity & IDENTITY_LOCAL_MAX) << 16;
#endif
}

static __always_inline bool identity_in_range(__u32 identity, __u32 range_start, __u32 range_end)
{
	return range_start <= identity && identity <= range_end;
}

#define IDENTITY_LOCAL_SCOPE_MASK 0xFF000000
#define IDENTITY_LOCAL_SCOPE_REMOTE_NODE 0x02000000

static __always_inline bool identity_is_host(__u32 identity)
{
	return identity == HOST_ID;
}

static __always_inline bool identity_is_remote_node(__u32 identity)
{
	/* KUBE_APISERVER_NODE_ID is the reserved identity that corresponds to
	 * the labels 'reserved:remote-node' and 'reserved:kube-apiserver'. As
	 * such, if it is ever used for determining the identity of a node in
	 * the cluster, then routing decisions and so on should be made the
	 * same way as for REMOTE_NODE_ID. If we ever assign unique identities
	 * to each node in the cluster, then we'll probably need to convert
	 * the implementation here into a map to select any of the possible
	 * identities. But for now, this is good enough to capture the notion
	 * of 'remote nodes in the cluster' for routing decisions.
	 *
	 * Remote nodes may also have, instead, an identity allocated from the
	 * remote node identity scope, which is identified by the top 8 bits
	 * being 0x02.
	 *
	 * Note that kube-apiserver policy is handled entirely separately by
	 * the standard policymap enforcement logic and has no relationship to
	 * the identity as used here. If the apiserver is outside the cluster,
	 * then the KUBE_APISERVER_NODE_ID case should not ever be hit.
	 */
	return identity == REMOTE_NODE_ID ||
		identity == KUBE_APISERVER_NODE_ID ||
		(identity & IDENTITY_LOCAL_SCOPE_MASK) == IDENTITY_LOCAL_SCOPE_REMOTE_NODE;
}

/**
 * identity_is_reserved is used to determine whether an identity is one of the
 * reserved identities that are not handed out to endpoints.
 *
 * Specifically, it should return true if the identity is one of these:
 * - IdentityUnknown
 * - ReservedIdentityHost
 * - ReservedIdentityWorld
 * - ReservedIdentityWorldIPv4
 * - ReservedIdentityWorldIPv6
 * - ReservedIdentityRemoteNode
 * - ReservedIdentityKubeAPIServer
 *
 * The following identities are given to endpoints so return false for these:
 * - ReservedIdentityUnmanaged
 * - ReservedIdentityHealth
 * - ReservedIdentityInit
 *
 * Identities 128 and higher are guaranteed to be generated based on user input.
 */
static __always_inline bool identity_is_reserved(__u32 identity)
{
#if defined ENABLE_IPV4 && defined ENABLE_IPV6
		return identity < UNMANAGED_ID || identity_is_remote_node(identity) ||
			identity == WORLD_IPV4_ID || identity == WORLD_IPV6_ID;
#else
		return identity < UNMANAGED_ID || identity_is_remote_node(identity);
#endif
}

/**
 * identity_is_world_ipv4 is used to determine whether an identity is the world-ipv4
 * reserved identity.
 *
 * Specifically, it should return true if the identity is one of these:
 * - ReservedIdentityWorld
 * - ReservedIdentityWorldIPv4
 */
static __always_inline bool identity_is_world_ipv4(__u32 identity)
{
#if defined ENABLE_IPV4 && defined ENABLE_IPV6
		return identity == WORLD_ID || identity == WORLD_IPV4_ID;
#else
		return identity == WORLD_ID;
#endif
}

/**
 * identity_is_world_ipv6 is used to determine whether an identity is the world-ipv6
 * reserved identity.
 *
 * Specifically, it should return true if the identity is one of these:
 * - ReservedIdentityWorld
 * - ReservedIdentityWorldIPv6
 */
static __always_inline bool identity_is_world_ipv6(__u32 identity)
{
#if defined ENABLE_IPV4 && defined ENABLE_IPV6
		return identity == WORLD_ID || identity == WORLD_IPV6_ID;
#else
		return identity == WORLD_ID;
#endif
}

/**
 * identity_is_cidr_range is used to determine whether an identity is assigned
 * to a CIDR range.
 */
static __always_inline bool identity_is_cidr_range(__u32 identity)
{
	return identity_in_range(identity, CIDR_IDENTITY_RANGE_START, CIDR_IDENTITY_RANGE_END);
}

/**
 * identity_is_cluster is used to determine whether an identity is assigned to
 * an entity inside the cluster.
 *
 * This function will return false for:
 * - ReservedIdentityWorld
 * - ReservedIdentityWorldIPv4
 * - ReservedIdentityWorldIPv6
 * - an identity in the CIDR range
 *
 * This function will return true for:
 * - ReservedIdentityHost
 * - ReservedIdentityUnmanaged
 * - ReservedIdentityHealth
 * - ReservedIdentityInit
 * - ReservedIdentityRemoteNode
 * - ReservedIdentityKubeAPIServer
 * - ReservedIdentityIngress
 * - all other identifies
 */
static __always_inline bool identity_is_cluster(__u32 identity)
{
#if defined ENABLE_IPV4 && defined ENABLE_IPV6
	if (identity == WORLD_ID || identity == WORLD_IPV4_ID || identity == WORLD_IPV6_ID)
		return false;
#else
	if (identity == WORLD_ID)
		return false;
#endif

	if (identity_is_cidr_range(identity))
		return false;

	return true;
}

#if __ctx_is == __ctx_skb
static __always_inline __u32 inherit_identity_from_host(struct __ctx_buff *ctx, __u32 *identity)
{
	__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;

	/* Packets from the ingress proxy must skip the proxy when the
	 * destination endpoint evaluates the policy. As the packet would loop
	 * and/or the connection be reset otherwise.
	 */
	if (magic == MARK_MAGIC_PROXY_INGRESS) {
		*identity = get_identity(ctx);
		ctx->tc_index |= TC_INDEX_F_FROM_INGRESS_PROXY;
	/* (Return) packets from the egress proxy must skip the redirection to
	 * the proxy, as the packet would loop and/or the connection be reset
	 * otherwise.
	 */
	} else if (magic == MARK_MAGIC_PROXY_EGRESS) {
		*identity = get_identity(ctx);
		ctx->tc_index |= TC_INDEX_F_FROM_EGRESS_PROXY;
	} else if (magic == MARK_MAGIC_IDENTITY) {
		*identity = get_identity(ctx);
	} else if (magic == MARK_MAGIC_HOST) {
		*identity = HOST_ID;
	} else {
#if defined ENABLE_IPV4 && defined ENABLE_IPV6
		__be16 proto = ctx_get_protocol(ctx);

		if (proto == bpf_htons(ETH_P_IP))
			*identity = WORLD_IPV4_ID;
		else if (proto == bpf_htons(ETH_P_IPV6))
			*identity = WORLD_IPV6_ID;
		else
			*identity = WORLD_ID;
#else
		*identity = WORLD_ID;
#endif
	}

	/* Reset packet mark to avoid hitting routing rules again */
	ctx->mark = 0;

	cilium_dbg(ctx, DBG_INHERIT_IDENTITY, *identity, 0);

	return magic;
}
#endif /* __ctx_is == __ctx_skb */

/**
 * identity_is_local is used to determine whether an identity is locally
 * allocated.
 */
static __always_inline bool identity_is_local(__u32 identity)
{
	return (identity & IDENTITY_LOCAL_SCOPE_MASK) != 0;
}
