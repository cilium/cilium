/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/config/node.h>
#include "export_type.h"

#include "dbg.h"
#include "clustermesh.h"

enum identity {
	UNKNOWN_ID = 0,
	HOST_ID = 1,
	WORLD_ID = 2,
	UNMANAGED_ID = 3,
	HEALTH_ID = 4,
	INIT_ID = 5,
	LOCAL_NODE_ID = 6,
	REMOTE_NODE_ID = LOCAL_NODE_ID,
	KUBE_APISERVER_NODE_ID = 7,
	INGRESS_ID = 8,
	WORLD_IPV4_ID = 9,
	WORLD_IPV6_ID = 10,
	POLICY_CLUSTER_ID = 11, /* This ID is not used by endpoints, only policy map */
	POLICY_CLUSTER_MESH_ID = 12,
};

EXPORT_TYPE(enum identity);

/* TODO(tb): Replace this with a helper, enable_v4/v6 will be runtime configs at
 * some point.
 */
#if defined ENABLE_IPV4 && defined ENABLE_IPV6
#else
# define WORLD_IPV4_ID WORLD_ID
# define WORLD_IPV6_ID WORLD_ID
#endif

/**
 * Minimal numeric identity value for a local (CIDR) identity.
 *
 * It must be in sync with the constant identity.MinLocalIdentity
 * defined in the numericidentity.go file.
 */
#define CIDR_IDENTITY_RANGE_START ((1 << 24) + 1)
/**
 * Maximal numeric identity value for a local (CIDR) identity.
 *
 * It must be in sync with the constant identity.MaxLocalIdentity
 * defined in the numericidentity.go file.
 */
#define CIDR_IDENTITY_RANGE_END ((1 << 24) + (1 << 16) - 1)

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
 * identity_is_ingress is used to determine whether an identity is
 * reserved ingress identity (used by L7 LB).
 */
static __always_inline bool identity_is_ingress(__u32 identity)
{
	return identity == INGRESS_ID;
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
 * identity_is_world returns true if a given identity belongs to extra-cluster
 * (i.e. the world cidr range or a world identity).
 */
static __always_inline bool identity_is_world(__u32 identity)
{
#if defined ENABLE_IPV4 && defined ENABLE_IPV6
	if (identity == WORLD_ID || identity == WORLD_IPV4_ID || identity == WORLD_IPV6_ID)
		return true;
#else
	if (identity == WORLD_ID)
		return true;
#endif

	return identity_is_cidr_range(identity);
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
	return !identity_is_world(identity);
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

static __always_inline __u32 get_tunnel_id(__u32 identity)
{
#if defined ENABLE_IPV4 && defined ENABLE_IPV6
	if (identity == WORLD_IPV4_ID || identity == WORLD_IPV6_ID)
		return WORLD_ID;
#endif
	return identity;
}

static __always_inline __u32 get_id_from_tunnel_id(__u32 tunnel_id, __be16 proto  __maybe_unused)
{
#if defined ENABLE_IPV4 && defined ENABLE_IPV6
	if (tunnel_id == WORLD_ID) {
		switch (proto) {
		case bpf_htons(ETH_P_IP):
			return WORLD_IPV4_ID;
		case bpf_htons(ETH_P_IPV6):
			return WORLD_IPV6_ID;
		}
	}
#endif
	return tunnel_id;
}

/**
 * aggregate_for_identity returns the aggregated (i.e. wildcard) identity
 * for the given leaf identity.
 *
 * This **must** match the implementation in pkg/policy/aggregate.go
 */
static __always_inline __u32 aggregate_for_identity(__u32 identity)
{
	/* All remote nodes aggregate to ID 6. */
	if (identity_is_remote_node(identity))
		return REMOTE_NODE_ID;
	if (identity_is_world(identity))
		return WORLD_ID;

	if (identity == POLICY_CLUSTER_ID || identity == POLICY_CLUSTER_MESH_ID || identity == 0)
		return identity;
	/* Identities 0-99 are special, we cannot easily aggregate them. */
	if (identity < 100)
		return 0;

	/* identity is global scope and >= 100.
	 * It must be an endpoint, either in cluster or cluster mesh.
	 */
	if (extract_cluster_id_from_identity(identity) == CONFIG(cluster_id))
		return POLICY_CLUSTER_ID;

	return POLICY_CLUSTER_MESH_ID;
}
