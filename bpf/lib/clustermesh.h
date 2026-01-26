/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

#pragma once

#include <bpf/config/node.h>

#include "lib/utils.h"

/*
 * Non node-local identity is 24 bits total. cluster_id_bits selects how many
 * bits are reserved for the Cluster ID; the remainder is the local identity.
 *
 * Example identity layout where C is a Cluster ID bit and I is a local
 * identity bit (default cluster_id_bits=8):
 * CCCCCCCC IIIIIIII IIIIIIII
 *
 * CLUSTER_ID_MAX and IDENTITY_LOCAL_MAX are the masks for the C and I portions.
 */
#define IDENTITY_BITS 24
#define IDENTITY_LOCAL_BITS (IDENTITY_BITS - CONFIG(cluster_id_bits))
#define CLUSTER_ID_MAX (__u32)((1 << CONFIG(cluster_id_bits)) - 1)
#define IDENTITY_LOCAL_MAX (__u32)((1 << IDENTITY_LOCAL_BITS) - 1)

#define CLUSTER_ID_LOWER_MASK 0x000000FF

static __always_inline __u32
extract_cluster_id_from_identity(__u32 identity)
{
	return (__u32)(identity >> IDENTITY_LOCAL_BITS);
}

static __always_inline __maybe_unused __u32
get_cluster_id_upper_mask()
{
	return (CLUSTER_ID_MAX & ~CLUSTER_ID_LOWER_MASK) << (8 + IDENTITY_LOCAL_BITS);
}

static __always_inline __maybe_unused __u32
get_mark_magic_cluster_id_mask()
{
	return CLUSTER_ID_LOWER_MASK | get_cluster_id_upper_mask();
}

static __always_inline __maybe_unused __u32
ctx_get_cluster_id_mark(const struct __ctx_buff *ctx __maybe_unused)
{
/* ctx->mark not available in XDP. */
#if __ctx_is == __ctx_skb
	__u32 cluster_id_lower = ctx->mark & CLUSTER_ID_LOWER_MASK;
	__u32 cluster_id_upper = (ctx->mark & get_cluster_id_upper_mask()) >>
				      (8 + IDENTITY_LOCAL_BITS);

	if ((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_CLUSTER_ID)
		return 0;

	return (cluster_id_upper | cluster_id_lower) & CLUSTER_ID_MAX;
#else /* __ctx_is == __ctx_xdp */
	return 0;
#endif /* __ctx_is == __ctx_xdp */
}

/**
 * format_cluster_id_mark - returns cluster_id lower and upper bits.
 */
static __always_inline __maybe_unused __u32
format_cluster_id_mark(__u32 cluster_id)
{
	__u32 cluster_id_lower = cluster_id & 0xFF;
	__u32 cluster_id_upper = (cluster_id & 0xFFFFFF00) << (8 + IDENTITY_LOCAL_BITS);

	return cluster_id_lower | cluster_id_upper;
}

/**
 * ctx_set_cluster_id_mark - sets the cluster_id mark.
 */
static __always_inline __maybe_unused void
ctx_set_cluster_id_mark(struct __ctx_buff *ctx __maybe_unused, __u32 cluster_id __maybe_unused)
{
/* ctx->mark not available in XDP. */
#if __ctx_is == __ctx_skb
	ctx->mark = format_cluster_id_mark(cluster_id) | MARK_MAGIC_CLUSTER_ID;
#endif /* __ctx_is == __ctx_skb */
}
