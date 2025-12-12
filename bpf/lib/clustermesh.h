/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

#pragma once

#include "lib/utils.h"

NODE_CONFIG(__u32, cluster_id, "Cluster ID")

NODE_CONFIG(__u32, cluster_id_max, "Max number of clusters that can be connected in Clustermesh")
ASSIGN_CONFIG(__u32, cluster_id_max, 255)

#ifndef get_cluster_id_max
static __always_inline __u32
get_cluster_id_max()
{
	return CONFIG(cluster_id_max);
}
#endif /* get_cluster_id_max() */

#define CLUSTER_ID_LOWER_MASK 0x000000FF

#ifndef __CLUSTERMESH_HELPERS__
#define __CLUSTERMESH_HELPERS__
/* these macros allow us to override the values in tests */
#define IDENTITY_LEN get_identity_len()
#define IDENTITY_MAX get_max_identity()

static __always_inline __u32
get_identity_len()
{
	return CONFIG(identity_length);
}

static __always_inline __u32
get_max_identity()
{
	return (__u32)((1 << IDENTITY_LEN) - 1);
}

#endif /* __CLUSTERMESH_HELPERS__ */


static __always_inline __u32
extract_cluster_id_from_identity(__u32 identity)
{
	return (__u32)(identity >> IDENTITY_LEN);
}

static __always_inline __maybe_unused __u32
get_cluster_id_upper_mask()
{
	return (get_cluster_id_max() & ~CLUSTER_ID_LOWER_MASK) << (8 + IDENTITY_LEN);
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
	__u32 cluster_id_upper = (ctx->mark & get_cluster_id_upper_mask()) >> (8 + IDENTITY_LEN);

	if ((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_CLUSTER_ID)
		return 0;

	return (cluster_id_upper | cluster_id_lower) & get_cluster_id_max();
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
	__u32 cluster_id_upper = (cluster_id & 0xFFFFFF00) << (8 + IDENTITY_LEN);

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
