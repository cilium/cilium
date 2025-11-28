/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

#pragma once

#include "lib/utils.h"

#define CLUSTER_ID_LOWER_MASK 0x000000FF

#ifndef __CLUSTERMESH_HELPERS__
#define __CLUSTERMESH_HELPERS__
/* these macros allow us to override the values in tests */
#define IDENTITY_LEN get_identity_len()
#define IDENTITY_MAX get_max_identity()

static __always_inline __u32
get_identity_len()
{
	__u32 identity_len = CONFIG(identity_length);
	return identity_len;
}

#endif /* __CLUSTERMESH_HELPERS__ */


static __always_inline __u32
extract_cluster_id_from_identity(__u32 identity)
{
	return (__u32)(identity >> IDENTITY_LEN);
}

static __always_inline __u32
get_max_identity()
{
	return (__u32)((1 << IDENTITY_LEN) - 1);
}

static __always_inline __maybe_unused __u32
get_cluster_id_upper_mask()
{
	return (CLUSTER_ID_MAX & ~CLUSTER_ID_LOWER_MASK) << (8 + IDENTITY_LEN);
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

	return (cluster_id_upper | cluster_id_lower) & CLUSTER_ID_MAX;
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
 * An agent with 'max-connected-clusters=512' would set identity in the mark
 * like the following:
 * CIIIIIII IIIIIIII XXXXXXXX CCCCCCCC
 */
static __always_inline __maybe_unused void
set_identity_mark(struct __ctx_buff *ctx __maybe_unused, __u32 identity __maybe_unused,
		  __u32 magic __maybe_unused)
{
#if __ctx_is == __ctx_skb
	__u32 cluster_id = (identity >> IDENTITY_LEN) & CLUSTER_ID_MAX;
	__u32 cluster_id_lower = cluster_id & 0xFF;
	__u32 cluster_id_upper = ((cluster_id & 0xFFFFFF00) << (8 + IDENTITY_LEN));

	ctx->mark = (magic & MARK_MAGIC_KEY_MASK);
	ctx->mark &= MARK_MAGIC_KEY_MASK;
	ctx->mark |= (identity & IDENTITY_MAX) << 16 | cluster_id_lower | cluster_id_upper;
#endif
}

/**
 * set_cluster_id_mark - sets the cluster_id mark.
 */
static __always_inline __maybe_unused void
ctx_set_cluster_id_mark(struct __ctx_buff *ctx __maybe_unused, __u32 cluster_id __maybe_unused)
{
/* ctx->mark not available in XDP. */
#if __ctx_is == __ctx_skb
	__u32 cluster_id_lower = (cluster_id & 0xFF);
	__u32 cluster_id_upper = ((cluster_id & 0xFFFFFF00) << (8 + IDENTITY_LEN));

	ctx->mark = cluster_id_lower | cluster_id_upper | MARK_MAGIC_CLUSTER_ID;
#endif /* __ctx_is == __ctx_skb */
}
