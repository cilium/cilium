/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"

/* Magic values for L7LB metadata carried via CB_FROM_HOST.
 *
 * This overlaps with CB_NAT46_STATE, so these values must be distinct from any
 * enums declared in nat46x64 headers!
 */
#define L7LB_MAGIC 0xFACADE42
#define L7LB_MASK 0xFFFFFFC3

/* L7LB directional bitflags are carried in the bits described by the inverse of
 * L7LB_MASK.
 *
 * At the time of writing the base magic value enables bits at the 2nd and 7th
 * positions within in the least significant byte. These must not be used. In
 * future, perhaps update the magic value to free up bits 0xFF so we can drop
 * this constraint.
 */
enum {
	L7LB_DIR_FROM_HOST	= (1 << 0),
	/* (1 << 1) collides with magic */
	L7LB_DIR_TO_NETDEV	= (1 << 2),
	L7LB_DIR_TO_CONTAINER	= (1 << 3),
	/* (1 << 6) collides with magic */
};

static __always_inline void
l7lb_set_metadata(struct __ctx_buff *ctx __maybe_unused,
		  __u8 direction __maybe_unused)
{
#ifdef ENABLE_L7_LB
	__u32 magic;

	magic = (L7LB_MAGIC & L7LB_MASK) | (direction & ~L7LB_MASK);
	ctx_store_meta(ctx, CB_FROM_HOST, magic);
#endif /* ENABLE_L7_LB */
}

/* Loads any L7-LB metadata from the current skb. If a direction pointer is
 * provided, any direction bitflags encoded in the L7-LB metadata is passed back
 * to the caller via this pointer.
 */
static __always_inline bool
__l7lb_get_metadata(struct __ctx_buff *ctx __maybe_unused,
		    __u8 *direction __maybe_unused)
{
#ifdef ENABLE_L7_LB
	__u32 magic = ctx_load_meta(ctx, CB_FROM_HOST);

	if ((magic & L7LB_MASK) != L7LB_MAGIC)
		return false;

	if (direction)
		*direction = (magic & ~L7LB_MASK);

	return true;
#else
	return false;
#endif /* ENABLE_L7_LB */
}

/* Returns true if the current skb has L7-LB metadata set, ignoring the
 * presence of any L7-LB direction bitflags.
 */
static __always_inline bool
is_from_l7lb(struct __ctx_buff *ctx __maybe_unused)
{
	return __l7lb_get_metadata(ctx, NULL);
}

/* Returns true if the current skb has L7-LB metadata set, including all
 * the specified direction bitflags.
 */
static __always_inline bool
is_from_l7lb_direction(struct __ctx_buff *ctx __maybe_unused,
		       __u8 wanted_dir __maybe_unused)
{
#ifdef ENABLE_L7_LB
	__u8 direction;

	if (!__l7lb_get_metadata(ctx, &direction))
		return false;

	return (direction == wanted_dir);
#else
	return false;
#endif /* ENABLE_L7_LB */
}
