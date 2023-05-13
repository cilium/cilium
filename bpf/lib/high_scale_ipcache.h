/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_HIGH_SCALE_IPCACHE_H_
#define __LIB_HIGH_SCALE_IPCACHE_H_

#include "maps.h"

#ifdef ENABLE_HIGH_SCALE_IPCACHE
/* WORLD_CIDR_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of
 * world_cidrs_key4.
 */
# define WORLD_CIDR_STATIC_PREFIX4						\
	(8 * (sizeof(struct world_cidrs_key4) - sizeof(struct bpf_lpm_trie_key)	\
	      - sizeof(__u32)))
#define WORLD_CIDR_PREFIX_LEN4(PREFIX) (WORLD_CIDR_STATIC_PREFIX4 + (PREFIX))

static __always_inline __maybe_unused bool
world_cidrs_lookup4(__u32 addr)
{
	__u8 *matches;
	struct world_cidrs_key4 key = {
		.lpm_key = { WORLD_CIDR_PREFIX_LEN4(V4_CACHE_KEY_LEN), {} },
		.ip = addr,
	};

	key.ip &= GET_PREFIX(V4_CACHE_KEY_LEN);
	matches = map_lookup_elem(&WORLD_CIDRS4_MAP, &key);
	return matches != NULL;
}
#endif /* ENABLE_HIGH_SCALE_IPCACHE */
#endif /* __LIB_HIGH_SCALE_IPCACHE_H_ */
