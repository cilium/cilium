/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

#ifndef __LIB_EGRESS_POLICIES_H_
#define __LIB_EGRESS_POLICIES_H_

#ifdef ENABLE_EGRESS_GATEWAY
/* EGRESS_STATIC_PREFIX gets sizeof non-IP, non-prefix part of egress_key */
# define EGRESS_STATIC_PREFIX							\
	(8 * (sizeof(struct egress_key) - sizeof(struct bpf_lpm_trie_key)	\
	      - 4))
# define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
# define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

static __always_inline __maybe_unused struct egress_info *
egress_lookup4(const void *map, __be32 sip, __be32 dip)
{
	struct egress_key key = {
		.lpm_key = { EGRESS_IPV4_PREFIX, {} },
		.sip = sip,
		.dip = dip,
	};
	return map_lookup_elem(map, &key);
}

# define lookup_ip4_egress_endpoint(sip, dip) \
	egress_lookup4(&EGRESS_MAP, sip, dip)
#endif /* ENABLE_EGRESS_GATEWAY */
#endif /* __LIB_EGRESS_POLICIES_H_ */
