/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

#ifndef __LIB_EGRESS_POLICIES_H_
#define __LIB_EGRESS_POLICIES_H_

#include "lib/identity.h"

#if defined(ENABLE_EGRESS_GATEWAY) || defined(ENABLE_SRV6)
/* is_cluster_destination returns true if the given destination is part of the
 * cluster. It uses the ipcache and endpoint maps information.
 * We check three cases:
 *  - Remote endpoints (non-zero tunnel endpoint field in ipcache)
 *  - Cilium-managed node (remote or local)
 *  - Local endpoint (present in endpoint map)
 * Everything else is outside the cluster.
 */
# define IS_CLUSTER_DESTINATION(NAME, TYPE, LOOKUP_FN)	\
static __always_inline bool				\
NAME(TYPE ip, __u32 dst_id, __u32 tunnel_endpoint)	\
{							\
	if (tunnel_endpoint != 0)			\
		return true;				\
							\
	if (identity_is_node(dst_id))			\
		return true;				\
							\
	if (LOOKUP_FN(ip))				\
		return true;				\
							\
	return false;					\
}

# ifdef ENABLE_IPV4
IS_CLUSTER_DESTINATION(is_cluster_destination4, struct iphdr *, lookup_ip4_endpoint)
# endif /* ENABLE_IPV4 */
IS_CLUSTER_DESTINATION(is_cluster_destination6, struct ipv6hdr *, lookup_ip6_endpoint)
#endif /* ENABLE_EGRESS_GATEWAY || ENABLE_SRV6 */

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

#ifdef ENABLE_SRV6
# ifdef ENABLE_IPV4

/* SRV6_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of srv6_key4 */
#  define SRV6_STATIC_PREFIX4							\
	(8 * (sizeof(struct srv6_key4) - sizeof(struct bpf_lpm_trie_key)	\
	      - 4))
#  define SRV6_PREFIX4_LEN(PREFIX) (SRV6_STATIC_PREFIX4 + (PREFIX))
#  define SRV6_IPV4_PREFIX SRV6_PREFIX4_LEN(32)
static __always_inline __maybe_unused union v6addr *
srv6_lookup4(const void *map, __be32 sip, __be32 dip)
{
	struct srv6_key4 key = {
		.lpm = { SRV6_IPV4_PREFIX, {} },
		.src_ip = sip,
		.dst_cidr = dip,
	};
	return map_lookup_elem(map, &key);
}

#  define lookup_ip4_srv6(sip, dip) \
	srv6_lookup4(&SRV6_MAP4, sip, dip)
# endif /* ENABLE_IPV4 */

/* SRV6_STATIC_PREFIX6 gets sizeof non-IP, non-prefix part of srv6_key6 */
# define SRV6_STATIC_PREFIX6							\
	(8 * (sizeof(struct srv6_key6) - sizeof(struct bpf_lpm_trie_key)	\
	      - 4))
# define SRV6_PREFIX6_LEN(PREFIX) (SRV6_STATIC_PREFIX6 + (PREFIX))
# define SRV6_IPV6_PREFIX SRV6_PREFIX6_LEN(128)

static __always_inline __maybe_unused union v6addr *
srv6_lookup6(const void *map, const union v6addr *sip,
	     const union v6addr *dip)
{
	struct srv6_key6 key = {
		.lpm = { SRV6_IPV6_PREFIX, {} },
		.src_ip = *sip,
		.dst_cidr = *dip,
	};
	return map_lookup_elem(map, &key);
}

# define lookup_ip6_srv6(sip, dip) \
	srv6_lookup6(&SRV6_MAP6, (union v6addr *)sip, (union v6addr *)dip)

#endif /* ENABLE_SRV6 */
#endif /* __LIB_EGRESS_POLICIES_H_ */
