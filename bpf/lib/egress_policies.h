/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_EGRESS_POLICIES_H_
#define __LIB_EGRESS_POLICIES_H_

#include "lib/identity.h"

#include "maps.h"

#ifdef ENABLE_EGRESS_GATEWAY

/* EGRESS_STATIC_PREFIX represents the size in bits of the static prefix part of
 * an egress policy key (i.e. the source IP).
 */
#define EGRESS_STATIC_PREFIX (sizeof(__be32) * 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

static __always_inline
struct egress_gw_policy_entry *lookup_ip4_egress_gw_policy(__be32 saddr, __be32 daddr)
{
	struct egress_gw_policy_key key = {
		.lpm_key = { EGRESS_IPV4_PREFIX, {} },
		.saddr = saddr,
		.daddr = daddr,
	};
	return map_lookup_elem(&EGRESS_POLICY_MAP, &key);
}

#endif /* ENABLE_EGRESS_GATEWAY */

#ifdef ENABLE_SRV6
# ifdef ENABLE_IPV4

/* SRV6_VRF_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of
 * srv6_vrf_key4.
 */
#  define SRV6_VRF_STATIC_PREFIX4						\
	(8 * (sizeof(struct srv6_vrf_key4) - sizeof(struct bpf_lpm_trie_key)\
	      - 4))
#  define SRV6_VRF_PREFIX4_LEN(PREFIX) (SRV6_VRF_STATIC_PREFIX4 + (PREFIX))
#  define SRV6_VRF_IPV4_PREFIX SRV6_VRF_PREFIX4_LEN(32)
static __always_inline __u32*
srv6_lookup_vrf4(__be32 sip, __be32 dip)
{
	struct srv6_vrf_key4 key = {
		.lpm = { SRV6_VRF_IPV4_PREFIX, {} },
		.src_ip = sip,
		.dst_cidr = dip,
	};
	return map_lookup_elem(&SRV6_VRF_MAP4, &key);
}

/* SRV6_POLICY_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of
 * srv6_policy_key4.
 */
#  define SRV6_POLICY_STATIC_PREFIX4						\
	(8 * (sizeof(struct srv6_policy_key4) - sizeof(struct bpf_lpm_trie_key)	\
	      - 4))
#  define SRV6_POLICY_PREFIX4_LEN(PREFIX) (SRV6_POLICY_STATIC_PREFIX4 + (PREFIX))
#  define SRV6_POLICY_IPV4_PREFIX SRV6_POLICY_PREFIX4_LEN(32)
static __always_inline union v6addr *
srv6_lookup_policy4(__u32 vrf_id, __be32 dip)
{
	struct srv6_policy_key4 key = {
		.lpm = { SRV6_POLICY_IPV4_PREFIX, {} },
		.vrf_id = vrf_id,
		.dst_cidr = dip,
	};
	return map_lookup_elem(&SRV6_POLICY_MAP4, &key);
}
# endif /* ENABLE_IPV4 */

/* SRV6_VRF_STATIC_PREFIX6 gets sizeof non-IP, non-prefix part of
 * srv6_vrf_key6.
 */
#  define SRV6_VRF_STATIC_PREFIX6						\
	(8 * (sizeof(struct srv6_vrf_key6) - sizeof(struct bpf_lpm_trie_key)\
	      - 4))
#  define SRV6_VRF_PREFIX6_LEN(PREFIX) (SRV6_VRF_STATIC_PREFIX6 + (PREFIX))
#  define SRV6_VRF_IPV6_PREFIX SRV6_VRF_PREFIX6_LEN(32)
static __always_inline __u32*
srv6_lookup_vrf6(const struct in6_addr *sip, const struct in6_addr *dip)
{
	struct srv6_vrf_key6 key = {
		.lpm = { SRV6_VRF_IPV6_PREFIX, {} },
		.src_ip = *(union v6addr *)sip,
		.dst_cidr = *(union v6addr *)dip,
	};
	return map_lookup_elem(&SRV6_VRF_MAP6, &key);
}

/* SRV6_POLICY_STATIC_PREFIX6 gets sizeof non-IP, non-prefix part of
 * srv6_policy_key6.
 */
# define SRV6_POLICY_STATIC_PREFIX6						\
	(8 * (sizeof(struct srv6_policy_key6) - sizeof(struct bpf_lpm_trie_key)	\
	      - 4))
# define SRV6_POLICY_PREFIX6_LEN(PREFIX) (SRV6_POLICY_STATIC_PREFIX6 + (PREFIX))
# define SRV6_POLICY_IPV6_PREFIX SRV6_POLICY_PREFIX6_LEN(128)

static __always_inline union v6addr *
srv6_lookup_policy6(__u32 vrf_id, const struct in6_addr *dip)
{
	struct srv6_policy_key6 key = {
		.lpm = { SRV6_POLICY_IPV6_PREFIX, {} },
		.vrf_id = vrf_id,
		.dst_cidr = *(union v6addr *)dip,
	};
	return map_lookup_elem(&SRV6_POLICY_MAP6, &key);
}
#endif /* ENABLE_SRV6 */
#endif /* __LIB_EGRESS_POLICIES_H_ */
