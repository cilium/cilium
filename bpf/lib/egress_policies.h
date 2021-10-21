/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

#ifndef __LIB_EGRESS_POLICIES_H_
#define __LIB_EGRESS_POLICIES_H_

#include "lib/identity.h"

#ifdef ENABLE_EGRESS_GATEWAY
/* is_cluster_destination returns true if the given destination is part of the
 * cluster. It uses the ipcache and endpoint maps information.
 */
static __always_inline bool
is_cluster_destination(struct iphdr *ip4, __u32 dst_id, __u32 tunnel_endpoint)
{
	/* If tunnel endpoint is found in ipcache, it means the remote endpoint
	 * is in cluster.
	 */
	if (tunnel_endpoint != 0)
		return true;

	/* If the destination is a Cilium-managed node (remote or local), it's
	 * part of the cluster.
	 */
	if (identity_is_node(dst_id))
		return true;

	/* Use the endpoint map to know if the destination is a local endpoint.
	 */
	if (lookup_ip4_endpoint(ip4))
		return true;

	/* Everything else is outside the cluster. */
	return false;
}

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
