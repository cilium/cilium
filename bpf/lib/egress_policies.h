/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

#ifndef __LIB_EGRESS_POLICIES_H_
#define __LIB_EGRESS_POLICIES_H_

#include "maps.h"

#ifdef ENABLE_EGRESS_GATEWAY

/* EGRESS_STATIC_PREFIX represents the size in bits of the static prefix part of
 * an egress policy key (i.e. the source IP).
 */
#define EGRESS_STATIC_PREFIX (sizeof(__be32) * 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

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
	if (dst_id == REMOTE_NODE_ID || dst_id == HOST_ID)
		return true;

	/* Use the endpoint map to know if the destination is a local endpoint.
	 */
	if (lookup_ip4_endpoint(ip4))
		return true;

	/* Everything else is outside the cluster. */
	return false;
}

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
#endif /* __LIB_EGRESS_POLICIES_H_ */
