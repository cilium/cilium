/*
 *  Copyright (C) 2016-2018 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __LIB_POLICY_H_
#define __LIB_POLICY_H_

#include "drop.h"
#include "eps.h"
#include "maps.h"

/**
 * MinimalNumericIdentity describes the lowest possible identity
 * allocated to endpoints. Numbers lower than this indicated
 * reserved identities.
 */
#define MINIMAL_NUMERIC_IDENTITY 256

#if defined POLICY_INGRESS || defined POLICY_EGRESS
#define REQUIRES_CAN_ACCESS
#endif

#ifdef REQUIRES_CAN_ACCESS
static inline bool identity_is_reserved(__u32 identity)
{
	return identity < MINIMAL_NUMERIC_IDENTITY;
}

static inline int __inline__
__policy_can_access(void *map, struct __sk_buff *skb, __u32 identity,
		    __u16 dport, __u8 proto, size_t cidr_addr_size,
		    void *cidr_addr, int dir)
{
#ifdef DROP_ALL
	return DROP_POLICY;
#else
	struct policy_entry *policy;

	struct policy_key key = {
		.sec_label = identity,
		.dport = dport,
		.protocol = proto,
		.egress = !dir,
		.pad = 0,
	};

#ifdef HAVE_L4_POLICY
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		cilium_dbg3(skb, DBG_L4_CREATE, identity, SECLABEL,
			    dport << 16 | proto);

		/* FIXME: Use per cpu counters */
		__sync_fetch_and_add(&policy->packets, 1);
		__sync_fetch_and_add(&policy->bytes, skb->len);
		goto get_proxy_port;
	}
#endif /* HAVE_L4_POLICY */

	/* If L4 policy check misses, fall back to L3. */
	key.dport = 0;
	key.protocol = 0;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Use per cpu counters */
		__sync_fetch_and_add(&policy->packets, 1);
		__sync_fetch_and_add(&policy->bytes, skb->len);
		return TC_ACT_OK;
	}

#ifdef HAVE_L4_POLICY
	key.sec_label = 0;
	key.dport = dport;
	key.protocol = proto;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Use per cpu counters */
		__sync_fetch_and_add(&policy->packets, 1);
		__sync_fetch_and_add(&policy->bytes, skb->len);
		goto get_proxy_port;
	}
#endif /* HAVE_L4_POLICY */

	if (skb->cb[CB_POLICY])
		goto allow;

	return DROP_POLICY;
#ifdef HAVE_L4_POLICY
get_proxy_port:
	if (likely(policy)) {
		if (policy->proxy_port)
			return policy->proxy_port;
		else
			return l4_proxy_lookup(skb, proto, dport, dir);
	}
#endif /* HAVE_L4_POLICY */
allow:
	return TC_ACT_OK;
#endif /* DROP_ALL */
}

#endif /* REQUIRES_CAN_ACCESS */

#ifdef POLICY_INGRESS

/**
 * Determine whether the policy allows this traffic on ingress.
 * @arg skb		Packet to allow or deny
 * @arg src_identity	Source security identity for this packet
 * @arg dport		Destination port of this packet
 * @arg proto		L3 Protocol of this packet
 * @arg cidr_addr_size	Size of the destination CIDR of this packet
 * @arg cidr_addr	Destination CIDR of this packet
 *
 * Returns:
 *   - Positive integer indicating the proxy_port to handle this traffic
 *   - TC_ACT_OK if the policy allows this traffic based only on labels/L3/L4
 *   - Negative error code if the packet should be dropped
 */
static inline int __inline__
policy_can_access_ingress(struct __sk_buff *skb, __u32 *src_identity,
			  __u16 dport, __u8 proto, size_t cidr_addr_size,
			  void *cidr_addr)
{
#ifdef DROP_ALL
	return DROP_POLICY;
#else
	int ret;

	if (identity_is_reserved(*src_identity)) {
		if (cidr_addr_size == sizeof(union v6addr)) {
			struct remote_endpoint_info *info;

			info = lookup_ip6_remote_endpoint(cidr_addr);
			if (info)
				*src_identity = info->sec_label;

			cilium_dbg(skb, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
				   ((__u32 *) cidr_addr)[3], *src_identity);
		}

		if (cidr_addr_size == sizeof(__be32)) {
			struct remote_endpoint_info *info;
			__be32 saddr = *(__be32 *)cidr_addr;

			if ((info = lookup_ip4_remote_endpoint(saddr)))
				*src_identity = info->sec_label;

			cilium_dbg(skb, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
				   saddr, *src_identity);
		}
	}

	ret = __policy_can_access(&POLICY_MAP, skb, *src_identity, dport,
				      proto, cidr_addr_size, cidr_addr,
				      CT_INGRESS);
	if (ret >= TC_ACT_OK)
		return ret;

	cilium_dbg(skb, DBG_POLICY_DENIED, *src_identity, SECLABEL);

#ifndef IGNORE_DROP
	return DROP_POLICY;
#else
	return TC_ACT_OK;
#endif
#endif /* DROP_ALL */
}

#else /* POLICY_INGRESS */

static inline int
policy_can_access_ingress(struct __sk_buff *skb, __u32 *src_label,
			  __u16 dport, __u8 proto, size_t cidr_addr_size,
			  void *cidr_addr)
{
#ifdef DROP_ALL
	return DROP_POLICY;
#else
	return TC_ACT_OK;
#endif
}

#endif /* POLICY_INGRESS */

#if defined POLICY_EGRESS && defined LXC_ID

static inline int __inline__
policy_can_egress(struct __sk_buff *skb, __u16 identity, __u16 dport, __u8 proto)
{
#ifdef DROP_ALL
	return DROP_POLICY;
#else
	int ret = __policy_can_access(&POLICY_MAP, skb, identity, dport, proto,
				      0, NULL, CT_EGRESS);
	if (ret >= 0)
		return ret;

	cilium_dbg(skb, DBG_POLICY_DENIED, SECLABEL, identity);
#ifndef IGNORE_DROP
	return DROP_POLICY;
#endif
	return TC_ACT_OK;
#endif /* DROP_ALL */
}

static inline int policy_can_egress6(struct __sk_buff *skb,
				     struct ipv6_ct_tuple *tuple,
				     __u16 default_identity,
				     union v6addr *daddr)
{
#ifdef DROP_ALL
	return DROP_POLICY;
#else
	struct remote_endpoint_info *info;
	__u16 identity = default_identity;

	info = lookup_ip6_remote_endpoint(daddr);
	if (info)
		identity = info->sec_label;
	cilium_dbg(skb, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
		   daddr->p4, identity);

	return policy_can_egress(skb, identity, tuple->dport, tuple->nexthdr);
#endif /* DROP_ALL */
}

static inline int policy_can_egress4(struct __sk_buff *skb,
				     struct ipv4_ct_tuple *tuple,
				     __u16 default_identity, __be32 daddr)
{
#ifdef DROP_ALL
	return DROP_POLICY;
#else
	struct remote_endpoint_info *info;
	__u16 identity = default_identity;

	info = lookup_ip4_remote_endpoint(daddr);
	if (info)
		identity = info->sec_label;
	cilium_dbg(skb, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
		   daddr, identity);

	return policy_can_egress(skb, identity, tuple->dport, tuple->nexthdr);
#endif /* DROP_ALL */
}

#else /* POLICY_EGRESS && LXC_ID */

static inline int
policy_can_egress6(struct __sk_buff *skb, struct ipv6_ct_tuple *tuple,
		   __u16 default_identity, union v6addr *daddr)
{
#ifdef DROP_ALL
	return DROP_POLICY;
#else
	return TC_ACT_OK;
#endif
}

static inline int
policy_can_egress4(struct __sk_buff *skb, struct ipv4_ct_tuple *tuple,
		   __u16 default_identity, __be32 daddr)
{
#ifdef DROP_ALL
	return DROP_POLICY;
#else
	return TC_ACT_OK;
#endif
}
#endif /* POLICY_EGRESS && LXC_ID */

#if !defined DROP_ALL && (defined POLICY_INGRESS || defined POLICY_EGRESS)

/**
 * Mark skb to skip policy enforcement
 * @arg skb	packet
 *
 * Will cause the packet to ignore the policy enforcement layer and
 * be considered accepted despite of the policy outcome.
 */
static inline void policy_mark_skip(struct __sk_buff *skb)
{
	skb->cb[CB_POLICY] = 1;
}

static inline void policy_clear_mark(struct __sk_buff *skb)
{
	skb->cb[CB_POLICY] = 0;
}

static inline int is_policy_skip(struct __sk_buff *skb)
{
	return skb->cb[CB_POLICY];
}

#else /* POLICY_INGRESS || POLICY_EGRESS */


static inline void policy_mark_skip(struct __sk_buff *skb)
{
}

static inline void policy_clear_mark(struct __sk_buff *skb)
{
}

static inline int is_policy_skip(struct __sk_buff *skb)
{
#ifdef DROP_ALL
	return 0;
#else
	return 1;
#endif
}
#endif /* POLICY_INGRESS || POLICY_EGRESS */

#endif
