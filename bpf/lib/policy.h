/*
 *  Copyright (C) 2016-2019 Authors of Cilium
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

#include <linux/icmp.h>

#include "drop.h"
#include "dbg.h"
#include "eps.h"
#include "maps.h"

static inline bool __inline__ inherit_identity_from_host(struct __sk_buff *skb, __u32 *identity)
{
	__u32 magic = skb->mark & MARK_MAGIC_HOST_MASK;
	bool from_proxy = false;

	/* Packets from the ingress proxy must skip the proxy when the
	 * destination endpoint evaluates the policy. As the packet
	 * would loop and/or the connection be reset otherwise. */
	if (magic == MARK_MAGIC_PROXY_INGRESS) {
		*identity = get_identity(skb);
		skb->tc_index |= TC_INDEX_F_SKIP_INGRESS_PROXY;
		from_proxy = true;
	/* (Return) packets from the egress proxy must skip the
	 * redirection to the proxy, as the packet would loop and/or
	 * the connection be reset otherwise. */
	} else if (magic == MARK_MAGIC_PROXY_EGRESS) {
		*identity = get_identity(skb);
		skb->tc_index |= TC_INDEX_F_SKIP_EGRESS_PROXY;
		from_proxy = true;
	} else if (magic == MARK_MAGIC_IDENTITY) {
		*identity = get_identity(skb);
	} else if (magic == MARK_MAGIC_HOST) {
		*identity = HOST_ID;
	} else {
		*identity = WORLD_ID;
	}

	/* Reset packet mark to avoid hitting routing rules again */
	skb->mark = 0;
	cilium_dbg(skb, DBG_INHERIT_IDENTITY, *identity, 0);

	return from_proxy;
}


/**
 * identity_is_reserved is used to determine whether an identity is one of the
 * reserved identities that are not handed out to endpoints.
 *
 * Specifically, it should return true if the identity is one of these:
 * - IdentityUnknown		(0)
 * - ReservedIdentityHost	(1)
 * - ReservedIdentityWorld	(2)
 *
 * The following identities are given to endpoints so return false for these:
 * - ReservedIdentityUnmanaged  (3)
 * - ReservedIdentityHealth	(4)
 * - ReservedIdentityInit	(5)
 *
 * Identities 128 and higher are guaranteed to be generated based on user input.
 */
static inline bool identity_is_reserved(__u32 identity)
{
	return identity < UNMANAGED_ID;
}

#ifdef SOCKMAP
static inline int __inline__
policy_sk_egress(__u32 identity, __u32 ip,  __u16 dport)
{
	void *map = lookup_ip4_endpoint_policy_map(ip);
	int dir = CT_EGRESS;
	__u8 proto = IPPROTO_TCP;
	struct policy_entry *policy;
	struct policy_key key = {
		.sec_label = identity,
		.dport = dport,
		.protocol = proto,
		.egress = !dir,
		.pad = 0,
	};

	if (!map)
		return 0;

	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Need byte counter */
		__sync_fetch_and_add(&policy->packets, 1);
		goto get_proxy_port;
	}

	/* If L4 policy check misses, fall back to L3. */
	key.dport = 0;
	key.protocol = 0;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Need byte counter */
		__sync_fetch_and_add(&policy->packets, 1);
		return TC_ACT_OK;
	}

	key.sec_label = 0;
	key.dport = dport;
	key.protocol = proto;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Use per cpu counters */
		__sync_fetch_and_add(&policy->packets, 1);
		goto get_proxy_port;
	}
	return DROP_POLICY;
get_proxy_port:
	if (likely(policy)) {
		return policy->proxy_port;
	}
	return TC_ACT_OK;
}
#else

static inline void __inline__
account(struct __sk_buff *skb, struct policy_entry *policy)
{
	/* FIXME: Use per cpu counters */
	__sync_fetch_and_add(&policy->packets, 1);
	__sync_fetch_and_add(&policy->bytes, skb->len);
}

static inline int __inline__
__policy_can_access(void *map, struct __sk_buff *skb, __u32 identity,
		    __u16 dport, __u8 proto, int dir, bool is_fragment)
{
#ifdef ALLOW_ICMP_FRAG_NEEDED
	// When ALLOW_ICMP_FRAG_NEEDED is defined we allow all packets
	// of ICMP type 3 code 4 - Fragmentation Needed
	if (proto == IPPROTO_ICMP) {
		void *data, *data_end;
		struct icmphdr icmphdr;
		struct iphdr *ip4;

		if (!revalidate_data(skb, &data, &data_end, &ip4))
			return DROP_INVALID;

		__u32 off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);

		if (skb_load_bytes(skb, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;

		if(icmphdr.type == ICMP_DEST_UNREACH && icmphdr.code == ICMP_FRAG_NEEDED)
			return TC_ACT_OK;
	}
#endif /* ALLOW_ICMP_FRAG_NEEDED */

	struct policy_entry *policy;

	struct policy_key key = {
		.sec_label = identity,
		.dport = dport,
		.protocol = proto,
		.egress = !dir,
		.pad = 0,
	};

	if (!is_fragment) {
		policy = map_lookup_elem(map, &key);
		if (likely(policy)) {
			cilium_dbg3(skb, DBG_L4_CREATE, identity, SECLABEL,
				    dport << 16 | proto);

			account(skb, policy);
			goto get_proxy_port;
		}
	}

	/* If L4 policy check misses, fall back to L3. */
	key.dport = 0;
	key.protocol = 0;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		account(skb, policy);
		return TC_ACT_OK;
	}

	if (!is_fragment) {
		key.sec_label = 0;
		key.dport = dport;
		key.protocol = proto;
		policy = map_lookup_elem(map, &key);
		if (likely(policy)) {
			account(skb, policy);
			goto get_proxy_port;
		}
		key.dport = 0;
		key.protocol = 0;
	}

	/* Final fallback if allow-all policy is in place. */
	key.sec_label = 0;
	policy = map_lookup_elem(map, &key);
	if (policy) {
		account(skb, policy);
		return TC_ACT_OK;
	}

	if (skb->cb[CB_POLICY])
		goto allow;

	if (is_fragment)
		return DROP_FRAG_NOSUPPORT;
	return DROP_POLICY;
get_proxy_port:
	if (likely(policy)) {
		return policy->proxy_port;
	}
allow:
	return TC_ACT_OK;
}

/**
 * Determine whether the policy allows this traffic on ingress.
 * @arg skb		Packet to allow or deny
 * @arg src_identity	Source security identity for this packet
 * @arg dport		Destination port of this packet
 * @arg proto		L3 Protocol of this packet
 *
 * Returns:
 *   - Positive integer indicating the proxy_port to handle this traffic
 *   - TC_ACT_OK if the policy allows this traffic based only on labels/L3/L4
 *   - Negative error code if the packet should be dropped
 */
static inline int __inline__
policy_can_access_ingress(struct __sk_buff *skb, __u32 src_identity,
			  __u16 dport, __u8 proto, bool is_fragment)
{
	int ret;

	ret = __policy_can_access(&POLICY_MAP, skb, src_identity, dport,
				      proto, CT_INGRESS, is_fragment);
	if (ret >= TC_ACT_OK)
		return ret;

	cilium_dbg(skb, DBG_POLICY_DENIED, src_identity, SECLABEL);

#ifdef IGNORE_DROP
	ret = TC_ACT_OK;
#endif

	return ret;
}

#ifdef ENCAP_IFINDEX
static inline bool __inline__
is_encap(struct __sk_buff *skb, __u16 dport, __u8 proto)
{
	return proto == IPPROTO_UDP &&
		(dport == bpf_htons(PORT_UDP_VXLAN) ||
		 dport == bpf_htons(PORT_UDP_GENEVE) ||
		 dport == bpf_htons(PORT_UDP_VXLAN_LINUX));
}
#endif

static inline int __inline__
policy_can_egress(struct __sk_buff *skb, __u32 identity, __u16 dport, __u8 proto)
{
#ifdef ENCAP_IFINDEX
	if (is_encap(skb, dport, proto))
		return DROP_ENCAP_PROHIBITED;
#endif

	int ret = __policy_can_access(&POLICY_MAP, skb, identity, dport, proto,
				      CT_EGRESS, false);
	if (ret >= 0)
		return ret;

	cilium_dbg(skb, DBG_POLICY_DENIED, SECLABEL, identity);

#ifdef IGNORE_DROP
	ret = TC_ACT_OK;
#endif

	return ret;
}

static inline int policy_can_egress6(struct __sk_buff *skb,
				     struct ipv6_ct_tuple *tuple,
				     __u32 identity)
{
	return policy_can_egress(skb, identity, tuple->dport, tuple->nexthdr);
}

static inline int policy_can_egress4(struct __sk_buff *skb,
				     struct ipv4_ct_tuple *tuple,
				     __u32 identity)
{
	return policy_can_egress(skb, identity, tuple->dport, tuple->nexthdr);
}

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

#endif // SOCKMAP
#else


static inline void policy_mark_skip(struct __sk_buff *skb)
{
}

static inline void policy_clear_mark(struct __sk_buff *skb)
{
}

#endif
