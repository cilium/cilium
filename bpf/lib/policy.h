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
		return TC_ACT_OK;

	/* Start with L3/L4 lookup. */
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Need byte counter */
		__sync_fetch_and_add(&policy->packets, 1);
		return policy->proxy_port;
	}

	/* L4-only lookup. */
	key.sec_label = 0;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Need byte counter */
		__sync_fetch_and_add(&policy->packets, 1);
		return policy->proxy_port;
	}
	key.sec_label = identity;

	/* If L4 policy check misses, fall back to L3. */
	key.dport = 0;
	key.protocol = 0;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Need byte counter */
		__sync_fetch_and_add(&policy->packets, 1);
		return TC_ACT_OK;
	}

	/* Final fallback if allow-all policy is in place. */
	key.sec_label = 0;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Need byte counter */
		__sync_fetch_and_add(&policy->packets, 1);
		return TC_ACT_OK;
	}

	return DROP_POLICY;
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
		    __u16 dport, __u8 proto, int dir, bool is_fragment, __u8 *match_type)
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

	/* L4 lookup can't be done on fragments. */
	if (!is_fragment) {
		/* Start with L3/L4 lookup. */
		policy = map_lookup_elem(map, &key);
		if (likely(policy)) {
			cilium_dbg3(skb, DBG_L4_CREATE, identity, SECLABEL,
				    dport << 16 | proto);

			account(skb, policy);
			*match_type = POLICY_MATCH_L3_L4;
			return policy->proxy_port;
		}

		/* L4-only lookup. */
		key.sec_label = 0;
		policy = map_lookup_elem(map, &key);
		if (likely(policy)) {
			account(skb, policy);
			*match_type = POLICY_MATCH_L4_ONLY;
			return policy->proxy_port;
		}
		key.sec_label = identity;
	}

	/* If L4 policy check misses, fall back to L3. */
	key.dport = 0;
	key.protocol = 0;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		account(skb, policy);
		*match_type = POLICY_MATCH_L3_ONLY;
		return TC_ACT_OK;
	}

	/* Final fallback if allow-all policy is in place. */
	key.sec_label = 0;
	policy = map_lookup_elem(map, &key);
	if (policy) {
		account(skb, policy);
		*match_type = POLICY_MATCH_ALL;
		return TC_ACT_OK;
	}

	if (skb->cb[CB_POLICY])
		return TC_ACT_OK;

	if (is_fragment)
		return DROP_FRAG_NOSUPPORT;
	return DROP_POLICY;
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
			  __u16 dport, __u8 proto, bool is_fragment, __u8 *match_type)
{
	int ret;

	ret = __policy_can_access(&POLICY_MAP, skb, src_identity, dport,
				      proto, CT_INGRESS, is_fragment, match_type);
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
policy_can_egress(struct __sk_buff *skb, __u32 identity, __u16 dport, __u8 proto, __u8 *match_type)
{
#ifdef ENCAP_IFINDEX
	if (is_encap(skb, dport, proto))
		return DROP_ENCAP_PROHIBITED;
#endif

	int ret = __policy_can_access(&POLICY_MAP, skb, identity, dport, proto,
				      CT_EGRESS, false, match_type);
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
				     __u32 identity, __u8 *match_type)
{
	return policy_can_egress(skb, identity, tuple->dport, tuple->nexthdr, match_type);
}

static inline int policy_can_egress4(struct __sk_buff *skb,
				     struct ipv4_ct_tuple *tuple,
				     __u32 identity, __u8 *match_type)
{
	return policy_can_egress(skb, identity, tuple->dport, tuple->nexthdr, match_type);
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
