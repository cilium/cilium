/*
 *  Copyright (C) 2016-2017 Authors of Cilium
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
#include "maps.h"

#ifdef POLICY_ENFORCEMENT

static inline int policy_can_access(void *map, struct __sk_buff *skb, __u32 src_label,
				    __u16 dport, __u8 proto, size_t cidr_addr_size, void *cidr_addr)
{
#ifdef DROP_ALL
	return DROP_POLICY;
#else
	struct policy_entry *policy;

	struct policy_key key = {
		.sec_label = src_label,
		.dport = dport,
		.protocol = proto,
		.pad = 0,
	};

#ifdef HAVE_L4_POLICY
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		cilium_dbg3(skb, DBG_L4_CREATE, src_label, SECLABEL,
			    dport << 16 | proto);

		/* FIXME: Use per cpu counters */
		__sync_fetch_and_add(&policy->packets, 1);
		__sync_fetch_and_add(&policy->bytes, skb->len);
		return TC_ACT_OK;
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

	// cidr_addr_size is a compile time constant so this should all be inlined neatly.
	if (cidr_addr_size == sizeof(union v6addr) && lpm6_ingress_lookup(cidr_addr))
		goto allow;
	if (cidr_addr_size == sizeof(__be32) && lpm4_ingress_lookup(*(__be32 *)cidr_addr))
		goto allow;

	if (skb->cb[CB_POLICY])
		goto allow;

	cilium_dbg(skb, DBG_POLICY_DENIED, src_label, SECLABEL);

#ifndef IGNORE_DROP
	return DROP_POLICY;
#endif

allow:
	return TC_ACT_OK;
#endif /* DROP_ALL */
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

static inline int is_policy_skip(struct __sk_buff *skb)
{
	return skb->cb[CB_POLICY];
}

#else /* POLICY_ENFORCEMENT */

static inline int policy_can_access(void *map, struct __sk_buff *skb, __u32 src_label,
				    __u16 dport, __u8 proto, size_t cidr_addr_size,
				    void *cidr_addr)
{
	return TC_ACT_OK;
}

static inline void policy_mark_skip(struct __sk_buff *skb)
{
}

static inline void policy_clear_mark(struct __sk_buff *skb)
{
}

static inline int is_policy_skip(struct __sk_buff *skb)
{
	return 1;
}
#endif /* !POLICY_ENFORCEMENT */

#endif
