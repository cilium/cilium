#ifndef __LIB_POLICY_H_
#define __LIB_POLICY_H_

#include "drop.h"

#ifndef DISABLE_POLICY_ENFORCEMENT
static inline int policy_can_access(void *map, struct __sk_buff *skb, __u32 src_label)
{
	struct policy_entry *policy;

	policy = map_lookup_elem(map, &src_label);
	if (likely(policy)) {
		/* FIXME: Use per cpu counters */
		__sync_fetch_and_add(&policy->packets, 1);
		__sync_fetch_and_add(&policy->bytes, skb->len);
		return TC_ACT_OK;
	}

#ifdef DEBUG_POLICY
	printk("Denied by policy! (%u->%u)\n", src_label, SECLABEL);
#endif /* DEBUG_POLICY */

#ifndef IGNORE_DROP
	return TC_ACT_SHOT;
#else
	return TC_ACT_OK;
#endif /* IGNORE_DROP */
}
#else
static inline int policy_can_access(struct __sk_buff *skb, __u32 src_label)
{
	return TC_ACT_OK;
}
#endif /* !DISABLE_POLICY_ENFORCEMENT */




#endif
