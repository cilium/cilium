#ifndef __LIB_POLICY_H_
#define __LIB_POLICY_H_

#include "drop.h"

enum {
	POLICY_UNSPEC,
	POLICY_SKIP,
};

#ifndef DISABLE_POLICY_ENFORCEMENT
static inline int policy_can_access(void *map, struct __sk_buff *skb, __u32 src_label)
{
	struct policy_entry *policy;

	if (skb->cb[CB_POLICY] == POLICY_SKIP)
		goto allow;

	policy = map_lookup_elem(map, &src_label);
	if (likely(policy)) {
		/* FIXME: Use per cpu counters */
		__sync_fetch_and_add(&policy->packets, 1);
		__sync_fetch_and_add(&policy->bytes, skb->len);
allow:
		return TC_ACT_OK;
	}

	cilium_trace(skb, DBG_POLICY_DENIED, src_label, SECLABEL);

#ifndef IGNORE_DROP
	return TC_ACT_SHOT;
#else
	return TC_ACT_OK;
#endif /* IGNORE_DROP */
}

static inline void policy_mark_skip(struct __sk_buff *skb)
{
	skb->cb[CB_POLICY] = POLICY_SKIP;
}

#else /* DISABLE_POLICY_ENFORCEMENT */

static inline int policy_can_access(void *map, struct __sk_buff *skb, __u32 src_label)
{
	return TC_ACT_OK;
}

static inline void policy_mark_skip(struct __sk_buff *skb)
{
}
#endif /* !DISABLE_POLICY_ENFORCEMENT */

#endif
