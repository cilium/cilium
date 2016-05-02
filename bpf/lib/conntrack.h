#ifndef __LIB_CONNTRACK_H_
#define __LIB_CONNTRACK_H_

#include "common.h"
#include "ipv6.h"
#include "dbg.h"

#define CT_INVALID	0
#define CT_NEW		1
#define CT_REPLY	2

static inline int __inline__ ct_lookup6(struct __sk_buff *skb, int off,
				        struct ipv6_ct_tuple *tuple)
{
	struct ipv6_ct_entry *entry;
	__u8 nexthdr = tuple->nexthdr;
	__u8 state = CT_NEW;

	switch (tuple->nexthdr) {
	case IPPROTO_ICMPV6:
		/* ICMPv6 will trigger a lookup with ports and nexthdr set to 0. The
		 * conntrack table will contain both an entry with and wihout L4 bits
		 * to allow matching related ICMP.
		 */
		tuple->nexthdr = 0;
		break;

	case IPPROTO_TCP:
		if (tcp_load_sport(skb, off, &tuple->sport) < 0 ||
		    tcp_load_dport(skb, off, &tuple->dport) < 0)
			return CT_INVALID;
		break;

	case IPPROTO_UDP:
		if (udp_load_sport(skb, off, &tuple->sport) < 0 ||
		    udp_load_dport(skb, off, &tuple->dport) < 0)
			return CT_INVALID;
		break;
	}

	printk("CT lookup for ctx=%d sport=%d dport=%d\n",
		tuple->secctx, tuple->sport, tuple->dport);

	entry = map_lookup_elem(&cilium_ct, tuple);
	if (entry) {
		printk("CT entry found\n");
		entry->last_activity = ktime_get_ns();
		state = CT_REPLY;

		if (nexthdr == IPPROTO_ICMPV6)
			tuple->nexthdr = nexthdr;
	}

	return state;
}

/* Offset must point to IPv6 */
static inline int __inline__ ct_create6(struct __sk_buff *skb, int off, __u32 secctx)
{
	struct ipv6_ct_tuple reversed = {
		.secctx = secctx,
	};

	if (ipv6_load_nexthdr(skb, off, &reversed.nexthdr) < 0 ||
	    ipv6_load_saddr(skb, off, &reversed.dst) < 0 ||
	    ipv6_load_daddr(skb, off, &reversed.src) < 0)
		return TC_ACT_SHOT;

	off += sizeof(struct ipv6hdr);

	switch (reversed.nexthdr) {
	case IPPROTO_ICMPV6:
		break;

	case IPPROTO_TCP:
		if (tcp_load_sport(skb, off, &reversed.dport) < 0 ||
		    tcp_load_dport(skb, off, &reversed.sport) < 0)
			return TC_ACT_SHOT;
		break;

	case IPPROTO_UDP:
		if (udp_load_sport(skb, off, &reversed.dport) < 0 ||
		    udp_load_dport(skb, off, &reversed.sport) < 0)
			return TC_ACT_SHOT;
		break;

	default:
		/* Can't handle extension headers yet */
		return TC_ACT_SHOT;
	}

	if (1) {
		struct ipv6_ct_entry entry = {};
		entry.last_activity = ktime_get_ns();

		printk("CT entry updated for secctx=%d sport=%d dport=%d\n",
			secctx, reversed.sport, reversed.dport);

		if (reversed.nexthdr == IPPROTO_ICMPV6)
			reversed.nexthdr = 0;

		map_update_elem(&cilium_ct, &reversed, &entry, 0);

		if (reversed.nexthdr != IPPROTO_ICMPV6) {
			reversed.nexthdr = 0;
			reversed.sport = 0;
			reversed.dport = 0;

			map_update_elem(&cilium_ct, &reversed, &entry, 0);
		}

	}

	return 0;
}

#endif
