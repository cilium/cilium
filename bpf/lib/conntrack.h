#ifndef __LIB_CONNTRACK_H_
#define __LIB_CONNTRACK_H_

#include "common.h"
#include "ipv6.h"
#include "dbg.h"

#define CT_DEFAULT_LIFEIME 360

#ifndef DISABLE_CONNTRACK

enum {
	ACTION_UNSPEC,
	ACTION_CREATE,
	ACTION_CLOSE,
	ACTION_DELETE,
};


static inline int __inline__ __ct_lookup6(void *map, struct __sk_buff *skb,
					  struct ipv6_ct_tuple *tuple,
					  int action, int in)
{
	struct ipv6_ct_entry *entry;

	cilium_trace(skb, DBG_CT_LOOKUP, tuple->sport, tuple->dport);

	if ((entry = map_lookup_elem(map, tuple))) {
		cilium_trace(skb, DBG_CT_MATCH, ntohl(tuple->addr.p3), ntohl(tuple->addr.p4));
		entry->lifetime = CT_DEFAULT_LIFEIME;

		if (action == ACTION_CREATE) {
			/* Connection already established in reverse direction. Stale entry
			 * or malicious packet. */
			return POLICY_DROP;
		}

		/* FIXME: This is slow, per-cpu counters? */
		if (in) {
			__sync_fetch_and_add(&entry->rx_packets, 1);
			__sync_fetch_and_add(&entry->rx_bytes, skb->len);
		} else {
			__sync_fetch_and_add(&entry->tx_packets, 1);
			__sync_fetch_and_add(&entry->tx_bytes, skb->len);
		}

		switch (action) {
		case ACTION_CLOSE:
			/* RST or similar, immediately delete ct entry */
			if (in) {
				entry->rx_closing = 1;
			} else {
				entry->tx_closing = 1;
			}

			if (entry->rx_closing && entry->tx_closing) {
				/* fall through */
			} else
				break;

		case ACTION_DELETE:
			map_delete_elem(map, tuple);
			break;
		}

		return POLICY_SKIP;
	}

	return POLICY_UNSPEC;
}

struct tcp_flags {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
};

static inline int ct_tuple_is_ingress(struct ipv6_ct_tuple *tuple)
{
	return tuple->flags & TUPLE_F_IN;
}

static inline void __inline__ ct_tuple_reverse(struct ipv6_ct_tuple *tuple)
{
	/* The meaning of .addr switches without requiring to copy bits
	 * around, we only have to swap the ports */
	__u16 tmp = tuple->sport;
	tuple->sport = tuple->dport;
	tuple->dport = tmp;

	/* Flip ingress/egress flag */
	if (ct_tuple_is_ingress(tuple))
		tuple->flags &= ~TUPLE_F_IN;
	else
		tuple->flags |= TUPLE_F_IN;
}

/* Offset must point to IPv6 */
static inline int __inline__ ct_create6(void *map, struct __sk_buff *skb,
					int off, __u32 secctx, int in)
{
	struct ipv6_ct_tuple tuple = {};
	int ret, action = ACTION_UNSPEC;

	/* Depending on direction, either source or destination address
	 * is assumed to be the address of the container. */
	if (in) {
		if (ipv6_load_saddr(skb, off, &tuple.addr) < 0)
			return POLICY_DROP;

		tuple.flags = TUPLE_F_IN;
	} else {
		if (ipv6_load_daddr(skb, off, &tuple.addr) < 0)
			return POLICY_DROP;

		tuple.flags = TUPLE_F_OUT;
	}

	if (ipv6_load_nexthdr(skb, off, &tuple.nexthdr) < 0)
		return POLICY_DROP;

	/* FIXME: handle extension headers */
	off += sizeof(struct ipv6hdr);

	switch (tuple.nexthdr) {
	case IPPROTO_ICMPV6:
		tuple.sport = 0;
		tuple.dport = 0;
		break;

	case IPPROTO_TCP:
		if (1) {
			struct tcp_flags flags;

			if (skb_load_bytes(skb, off + 12, &flags, 2) < 0)
				return POLICY_DROP;

			if (unlikely(flags.syn && !flags.ack))
				action = ACTION_CREATE;
			else {
				if (unlikely(!flags.ack))
					return POLICY_DROP;

				if (unlikely(flags.rst))
					action = ACTION_DELETE;
				else if (unlikely(flags.fin))
					action = ACTION_CLOSE;
			}
		}
		/* fall through */

	case IPPROTO_UDP:
		/* load sport + dport into tuple */
		if (skb_load_bytes(skb, off, &tuple.sport, 4) < 0)
			return POLICY_DROP;
		break;

	default:
		/* Can't handle extension headers yet */
		return POLICY_DROP;
	}

	/* Lookup entry in forward direction */
	if ((ret = __ct_lookup6(map, skb, &tuple, action, in)) != POLICY_UNSPEC) {
		if (ret == POLICY_SKIP && tuple.nexthdr != IPPROTO_ICMPV6)
			ret = POLICY_UNSPEC;
		return ret;
	}

	/* Lookup entry in reverse direction */
	ct_tuple_reverse(&tuple);
	if ((ret = __ct_lookup6(map, skb, &tuple, action, in)) != POLICY_UNSPEC)
		return ret;

	if (action != ACTION_CREATE && action != ACTION_UNSPEC)
		return POLICY_DROP;

	/* Create entry in original direction.
	 *
	 * FIXME: Lookup reverse direction first so we don't have to reverse twice */
	ct_tuple_reverse(&tuple);

	if (1) {
		struct ipv6_ct_entry entry = {
			.lifetime = CT_DEFAULT_LIFEIME,
		};

		if (in) {
			entry.rx_packets = 1;
			entry.rx_bytes = skb->len;
		} else {
			entry.tx_packets = 1;
			entry.tx_bytes = skb->len;
		}

		cilium_trace(skb, DBG_CT_CREATED, tuple.nexthdr, 0);
		map_update_elem(map, &tuple, &entry, 0);

		/* Create an ICMPv6 entry to relate errors */
		if (tuple.nexthdr != IPPROTO_ICMPV6) {
			/* FIXME: We could do a lookup and check if an L3 entry already exists */
			tuple.nexthdr = IPPROTO_ICMPV6;
			tuple.sport = 0;
			tuple.dport = 0;

			cilium_trace(skb, DBG_CT_CREATED, tuple.sport, tuple.dport);
			map_update_elem(map, &tuple, &entry, 0);
		}
	}

	return 0;
}

static inline int __inline__ ct_create6_in(void *map, struct __sk_buff *skb, int off, __u32 secctx)
{
	return ct_create6(map, skb, off, secctx, 1);
}

static inline int __inline__ ct_create6_out(void *map, struct __sk_buff *skb, int off, __u32 secctx)
{
	return ct_create6(map, skb, off, secctx, 0);
}

#else /* !DISABLE_CONNTRACK */
static inline int __inline__ ct_create6_in(void *map, struct __sk_buff *skb, int off, __u32 secctx)
{
	return 0;
}

static inline int __inline__ ct_create6_out(void *map, struct __sk_buff *skb, int off, __u32 secctx)
{
	return 0;
}
#endif

#endif
