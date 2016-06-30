#ifndef __LIB_CONNTRACK_H_
#define __LIB_CONNTRACK_H_

#include "common.h"
#include "ipv6.h"
#include "dbg.h"

#define CT_DEFAULT_LIFEIME 360

enum {
	CT_NEW,
	CT_ESTABLISHED,
	CT_REPLY,
	CT_RELATED,
};

#ifndef DISABLE_CONNTRACK

#define TUPLE_F_OUT		0	/* Outgoing flow */
#define TUPLE_F_IN		1	/* Incoming flow */
#define TUPLE_F_RELATED		2	/* Flow represents related packets */

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
		cilium_trace(skb, DBG_CT_MATCH, tuple->flags, ntohl(tuple->addr.p4));
		entry->lifetime = CT_DEFAULT_LIFEIME;

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

		return CT_ESTABLISHED;
	}

	return CT_NEW;
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
static inline int __inline__ ct_lookup6(void *map, struct ipv6_ct_tuple *tuple,
					struct __sk_buff *skb, int off, __u32 secctx, int in)
{
	int ret, action = ACTION_UNSPEC;

	/* The tuple is created in reverse order initially to find a
	 * potential reverse flow. This is required because the RELATED
	 * or REPLY state takes precedence over ESTABLISHED due to
	 * policy requirements.
	 *
	 * Depending on direction, either source or destination address
	 * is assumed to be the address of the container. Therefore,
	 * the source address for incoming respectively the destination
	 * address for outgoing packets is stored in a single field in
	 * the tuple. The TUPLE_F_OUT and TUPLE_F_IN flags indicate which
	 * address the field currently represents.
	 */
	if (in)
		tuple->flags = TUPLE_F_OUT;
	else
		tuple->flags = TUPLE_F_IN;

	/* FIXME: handle extension headers */
	off += sizeof(struct ipv6hdr);

	switch (tuple->nexthdr) {
	case IPPROTO_ICMPV6:
		if (1) {
			__u8 type;

			if (skb_load_bytes(skb, off, &type, 1) < 0)
				return DROP_CT_INVALID_HDR;

			tuple->sport = 0;
			tuple->dport = 0;

			switch (type) {
			case ICMPV6_DEST_UNREACH:
			case ICMPV6_PKT_TOOBIG:
			case ICMPV6_TIME_EXCEED:
			case ICMPV6_PARAMPROB:
				tuple->flags |= TUPLE_F_RELATED;
				break;

			case ICMPV6_ECHO_REPLY:
				tuple->dport = ICMPV6_ECHO_REQUEST;
				break;

			case ICMPV6_ECHO_REQUEST:
				tuple->sport = type;
				/* fall through */
			default:
				action = ACTION_CREATE;
				break;
			}
		}
		break;

	case IPPROTO_TCP:
		if (1) {
			struct tcp_flags flags;

			if (skb_load_bytes(skb, off + 12, &flags, 2) < 0)
				return DROP_CT_INVALID_HDR;

			if (unlikely(flags.syn && !flags.ack))
				action = ACTION_CREATE;
			else {
				if (unlikely(!flags.ack))
					return DROP_CT_MISSING_ACK;

				if (unlikely(flags.rst))
					action = ACTION_DELETE;
				else if (unlikely(flags.fin))
					action = ACTION_CLOSE;
			}
		}
		/* fall through */

	case IPPROTO_UDP:
		/* load sport + dport into tuple */
		if (skb_load_bytes(skb, off, &tuple->dport, 4) < 0)
			return DROP_CT_INVALID_HDR;

		action = ACTION_CREATE;
		break;

	default:
		/* Can't handle extension headers yet */
		return DROP_CT_UNKNOWN_PROTO;
	}

	/* Lookup the reverse direction
	 *
	 * This will find an existing flow in the reverse direction.
	 */
	if ((ret = __ct_lookup6(map, skb, tuple, action, in)) != CT_NEW) {
		if (likely(ret == CT_ESTABLISHED)) {
			if (unlikely(tuple->flags & TUPLE_F_RELATED))
				ret = CT_RELATED;
			else
				ret = CT_REPLY;
		}
		goto out;
	}

	/* Lookup entry in forward direction */
	ct_tuple_reverse(tuple);
	ret = __ct_lookup6(map, skb, tuple, action, in);

	/* No entries found, packet must be eligible for creating a CT entry */
	if (ret == CT_NEW && action != ACTION_CREATE)
		ret = DROP_CT_CANT_CREATE;

out:
	cilium_trace(skb, DBG_CT_VERDICT, ret, 0);
	return ret;
}

/* Offset must point to IPv6 */
static inline void __inline__ ct_create6(void *map, struct ipv6_ct_tuple *tuple,
					 struct __sk_buff *skb, int in)
{
	/* Create entry in original direction */
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

	cilium_trace(skb, DBG_CT_CREATED, tuple->nexthdr, tuple->flags);
	map_update_elem(map, tuple, &entry, 0);

	/* Create an ICMPv6 entry to relate errors */
	if (tuple->nexthdr != IPPROTO_ICMPV6) {
		/* FIXME: We could do a lookup and check if an L3 entry already exists */
		tuple->nexthdr = IPPROTO_ICMPV6;
		tuple->sport = 0;
		tuple->dport = 0;
		tuple->flags |= TUPLE_F_RELATED;

		cilium_trace(skb, DBG_CT_CREATED, tuple->nexthdr, tuple->flags);
		map_update_elem(map, tuple, &entry, 0);
	}

	cilium_trace(skb, DBG_GENERIC, CT_NEW, 0);
}

#else /* !DISABLE_CONNTRACK */
static inline int __inline__ ct_lookup6(void *map, struct ipv6_ct_tuple *tuple,
					struct __sk_buff *skb, int off, __u32 secctx, int in)
{
	return 0;
}

static inline void __inline__ ct_create6(void *map, struct ipv6_ct_tuple *tuple, struct __sk_buff *skb, int in)
{
}
#endif

#endif
