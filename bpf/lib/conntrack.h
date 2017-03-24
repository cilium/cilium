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
#ifndef __LIB_CONNTRACK_H_
#define __LIB_CONNTRACK_H_

#include <linux/icmpv6.h>
#include <linux/icmp.h>

#include "common.h"
#include "ipv6.h"
#include "dbg.h"
#include "l4.h"

#define CT_DEFAULT_LIFEIME 360

enum {
	CT_NEW,
	CT_ESTABLISHED,
	CT_REPLY,
	CT_RELATED,
};

#ifdef CONNTRACK

#define TUPLE_F_OUT		0	/* Outgoing flow */
#define TUPLE_F_IN		1	/* Incoming flow */
#define TUPLE_F_RELATED		2	/* Flow represents related packets */

enum {
	ACTION_UNSPEC,
	ACTION_CREATE,
	ACTION_CLOSE,
	ACTION_DELETE,
};

static inline int __inline__ __ct_lookup(void *map, struct __sk_buff *skb,
					 void *tuple, int action, int dir,
					 struct ct_state *ct_state)
{
	struct ct_entry *entry;
	int ret;

	if ((entry = map_lookup_elem(map, tuple))) {
		cilium_trace(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
		entry->lifetime = CT_DEFAULT_LIFEIME;
		if (ct_state) {
			ct_state->rev_nat_index = entry->rev_nat_index;
			ct_state->loopback = entry->lb_loopback;
			ct_state->proxy_port = entry->proxy_port;
		}

#ifdef LXC_NAT46
		/* This packet needs nat46 translation */
		if (entry->nat46 && !skb->cb[CB_NAT46_STATE])
			skb->cb[CB_NAT46_STATE] = NAT46;
#endif

#ifdef CONNTRACK_ACCOUNTING
		/* FIXME: This is slow, per-cpu counters? */
		if (dir == CT_INGRESS) {
			__sync_fetch_and_add(&entry->rx_packets, 1);
			__sync_fetch_and_add(&entry->rx_bytes, skb->len);
		} else {
			__sync_fetch_and_add(&entry->tx_packets, 1);
			__sync_fetch_and_add(&entry->tx_bytes, skb->len);
		}
#endif

		switch (action) {
		case ACTION_CLOSE:
			/* RST or similar, immediately delete ct entry */
			if (dir == CT_INGRESS)
				entry->rx_closing = 1;
			else
				entry->tx_closing = 1;

			if (!entry->rx_closing || !entry->tx_closing)
				break;
			/* fall through */

		case ACTION_DELETE:
			if ((ret = map_delete_elem(map, tuple)) < 0)
				cilium_trace(skb, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, ret);
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

static inline void __inline__ ipv6_ct_tuple_reverse(struct ipv6_ct_tuple *tuple)
{
	__u16 tmp;

#ifndef CONNTRACK_LOCAL
	union v6addr tmp_addr = {};
	ipv6_addr_copy(&tmp_addr, &tuple->saddr);
	ipv6_addr_copy(&tuple->saddr, &tuple->daddr);
	ipv6_addr_copy(&tuple->daddr, &tmp_addr);
#endif

	/* The meaning of .addr switches without requiring to copy bits
	 * around, we only have to swap the ports */
	tmp = tuple->sport;
	tuple->sport = tuple->dport;
	tuple->dport = tmp;

	/* Flip ingress/egress flag */
	if (tuple->flags & TUPLE_F_IN)
		tuple->flags &= ~TUPLE_F_IN;
	else
		tuple->flags |= TUPLE_F_IN;
}

/* Offset must point to IPv6 */
static inline int __inline__ ct_lookup6(void *map, struct ipv6_ct_tuple *tuple,
					struct __sk_buff *skb, int l4_off, __u32 secctx, int dir,
					struct ct_state *ct_state)
{
	int ret = CT_NEW, action = ACTION_UNSPEC;

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
	if (dir == CT_INGRESS)
		tuple->flags = TUPLE_F_OUT;
	else
		tuple->flags = TUPLE_F_IN;

	switch (tuple->nexthdr) {
	case IPPROTO_ICMPV6:
		if (1) {
			__u8 type;

			if (skb_load_bytes(skb, l4_off, &type, 1) < 0)
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

			if (skb_load_bytes(skb, l4_off + 12, &flags, 2) < 0)
				return DROP_CT_INVALID_HDR;

			if (unlikely(flags.syn && !flags.ack))
				action = ACTION_CREATE;
			else {
				if (unlikely(flags.rst))
					action = ACTION_DELETE;
				else if (unlikely(flags.fin))
					action = ACTION_CLOSE;

				/* FIXME: Drop packets here with missing ACK flag? */
			}
		}
		/* fall through */

	case IPPROTO_UDP:
		/* load sport + dport into tuple */
		if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
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
	 * The reverse direction is the one where reverse nat index is stored.
	 */
	cilium_trace(skb, DBG_CT_LOOKUP, (ntohs(tuple->sport) << 16) | ntohs(tuple->dport),
		     (tuple->nexthdr << 8) | tuple->flags);
	if ((ret = __ct_lookup(map, skb, tuple, action, dir, ct_state)) != CT_NEW) {
		if (likely(ret == CT_ESTABLISHED)) {
			if (unlikely(tuple->flags & TUPLE_F_RELATED))
				ret = CT_RELATED;
			else
				ret = CT_REPLY;
		}
		goto out;
	}

	/* Lookup entry in forward direction */
	ipv6_ct_tuple_reverse(tuple);
	cilium_trace(skb, DBG_CT_LOOKUP, (ntohs(tuple->sport) << 16) | ntohs(tuple->dport),
		     (tuple->nexthdr << 8) | tuple->flags);
	ret = __ct_lookup(map, skb, tuple, action, dir, NULL);

#ifdef LXC_NAT46
	skb->cb[CB_NAT46_STATE] = NAT46_CLEAR;
#endif
	/* No entries found, packet must be eligible for creating a CT entry */
	if (ret == CT_NEW && action != ACTION_CREATE)
		ret = DROP_CT_CANT_CREATE;

out:
	cilium_trace(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret, 0);
	return ret;
}

static inline void __inline__ ipv4_ct_tuple_reverse(struct ipv4_ct_tuple *tuple)
{
	__u16 tmp;

#ifndef CONNTRACK_LOCAL
	__be32 tmp_addr = tuple->saddr;
	tuple->saddr = tuple->daddr;
	tuple->daddr = tmp_addr;
#endif

	/* The meaning of .addr switches without requiring to copy bits
	 * around for CONNTRACK_LOCAL, we only have to swap the ports */
	tmp = tuple->sport;
	tuple->sport = tuple->dport;
	tuple->dport = tmp;

	/* Flip ingress/egress flag */
	if (tuple->flags & TUPLE_F_IN)
		tuple->flags &= ~TUPLE_F_IN;
	else
		tuple->flags |= TUPLE_F_IN;
}

/* Offset must point to IPv4 header */
static inline int __inline__ ct_lookup4(void *map, struct ipv4_ct_tuple *tuple,
					struct __sk_buff *skb, int off, __u32 secctx, int dir,
					struct ct_state *ct_state)
{
	int ret = CT_NEW, action = ACTION_UNSPEC;
	int type = 0;
	__be32 addr;

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
	if (dir == CT_INGRESS)
		tuple->flags = TUPLE_F_OUT;
	else
		tuple->flags = TUPLE_F_IN;

	switch (tuple->nexthdr) {
	case IPPROTO_ICMP:
		if (1) {
			if (skb_load_bytes(skb, off, &type, 1) < 0)
				return DROP_CT_INVALID_HDR;

			tuple->sport = 0;
			tuple->dport = 0;

			switch (type) {
			case ICMP_DEST_UNREACH:
			case ICMP_TIME_EXCEEDED:
			case ICMP_PARAMETERPROB:
				tuple->flags |= TUPLE_F_RELATED;
				break;

			case ICMP_ECHOREPLY:
				tuple->dport = ICMP_ECHO;
				break;

			case ICMP_ECHO:
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
				if (unlikely(flags.rst))
					action = ACTION_DELETE;
				else if (unlikely(flags.fin))
					action = ACTION_CLOSE;

				/* FIXME: Drop packets here with missing ACK flag? */
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
	cilium_trace(skb, DBG_CT_LOOKUP, (ntohs(tuple->sport) << 16) | ntohs(tuple->dport),
		     (tuple->nexthdr << 8) | tuple->flags);
#ifdef CONNTRACK_LOCAL
	addr = tuple->addr;
#else
	addr = (dir == CT_INGRESS) ? tuple->saddr : tuple->daddr;
#endif
	cilium_trace(skb, DBG_CT_LOOKUP4, addr, 0);
	if ((ret = __ct_lookup(map, skb, tuple, action, dir, ct_state)) != CT_NEW) {
		if (likely(ret == CT_ESTABLISHED)) {
			if (unlikely(tuple->flags & TUPLE_F_RELATED))
				ret = CT_RELATED;
			else
				ret = CT_REPLY;
		}
		goto out;
	}

	/* Lookup entry in forward direction */
	ipv4_ct_tuple_reverse(tuple);
	cilium_trace(skb, DBG_CT_LOOKUP, (ntohs(tuple->sport) << 16) | ntohs(tuple->dport),
		     (tuple->nexthdr << 8) | tuple->flags);
	ret = __ct_lookup(map, skb, tuple, action, dir, ct_state);

	/* No entries found, packet must be eligible for creating a CT entry */
	if (ret == CT_NEW && action != ACTION_CREATE)
		ret = DROP_CT_CANT_CREATE;

out:
	cilium_trace(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret, 0);
	return ret;
}

/* Offset must point to IPv6 */
static inline int __inline__ ct_create6(void *map, struct ipv6_ct_tuple *tuple,
					struct __sk_buff *skb, int dir,
					struct ct_state *ct_state)
{
	__u32 addr_p4;

	/* Create entry in original direction */
	struct ct_entry entry = {
		.lifetime = CT_DEFAULT_LIFEIME,
	};
	int proxy_port = 0;

	entry.rev_nat_index = ct_state->rev_nat_index;
	entry.lb_loopback = ct_state->loopback;

	if (dir == CT_INGRESS) {
		if (tuple->nexthdr == IPPROTO_UDP ||
		    tuple->nexthdr == IPPROTO_TCP) {
			/* Resolve L4 policy. This may fail due to policy reasons. May
			 * optonally return a proxy port number to redirect all traffic to.
			 */
			proxy_port = l4_ingress_policy(skb, tuple->dport, tuple->nexthdr);
			if (IS_ERR(proxy_port))
				return proxy_port;

			cilium_trace(skb, DBG_L4_POLICY, proxy_port, CT_INGRESS);

			/* FIXME:
			 * Drop all packets which need to go to the proxy for now
			 * as we do not support redirection yet and the expectation
			 * may be to apply security rules.
			 */
			if (proxy_port)
				return DROP_POLICY;
		}

		entry.rx_packets = 1;
		entry.rx_bytes = skb->len;
	} else {
		if (tuple->nexthdr == IPPROTO_UDP ||
		    tuple->nexthdr == IPPROTO_TCP) {
			/* Resolve L4 policy. This may fail due to policy reasons. May
			 * optonally return a proxy port number to redirect all traffic to.
			 */
			proxy_port = l4_egress_policy(skb, tuple->dport, tuple->nexthdr);
			if (IS_ERR(proxy_port))
				return proxy_port;

			cilium_trace(skb, DBG_L4_POLICY, proxy_port, CT_EGRESS);

			/* FIXME:
			 * Drop all packets which need to go to the proxy for now
			 * as we do not support redirection yet and the expectation
			 * may be to apply security rules.
			 */
			if (proxy_port)
				return DROP_POLICY;
		}

		entry.tx_packets = 1;
		entry.tx_bytes = skb->len;
	}

	entry.proxy_port = proxy_port;

	cilium_trace(skb, DBG_CT_CREATED, (ntohs(tuple->sport) << 16) | ntohs(tuple->dport),
		     (tuple->nexthdr << 8) | tuple->flags);
#ifdef CONNTRACK_LOCAL
	addr_p4 = tuple->addr.p4;
#else
	addr_p4 = (dir == CT_INGRESS) ? tuple->saddr.p4 : tuple->daddr.p4;
#endif
	cilium_trace(skb, DBG_CT_CREATED2, addr_p4, ct_state->rev_nat_index);
	if (map_update_elem(map, tuple, &entry, 0) < 0)
		return DROP_CT_CREATE_FAILED;

	/* Create an ICMPv6 entry to relate errors */
	/* FIXME: We could do a lookup and check if an L3 entry already exists */
	tuple->nexthdr = IPPROTO_ICMPV6;
	tuple->sport = 0;
	tuple->dport = 0;
	tuple->flags |= TUPLE_F_RELATED;
	entry.proxy_port = 0;

	cilium_trace(skb, DBG_CT_CREATED, 0, (tuple->nexthdr << 8) | tuple->flags);
	if (map_update_elem(map, tuple, &entry, 0) < 0) {
		/* Previous map update succeeded, we could delete it
		 * but we might as well just let it time out.
		 */
		return DROP_CT_CREATE_FAILED;
	}

	ct_state->proxy_port = proxy_port;

	return 0;
}

static inline int __inline__ ct_create4(void *map, struct ipv4_ct_tuple *tuple,
					struct __sk_buff *skb, int dir,
					struct ct_state *ct_state)
{
	__be32 addr;

	/* Create entry in original direction */
	struct ct_entry entry = {
		.lifetime = CT_DEFAULT_LIFEIME,
	};
	int proxy_port = 0;

	entry.rev_nat_index = ct_state->rev_nat_index;
	entry.lb_loopback = ct_state->loopback;

	if (dir == CT_INGRESS) {
		if (tuple->nexthdr == IPPROTO_UDP ||
		    tuple->nexthdr == IPPROTO_TCP) {
			/* Resolve L4 policy. This may fail due to policy reasons. May
			 * optonally return a proxy port number to redirect all traffic to.
			 */
			proxy_port = l4_ingress_policy(skb, ct_state->orig_dport, tuple->nexthdr);
			if (IS_ERR(proxy_port))
				return proxy_port;

			cilium_trace(skb, DBG_L4_POLICY, proxy_port, CT_INGRESS);
		}

		entry.rx_packets = 1;
		entry.rx_bytes = skb->len;
	} else {
		if (tuple->nexthdr == IPPROTO_UDP ||
		    tuple->nexthdr == IPPROTO_TCP) {
			/* Resolve L4 policy. This may fail due to policy reasons. May
			 * optonally return a proxy port number to redirect all traffic to.
			 */
			proxy_port = l4_egress_policy(skb, ct_state->orig_dport, tuple->nexthdr);
			if (IS_ERR(proxy_port))
				return proxy_port;

			cilium_trace(skb, DBG_L4_POLICY, proxy_port, CT_EGRESS);
		}

		entry.tx_packets = 1;
		entry.tx_bytes = skb->len;
	}

	entry.proxy_port = proxy_port;

#ifdef LXC_NAT46
	if (skb->cb[CB_NAT46_STATE] == NAT64)
		entry.nat46 = dir == CT_EGRESS;
#endif

	cilium_trace(skb, DBG_CT_CREATED, (ntohs(tuple->sport) << 16) | ntohs(tuple->dport),
		     (tuple->nexthdr << 8) | tuple->flags);
#ifdef CONNTRACK_LOCAL
	addr = tuple->addr;
#else
	addr = (dir == CT_INGRESS) ? tuple->saddr : tuple->daddr;
#endif
	cilium_trace(skb, DBG_CT_CREATED2, addr, ct_state->rev_nat_index);
	if (map_update_elem(map, tuple, &entry, 0) < 0)
		return DROP_CT_CREATE_FAILED;

	if (ct_state->addr) {
#ifdef CONNTRACK_LOCAL
		addr = tuple->addr;
		tuple->addr = ct_state->addr;
#else
		if (dir == CT_INGRESS) {
			addr = tuple->saddr;
			tuple->saddr = ct_state->addr;
		} else {
			addr = tuple->daddr;
			tuple->daddr = ct_state->addr;
		}
#endif

		__u8 flags = tuple->flags;

		/* We are looping back into the origin endpoint through a service,
		 * set up a conntrack tuple for the reply to ensure we do rev NAT
		 * before attempting to route the destination address which will
		 * not point back to the right source. */
		if (ct_state->loopback)
			tuple->flags = TUPLE_F_IN;

		cilium_trace(skb, DBG_CT_CREATED, (ntohs(tuple->sport) << 16) | ntohs(tuple->dport),
			     (tuple->nexthdr << 8) | tuple->flags);
#ifdef CONNTRACK_LOCAL
	addr = tuple->addr;
#else
	addr = (dir == CT_INGRESS) ? tuple->saddr : tuple->daddr;
#endif
		cilium_trace(skb, DBG_CT_CREATED2, addr, ct_state->rev_nat_index);
		if (map_update_elem(map, tuple, &entry, 0) < 0)
			return DROP_CT_CREATE_FAILED;
#ifdef CONNTRACK_LOCAL
		tuple->addr = addr;
#else
		(dir == CT_INGRESS) ? (tuple->saddr = addr) : (tuple->daddr = addr);
#endif
		tuple->flags = flags;
	}

	/* Create an ICMPv6 entry to relate errors */
	/* FIXME: We could do a lookup and check if an L3 entry already exists */
	tuple->nexthdr = IPPROTO_ICMP;
	tuple->sport = 0;
	tuple->dport = 0;
	tuple->flags |= TUPLE_F_RELATED;
	entry.proxy_port = 0;

	cilium_trace(skb, DBG_CT_CREATED, 0, (tuple->nexthdr << 8) | tuple->flags);
	if (map_update_elem(map, tuple, &entry, 0) < 0)
		return DROP_CT_CREATE_FAILED;

	ct_state->proxy_port = proxy_port;

	return 0;
}

#else /* !CONNTRACK */
static inline int __inline__ __ct_lookup(void *map, struct __sk_buff *skb, void *tuple,
					 int action, int dir, struct ct_state *ct_state)
{
	return 0;
}

static inline int __inline__ ct_lookup6(void *map, struct ipv6_ct_tuple *tuple,
					struct __sk_buff *skb, int off, __u32 secctx, int dir,
					struct ct_state *ct_state)
{
	return 0;
}

static inline int __inline__ ct_lookup4(void *map, struct ipv4_ct_tuple *tuple,
					struct __sk_buff *skb, int off, __u32 secctx, int dir,
					struct ct_state *ct_state)
{
	return 0;
}

static inline int __inline__ ct_create6(void *map, struct ipv6_ct_tuple *tuple,
					struct __sk_buff *skb, int dir,
					struct ct_state *ct_state)
{
	return 0;
}

static inline int __inline__ ct_create4(void *map, struct ipv4_ct_tuple *tuple,
					struct __sk_buff *skb, int dir,
					struct ct_state *ct_state)
{
	return 0;
}
#endif

#endif
