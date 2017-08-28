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
#include "utils.h"
#include "ipv6.h"
#include "dbg.h"
#include "l4.h"

#define CT_DEFAULT_LIFEIME	360
#define CT_CLOSE_TIMEOUT	10

struct bpf_elf_map __section_maps CT_MAP6 = {
#ifdef HAVE_LRU_MAP_TYPE
	.type		= BPF_MAP_TYPE_LRU_HASH,
#else
	.type		= BPF_MAP_TYPE_HASH,
#endif
	.size_key	= sizeof(struct ipv6_ct_tuple),
	.size_value	= sizeof(struct ct_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CT_MAP_SIZE,
};

struct bpf_elf_map __section_maps CT_MAP4 = {
#ifdef HAVE_LRU_MAP_TYPE
	.type		= BPF_MAP_TYPE_LRU_HASH,
#else
	.type		= BPF_MAP_TYPE_HASH,
#endif
	.size_key	= sizeof(struct ipv4_ct_tuple),
	.size_value	= sizeof(struct ct_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CT_MAP_SIZE,
};


enum {
	CT_NEW,
	CT_ESTABLISHED,
	CT_REPLY,
	CT_RELATED,
};

#define TUPLE_F_OUT		0	/* Outgoing flow */
#define TUPLE_F_IN		1	/* Incoming flow */
#define TUPLE_F_RELATED		2	/* Flow represents related packets */

/**
 * direction2flags translates a direction (CT_INGRESS/CT_EGRESS) into tuple flags
 */
static inline int __inline__ direction2flags(int direction)
{
	return (direction == CT_INGRESS) ? TUPLE_F_IN : TUPLE_F_OUT;
}


/**
 * ct_extract_tuple4 extracts a layer 3 IPv4 tuple representing the flow
 * @tuple Tuple structure to fill
 * @ip4 Pointer to IPv4 header
 * @l3_off Offset to layer 3 header
 * @direction Direction the traffic is flowing (CT_INGRESS / CT_EGRESS)
 *
 * Returns the offset to the layer 4 header
 */
static inline int __inline__ ct_extract_tuple4(struct ipv4_ct_tuple *tuple,
					       struct iphdr *ip4, int l3_off,
					       int direction)
{
	tuple->nexthdr = ip4->protocol;
	tuple->saddr = ip4->saddr;
	tuple->daddr = ip4->daddr;
	tuple->flags = direction2flags(direction);

	return l3_off + ipv4_hdrlen(ip4);
}

/**
 * ct_extract_tuple6 extracts a layer 3 IPv6 tuple representing the flow
 * @skb Pointer to skb
 * @tuple Tuple structure to fill
 * @ip6 Pointer to IPv6 header
 * @l3_off Offset to layer 3 header
 * @direction Direction the traffic is flowing (CT_INGRESS / CT_EGRESS)
 *
 * Returns the offset to the layer 4 header
 */
static inline int __inline__ ct_extract_tuple6(struct __sk_buff *skb,
					       struct ipv6_ct_tuple *tuple,
					       struct ipv6hdr *ip6, int l3_off,
					       int direction)
{
	ipv6_addr_copy(&tuple->saddr, (union v6addr *) &ip6->saddr);
	ipv6_addr_copy(&tuple->daddr, (union v6addr *) &ip6->daddr);
	tuple->flags = direction2flags(direction);
	tuple->nexthdr = ip6->nexthdr;

	return l3_off + ipv6_hdrlen(skb, l3_off, &tuple->nexthdr);
}

#ifdef CONNTRACK

enum {
	ACTION_UNSPEC,
	ACTION_CREATE,
	ACTION_CLOSE,
	ACTION_DELETE,
};

static inline void __inline__ __ct_update_timeout(struct ct_entry *entry,
						  __u32 lifetime)
{
#ifdef NEEDS_TIMEOUT
	entry->lifetime = bpf_ktime_get_sec() + lifetime;
#endif
}

static inline void __inline__ ct_update_timeout(struct ct_entry *entry)
{
	__ct_update_timeout(entry, CT_DEFAULT_LIFEIME);
}

static inline void __inline__ ct_reset_closing(struct ct_entry *entry)
{
	entry->rx_closing = 0;
	entry->tx_closing = 0;
}

static inline bool __inline__ ct_entry_alive(const struct ct_entry *entry)
{
	return !entry->rx_closing || !entry->tx_closing;
}

static inline int __inline__ __ct_lookup(void *map, struct __sk_buff *skb,
					 void *tuple, int action, int dir,
					 struct ct_state *ct_state)
{
	struct ct_entry *entry;
	int ret;

	if ((entry = map_lookup_elem(map, tuple))) {
#ifndef QUIET_CT
		cilium_trace(skb, DBG_CT_MATCH, entry->lifetime,
			entry->proxy_port << 16 | entry->rev_nat_index);
#endif
		if (ct_entry_alive(entry))
			ct_update_timeout(entry);
		if (ct_state) {
			ct_state->rev_nat_index = entry->rev_nat_index;
			ct_state->loopback = entry->lb_loopback;
			ct_state->proxy_port = entry->proxy_port;
			ct_state->snat = entry->snat;
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
		case ACTION_CREATE:
			ret = entry->rx_closing + entry->tx_closing;
			if (unlikely(ret >= 1)) {
				ct_reset_closing(entry);
				ct_update_timeout(entry);
			}
			break;
		case ACTION_CLOSE:
			/* RST or similar, immediately delete ct entry */
			if (dir == CT_INGRESS)
				entry->rx_closing = 1;
			else
				entry->tx_closing = 1;

			if (ct_entry_alive(entry))
				break;
			__ct_update_timeout(entry, CT_CLOSE_TIMEOUT);
			break;
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

static inline int __inline__ reverse_tuple_flags(int flags)
{
	if (flags & TUPLE_F_IN)
		flags &= ~TUPLE_F_IN;
	else
		flags |= TUPLE_F_IN;

	return flags;
}

static inline void __inline__ reverse_ipv6_ct_tuple(struct ipv6_ct_tuple *tuple, struct ipv6_ct_tuple *reverse)
{
	ipv6_addr_copy(&reverse->saddr, &tuple->daddr);
	ipv6_addr_copy(&reverse->daddr, &tuple->saddr);
	reverse->sport = tuple->dport;
	reverse->dport = tuple->sport;
	reverse->nexthdr = tuple->nexthdr;
	reverse->flags = reverse_tuple_flags(tuple->flags);
}

/**
 * ct_lookup6 - Lookup IPv6 5-tuple in connection tracking table
 * @map      Pointer to IPv6 conntrack table map (global or local)
 * @tuple    3-tuple (layer 3) extracted by ct_extract_tuple6()
 * @skb      Packet pointer
 * @off      Offset to L4 header
 * @dir      Direction of packet flow (CT_INGRESS/CT_EGRESS)
 * @cs_state Result structure to store connection tracking state found
 *
 * Completes the tuple with Layer 4 information and perform a connection
 * tracking lookup.
 *
 * Returns:
 *  - CT_REPLY: The packet is a reply packet to a known connection
 *  - CT_RELATED: The packet is a reply packet related to a known connection
 *                (ICMP errors)
 *  - CT_NEW: The packet could not be associated with any connection, a new
 *            connection tracking entry has been created.
 *
 * The ct_state argument is filled with the state of the connection found. It
 * is only valid if no error has been returned.
 */
static inline int __inline__ ct_lookup6(void *map, struct ipv6_ct_tuple *tuple,
					struct __sk_buff *skb, int l4_off, int dir,
					struct ct_state *ct_state)
{
	int ret = CT_NEW, action = ACTION_UNSPEC;
	struct ipv6_ct_tuple rev_tuple = {};

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
				tuple->sport = ICMPV6_ECHO_REQUEST;
				break;

			case ICMPV6_ECHO_REQUEST:
				tuple->dport = type;
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

		/* load sport + dport into tuple */
		if (skb_load_bytes(skb, l4_off, &tuple->sport, 4) < 0)
			return DROP_CT_INVALID_HDR;
		break;

	case IPPROTO_UDP:
		/* load sport + dport into tuple */
		if (skb_load_bytes(skb, l4_off, &tuple->sport, 4) < 0)
			return DROP_CT_INVALID_HDR;

		action = ACTION_CREATE;
		break;

	default:
		/* Can't handle extension headers yet */
		return DROP_CT_UNKNOWN_PROTO;
	}

	reverse_ipv6_ct_tuple(tuple, &rev_tuple);

	/* Lookup the reverse direction
	 *
	 * This will find an existing flow in the reverse direction.
	 * The reverse direction is the one where reverse nat index is stored.
	 */
#ifndef QUIET_CT
	cilium_trace3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
		      (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
	cilium_trace3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
#endif
	if ((ret = __ct_lookup(map, skb, &rev_tuple, action, dir, ct_state)) != CT_NEW) {
		if (likely(ret == CT_ESTABLISHED)) {
			if (unlikely(rev_tuple.flags & TUPLE_F_RELATED))
				ret = CT_RELATED;
			else
				ret = CT_REPLY;
		}
		goto out;
	}

	/* Lookup entry in forward direction */
	ret = __ct_lookup(map, skb, tuple, action, dir, ct_state);

#ifdef LXC_NAT46
	skb->cb[CB_NAT46_STATE] = NAT46_CLEAR;
#endif
	/* No entries found, packet must be eligible for creating a CT entry */
	if (ret == CT_NEW && action != ACTION_CREATE)
		ret = DROP_CT_CANT_CREATE;

out:
#ifndef QUIET_CT
	cilium_trace(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret,
		ct_state->proxy_port << 16 | ct_state->rev_nat_index);
#endif
	return ret;
}

static inline void __inline__ reverse_ipv4_ct_tuple(struct ipv4_ct_tuple *tuple, struct ipv4_ct_tuple *reverse)
{
	reverse->saddr = tuple->daddr;
	reverse->daddr = tuple->saddr;
	reverse->sport = tuple->dport;
	reverse->dport = tuple->sport;
	reverse->nexthdr = tuple->nexthdr;
	reverse->flags = reverse_tuple_flags(tuple->flags);
}

/**
 * ct_lookup4 - Lookup IPv4 5-tuple in connection tracking table
 * @map      Pointer to IPv4 conntrack table map (global or local)
 * @tuple    3-tuple (layer 3) extracted by ct_extract_tuple4()
 * @skb      Packet pointer
 * @off      Offset to L4 header
 * @dir      Direction of packet flow (CT_INGRESS/CT_EGRESS)
 * @cs_state Result structure to store connection tracking state found
 *
 * Completes the tuple with Layer 4 information and perform a connection
 * tracking lookup.
 *
 * Returns:
 *  - CT_REPLY: The packet is a reply packet to a known connection
 *  - CT_RELATED: The packet is a reply packet related to a known connection
 *                (ICMP errors)
 *  - CT_NEW: The packet could not be associated with any connection, a new
 *            connection tracking entry has been created.
 *
 * The ct_state argument is filled with the state of the connection found. It
 * is only valid if no error has been returned.
 */
static inline int __inline__ ct_lookup4(void *map, struct ipv4_ct_tuple *tuple,
					struct __sk_buff *skb, int off, int dir,
					struct ct_state *ct_state)
{
	int ret = CT_NEW, action = ACTION_UNSPEC;
	struct ipv4_ct_tuple rev_tuple = {};

	switch (tuple->nexthdr) {
	case IPPROTO_ICMP:
		if (1) {
			__u8 type;

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
				tuple->sport = ICMP_ECHO;
				break;

			case ICMP_ECHO:
				tuple->dport = type;
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

		/* load sport + dport into tuple */
		if (skb_load_bytes(skb, off, &tuple->sport, 4) < 0)
			return DROP_CT_INVALID_HDR;
		break;

	case IPPROTO_UDP:
		/* load sport + dport into tuple */
		if (skb_load_bytes(skb, off, &tuple->sport, 4) < 0)
			return DROP_CT_INVALID_HDR;

		action = ACTION_CREATE;
		break;

	default:
		/* Can't handle extension headers yet */
		return DROP_CT_UNKNOWN_PROTO;
	}

	reverse_ipv4_ct_tuple(tuple, &rev_tuple);

	/* Lookup the reverse direction
	 *
	 * This will find an existing flow in the reverse direction.
	 */
#ifndef QUIET_CT
	cilium_trace3(skb, DBG_CT_LOOKUP4_1, tuple->saddr, tuple->daddr,
		      (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
	cilium_trace3(skb, DBG_CT_LOOKUP4_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
#endif
	if ((ret = __ct_lookup(map, skb, &rev_tuple, action, dir, ct_state)) != CT_NEW) {
		if (likely(ret == CT_ESTABLISHED)) {
			if (unlikely(rev_tuple.flags & TUPLE_F_RELATED))
				ret = CT_RELATED;
			else
				ret = CT_REPLY;
		}
		goto out;
	}

	/* Lookup entry in forward direction */
	ret = __ct_lookup(map, skb, tuple, action, dir, ct_state);

	/* No entries found, packet must be eligible for creating a CT entry */
	if (ret == CT_NEW && action != ACTION_CREATE)
		ret = DROP_CT_CANT_CREATE;

out:
#ifndef QUIET_CT
	cilium_trace(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret,
		ct_state->proxy_port << 16 | ct_state->rev_nat_index);
#endif
	return ret;
}

/* Offset must point to IPv6 */
static inline int __inline__ ct_create6(void *map, struct ipv6_ct_tuple *tuple,
					struct __sk_buff *skb, int dir,
					struct ct_state *ct_state,
					bool orig_was_proxy)
{
	/* Create entry in original direction */
	struct ct_entry entry = { };
	int proxy_port = 0;

	entry.rev_nat_index = ct_state->rev_nat_index;
	entry.lb_loopback = ct_state->loopback;
	entry.snat = ct_state->snat;
	ct_update_timeout(&entry);

	if (dir == CT_INGRESS) {
		if (tuple->nexthdr == IPPROTO_UDP ||
		    tuple->nexthdr == IPPROTO_TCP) {
			/* Resolve L4 policy. This may fail due to policy reasons. May
			 * optonally return a proxy port number to redirect all traffic to.
			 */
			if (orig_was_proxy) {
				proxy_port = 0;
			} else {
				proxy_port = l4_ingress_policy(skb, ct_state->orig_dport, tuple->nexthdr);
				if (IS_ERR(proxy_port))
					return proxy_port;
			}

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

	cilium_trace3(skb, DBG_CT_CREATED6, entry.proxy_port << 16 | entry.rev_nat_index,
		      ct_state->src_sec_id, 0);

	entry.src_sec_id = ct_state->src_sec_id;
	if (map_update_elem(map, tuple, &entry, 0) < 0)
		return DROP_CT_CREATE_FAILED;

	/* Create an ICMPv6 entry to relate errors */
	struct ipv6_ct_tuple icmp_tuple = {
		.nexthdr = IPPROTO_ICMPV6,
		.sport = 0,
		.dport = 0,
		.flags = tuple->flags | TUPLE_F_RELATED,
	};

	entry.proxy_port = 0;

	ipv6_addr_copy(&icmp_tuple.daddr, &tuple->daddr);
	ipv6_addr_copy(&icmp_tuple.saddr, &tuple->saddr);

	/* FIXME: We could do a lookup and check if an L3 entry already exists */
	if (map_update_elem(map, &icmp_tuple, &entry, 0) < 0) {
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
					struct ct_state *ct_state,
					bool orig_was_proxy)
{
	/* Create entry in original direction */
	struct ct_entry entry = { };
	int proxy_port = 0;

	entry.rev_nat_index = ct_state->rev_nat_index;
	entry.lb_loopback = ct_state->loopback;
	entry.snat = ct_state->snat;
	ct_update_timeout(&entry);

	if (dir == CT_INGRESS) {
		if (tuple->nexthdr == IPPROTO_UDP ||
		    tuple->nexthdr == IPPROTO_TCP) {
			/* Resolve L4 policy. This may fail due to policy reasons. May
			 * optonally return a proxy port number to redirect all traffic to.
			 *
			 * However when the sender _is_ the proxy we need to ensure that
			 * we short circuit the redirect to proxy port logic. This happens
			 * when using ingress policies because we are doing the
			 * l4_ingress_policy() lookup in the context of the server.
			 */
			if (orig_was_proxy) {
				proxy_port = 0;
			} else {
				proxy_port = l4_ingress_policy(skb, ct_state->orig_dport, tuple->nexthdr);
				if (IS_ERR(proxy_port))
					return proxy_port;
			}

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

	cilium_trace3(skb, DBG_CT_CREATED4, entry.proxy_port << 16 | entry.rev_nat_index,
		      ct_state->src_sec_id, ct_state->addr);

	entry.src_sec_id = ct_state->src_sec_id;
	if (map_update_elem(map, tuple, &entry, 0) < 0)
		return DROP_CT_CREATE_FAILED;

	if (ct_state->addr) {
		__u8 flags = tuple->flags;
		__be32 saddr, daddr;

		saddr = tuple->saddr;
		daddr = tuple->daddr;
		if (dir == CT_INGRESS)
			tuple->daddr = ct_state->addr;
		else
			tuple->saddr = ct_state->addr;

		/* We are looping back into the origin endpoint through a service,
		 * set up a conntrack tuple for the reply to ensure we do rev NAT
		 * before attempting to route the destination address which will
		 * not point back to the right source. */
		if (ct_state->loopback) {
			tuple->flags = TUPLE_F_IN;
			if (dir == CT_INGRESS)
				tuple->saddr = ct_state->svc_addr;
			else
				tuple->daddr = ct_state->svc_addr;
		}

		if (map_update_elem(map, tuple, &entry, 0) < 0)
			return DROP_CT_CREATE_FAILED;
		tuple->saddr = saddr;
		tuple->daddr = daddr;
		tuple->flags = flags;
	}

	/* Create an ICMP entry to relate errors */
	struct ipv4_ct_tuple icmp_tuple = {
		.daddr = tuple->daddr,
		.saddr = tuple->saddr,
		.nexthdr = IPPROTO_ICMP,
		.sport = 0,
		.dport = 0,
		.flags = tuple->flags | TUPLE_F_RELATED,
	};

	entry.proxy_port = 0;

	/* FIXME: We could do a lookup and check if an L3 entry already exists */
	if (map_update_elem(map, &icmp_tuple, &entry, 0) < 0)
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
					struct __sk_buff *skb, int l4_off, int dir,
					struct ct_state *ct_state)
{
	return 0;
}

static inline int __inline__ ct_lookup4(void *map, struct ipv4_ct_tuple *tuple,
					struct __sk_buff *skb, int off, int dir,
					struct ct_state *ct_state)
{
	return 0;
}

static inline int __inline__ ct_create6(void *map, struct ipv6_ct_tuple *tuple,
					struct __sk_buff *skb, int dir,
					struct ct_state *ct_state,
					bool orig_was_proxy)
{
	return 0;
}

static inline int __inline__ ct_create4(void *map, struct ipv4_ct_tuple *tuple,
					struct __sk_buff *skb, int dir,
					struct ct_state *ct_state,
					bool orig_was_proxy)
{
	return 0;
}
#endif

#endif
