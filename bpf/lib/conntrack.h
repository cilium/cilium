/*
 *  Copyright (C) 2016-2018 Authors of Cilium
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
#include "nat46.h"

#define CT_DEFAULT_LIFETIME_TCP		21600	/* 6 hours */
#define CT_DEFAULT_LIFETIME_NONTCP	60	/* 60 seconds */
#define CT_DEFAULT_SYN_TIMEOUT		60	/* 60 seconds */
#define CT_DEFAULT_CLOSE_TIMEOUT	10	/* 10 seconds */
#define CT_DEFAULT_REPORT_INTERVAL	5	/* 5 seconds */

#ifndef CT_LIFETIME_TCP
#define CT_LIFETIME_TCP CT_DEFAULT_LIFETIME_TCP
#endif

#ifndef CT_LIFETIME_NONTCP
#define CT_LIFETIME_NONTCP CT_DEFAULT_LIFETIME_NONTCP
#endif

#ifndef CT_SYN_TIMEOUT
#define CT_SYN_TIMEOUT CT_DEFAULT_SYN_TIMEOUT
#endif

#ifndef CT_CLOSE_TIMEOUT
#define CT_CLOSE_TIMEOUT CT_DEFAULT_CLOSE_TIMEOUT
#endif

/* CT_REPORT_INTERVAL, when MONITOR_AGGREGATION is >= TRACE_AGGREGATE_ACTIVE_CT
 * determines how frequently monitor notifications should be sent for active
 * connections. A notification is always triggered on a packet event.
 */
#ifndef CT_REPORT_INTERVAL
#define CT_REPORT_INTERVAL CT_DEFAULT_REPORT_INTERVAL
#endif

#ifdef CONNTRACK

#define TUPLE_F_OUT		0	/* Return flow for an ingress to a container */
#define TUPLE_F_IN		1	/* Return flow for an egress from a container */
#define TUPLE_F_RELATED		2	/* Flow represents related packets */
#define TUPLE_F_SERVICE		4	/* Flow represents service/slave map */

enum {
	ACTION_UNSPEC,
	ACTION_CREATE,
	ACTION_CLOSE,
};

/* conn_is_dns returns true if the connection is DNS, false otherwise.
 *
 * @dport: Connection destination port.
 *
 * To reduce program complexity, we ignore nexthdr and dir here:
 * nexthdr: The parser will not fill dport if nexthdr is not TCP/UDP.
 * dir:     Ideally we would only consider responses, but requests are likely
 *          to be small anyway.
 * */
static inline bool conn_is_dns(__u16 dport)
{
	if (dport == bpf_htons(53)) {
		relax_verifier();
		return true;
	}
	return false;
}

union tcp_flags {
	struct {
		__u8 upper_bits;
		__u8 lower_bits;
		__u16 pad;
	};
	__u32 value;
};

/**
 * Update the CT timeout and TCP flags for the specified entry.
 *
 * We track the OR'd accumulation of seen tcp flags in the entry, and the
 * last time that a notification was sent. Multiple CPUs may enter this
 * function with packets for the same connection, in which case it is possible
 * for the CPUs to race to update the entry. In such a case, the critical
 * update section may be entered in quick succession, leading to multiple
 * updates of the entry and returning true for each CPU. The BPF architecture
 * guarantees that entire 8-bit or 32-bit values will be set within the entry,
 * so although the CPUs may race, the worst result is that multiple executions
 * of this function return non-zero for the same connection within short
 * succession, leading to multiple trace notifications being sent when one
 * might otherwise expect such notifications to be aggregated.
 *
 * Returns how many bytes of the packet should be monitored:
 * - Zero if this flow was recently monitored.
 * - Non-zero if this flow has not been monitored recently.
 */
static inline __u32 __inline__ __ct_update_timeout(struct ct_entry *entry,
						   __u32 lifetime, int dir,
						   union tcp_flags flags)
{
	__u32 now = bpf_ktime_get_sec();
	__u8 *accumulated_flags;
	__u8 seen_flags = flags.lower_bits;
	__u32 *last_report;

#ifdef NEEDS_TIMEOUT
	entry->lifetime = now + lifetime;
#endif
	if (dir == CT_INGRESS) {
		accumulated_flags = &entry->rx_flags_seen;
		last_report = &entry->last_rx_report;
	} else {
		accumulated_flags = &entry->tx_flags_seen;
		last_report = &entry->last_tx_report;
	}
	seen_flags |= *accumulated_flags;

	/* It's possible for multiple CPUs to execute the branch statement here
	 * one after another, before the first CPU is able to execute the entry
	 * modifications within this branch. This is somewhat unlikely because
	 * packets for the same connection are typically steered towards the
	 * same CPU, but is possible in theory.
	 *
	 * If the branch is taken by multiple CPUs because of '*last_report',
	 * then this merely causes multiple notifications to be sent after
	 * CT_REPORT_INTERVAL rather than a single notification. '*last_report'
	 * will be updated by all CPUs and subsequent checks should not take
	 * this branch until the next CT_REPORT_INTERVAL. As such, the trace
	 * aggregation that uses the result of this function may reduce the
	 * number of packets per interval to a small integer value (max N_CPUS)
	 * rather than 1 notification per packet throughout the interval.
	 *
	 * Similar behaviour may happen with tcp_flags. The worst case race
	 * here would be that two or more CPUs argue over which flags have been
	 * seen and overwrite each other, with each CPU interleaving different
	 * values for which flags were seen. In practice, realistic connections
	 * are likely to progressively set SYN, ACK, then much later perhaps
	 * FIN and/or RST. Furthermore, unless such a traffic pattern were
	 * constantly received, this should self-correct as the stored
	 * tcp_flags is an OR'd set of flags and each time the above code is
	 * executed, it pulls the latest set of accumulated flags. Therefore
	 * even in the worst case such a conflict is likely only to cause a
	 * small number of additional notifications, which is still likely to
	 * be significantly less under this MONITOR_AGGREGATION mode than would
	 * otherwise be sent if the MONITOR_AGGREGATION level is set to none
	 * (ie, sending a notification for every packet).
	 */
	if (*last_report + CT_REPORT_INTERVAL < now ||
	    *accumulated_flags != seen_flags) {
		*last_report = now;
		*accumulated_flags = seen_flags;
		return TRACE_PAYLOAD_LEN;
	}
	return 0;
}

/**
 * Update the CT timeouts for the specified entry.
 *
 * If CT_REPORT_INTERVAL has elapsed since the last update, updates the
 * last_updated timestamp and returns true. Otherwise returns false.
 */
static inline __u32 __inline__ ct_update_timeout(struct ct_entry *entry,
						 bool tcp, int dir,
						 union tcp_flags seen_flags)
{
	__u32 lifetime = CT_LIFETIME_NONTCP;
	bool syn = seen_flags.value & TCP_FLAG_SYN;

	if (tcp) {
		entry->seen_non_syn |= !syn;

		if (entry->seen_non_syn)
			lifetime = CT_LIFETIME_TCP;
		else
			lifetime = CT_SYN_TIMEOUT;
	}

	return __ct_update_timeout(entry, lifetime, dir, seen_flags);
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
					 struct ct_state *ct_state,
					 bool is_tcp, union tcp_flags seen_flags,
					 __u32 *monitor)
{
	struct ct_entry *entry;
	int reopen;

	if ((entry = map_lookup_elem(map, tuple))) {
		cilium_dbg(skb, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
		if (ct_entry_alive(entry)) {
			*monitor = ct_update_timeout(entry, is_tcp, dir, seen_flags);
		}
		if (ct_state) {
			ct_state->rev_nat_index = entry->rev_nat_index;
			ct_state->loopback = entry->lb_loopback;
			ct_state->slave = entry->slave;
		}

#ifdef ENABLE_NAT46
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
			reopen = entry->rx_closing | entry->tx_closing;
			reopen |= seen_flags.value & TCP_FLAG_SYN;
			if (unlikely(reopen == (TCP_FLAG_SYN|0x1))) {
				ct_reset_closing(entry);
				*monitor = ct_update_timeout(entry, is_tcp, dir, seen_flags);
			}
			break;
		case ACTION_CLOSE:
			/* RST or similar, immediately delete ct entry */
			if (dir == CT_INGRESS)
				entry->rx_closing = 1;
			else
				entry->tx_closing = 1;

			*monitor = TRACE_PAYLOAD_LEN;
			if (ct_entry_alive(entry))
				break;
			__ct_update_timeout(entry, CT_CLOSE_TIMEOUT, dir, seen_flags);
			break;
		}

		return CT_ESTABLISHED;
	}

	*monitor = TRACE_PAYLOAD_LEN;
	return CT_NEW;
}

static inline void __inline__ ipv6_ct_tuple_reverse(struct ipv6_ct_tuple *tuple)
{
	union v6addr tmp_addr = {};
	__be16 tmp;

	ipv6_addr_copy(&tmp_addr, &tuple->saddr);
	ipv6_addr_copy(&tuple->saddr, &tuple->daddr);
	ipv6_addr_copy(&tuple->daddr, &tmp_addr);

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
					struct __sk_buff *skb, int l4_off, int dir,
					struct ct_state *ct_state, __u32 *monitor)
{
	int ret = CT_NEW, action = ACTION_UNSPEC;
	bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
	union tcp_flags tcp_flags = { .value = 0 };

	/* The tuple is created in reverse order initially to find a
	 * potential reverse flow. This is required because the RELATED
	 * or REPLY state takes precedence over ESTABLISHED due to
	 * policy requirements.
	 *
	 * tuple->flags separates entries that could otherwise be overlapping.
	 */
	if (dir == CT_INGRESS)
		tuple->flags = TUPLE_F_OUT;
	else if (dir == CT_EGRESS)
		tuple->flags = TUPLE_F_IN;
	else if (dir == CT_SERVICE)
		tuple->flags = TUPLE_F_SERVICE;
	else
		return DROP_CT_INVALID_HDR;

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
			if (skb_load_bytes(skb, l4_off + 12, &tcp_flags, 2) < 0)
				return DROP_CT_INVALID_HDR;

			if (unlikely(tcp_flags.value & (TCP_FLAG_RST|TCP_FLAG_FIN)))
				action = ACTION_CLOSE;
			else
				action = ACTION_CREATE;
		}

		/* load sport + dport into tuple */
		if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
			return DROP_CT_INVALID_HDR;
		break;

	case IPPROTO_UDP:
		/* load sport + dport into tuple */
		if (skb_load_bytes(skb, l4_off, &tuple->dport, 4) < 0)
			return DROP_CT_INVALID_HDR;

		action = ACTION_CREATE;
		break;

	default:
		/* Can't handle extension headers yet */
		relax_verifier();
		return DROP_CT_UNKNOWN_PROTO;
	}

	/* Lookup the reverse direction
	 *
	 * This will find an existing flow in the reverse direction.
	 * The reverse direction is the one where reverse nat index is stored.
	 */
	cilium_dbg3(skb, DBG_CT_LOOKUP6_1, (__u32) tuple->saddr.p4, (__u32) tuple->daddr.p4,
		      (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
	cilium_dbg3(skb, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
	ret = __ct_lookup(map, skb, tuple, action, dir, ct_state, is_tcp,
			  tcp_flags, monitor);
	if (ret != CT_NEW) {
		if (likely(ret == CT_ESTABLISHED)) {
			if (unlikely(tuple->flags & TUPLE_F_RELATED))
				ret = CT_RELATED;
			else
				ret = CT_REPLY;
		}
		goto out;
	}

	/* Lookup entry in forward direction */
	if (dir != CT_SERVICE) {
		ipv6_ct_tuple_reverse(tuple);
		ret = __ct_lookup(map, skb, tuple, action, dir, ct_state,
				  is_tcp, tcp_flags, monitor);
	}

#ifdef ENABLE_NAT46
	skb->cb[CB_NAT46_STATE] = NAT46_CLEAR;
#endif
out:
	cilium_dbg(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret, ct_state->rev_nat_index);
	if (conn_is_dns(tuple->dport))
		*monitor = MTU;
	return ret;
}

static inline void __inline__ ipv4_ct_tuple_reverse(struct ipv4_ct_tuple *tuple)
{
	__be32 tmp_addr = tuple->saddr;
	__be16 tmp;

	tuple->saddr = tuple->daddr;
	tuple->daddr = tmp_addr;

	tmp = tuple->sport;
	tuple->sport = tuple->dport;
	tuple->dport = tmp;

	/* Flip ingress/egress flag */
	if (tuple->flags & TUPLE_F_IN)
		tuple->flags &= ~TUPLE_F_IN;
	else
		tuple->flags |= TUPLE_F_IN;
}

static inline void ct4_cilium_dbg_tuple(struct __sk_buff *skb, __u8 type,
					  const struct ipv4_ct_tuple *tuple,
					  __u32 rev_nat_index, int dir)
{
	__be32 addr = (dir == CT_INGRESS) ? tuple->saddr : tuple->daddr;
	cilium_dbg(skb, type, addr, rev_nat_index);
}

/* Offset must point to IPv4 header */
static inline int __inline__ ct_lookup4(void *map, struct ipv4_ct_tuple *tuple,
					struct __sk_buff *skb, int off, int dir,
					struct ct_state *ct_state, __u32 *monitor)
{
	int ret = CT_NEW, action = ACTION_UNSPEC;
	bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
	union tcp_flags tcp_flags = { .value = 0 };

	/* The tuple is created in reverse order initially to find a
	 * potential reverse flow. This is required because the RELATED
	 * or REPLY state takes precedence over ESTABLISHED due to
	 * policy requirements.
	 *
	 * tuple->flags separates entries that could otherwise be overlapping.
	 */
	if (dir == CT_INGRESS)
		tuple->flags = TUPLE_F_OUT;
	else if (dir == CT_EGRESS)
		tuple->flags = TUPLE_F_IN;
	else if (dir == CT_SERVICE)
		tuple->flags = TUPLE_F_SERVICE;
	else
		return DROP_CT_INVALID_HDR;

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
			if (skb_load_bytes(skb, off + 12, &tcp_flags, 2) < 0)
				return DROP_CT_INVALID_HDR;

			if (unlikely(tcp_flags.value & (TCP_FLAG_RST|TCP_FLAG_FIN)))
				action = ACTION_CLOSE;
			else
				action = ACTION_CREATE;
		}

		/* load sport + dport into tuple */
		if (skb_load_bytes(skb, off, &tuple->dport, 4) < 0)
			return DROP_CT_INVALID_HDR;
		break;

	case IPPROTO_UDP:
		/* load sport + dport into tuple */
		if (skb_load_bytes(skb, off, &tuple->dport, 4) < 0)
			return DROP_CT_INVALID_HDR;

		action = ACTION_CREATE;
		break;

	default:
		/* Can't handle extension headers yet */
		relax_verifier();
		return DROP_CT_UNKNOWN_PROTO;
	}

	/* Lookup the reverse direction
	 *
	 * This will find an existing flow in the reverse direction.
	 */
#ifndef QUIET_CT
	cilium_dbg3(skb, DBG_CT_LOOKUP4_1, tuple->saddr, tuple->daddr,
		      (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
	cilium_dbg3(skb, DBG_CT_LOOKUP4_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
#endif
	ret = __ct_lookup(map, skb, tuple, action, dir, ct_state, is_tcp,
			  tcp_flags, monitor);
	if (ret != CT_NEW) {
		if (likely(ret == CT_ESTABLISHED)) {
			if (unlikely(tuple->flags & TUPLE_F_RELATED))
				ret = CT_RELATED;
			else
				ret = CT_REPLY;
		}
		goto out;
	}

	/* Lookup entry in forward direction */
	if (dir != CT_SERVICE) {
		ipv4_ct_tuple_reverse(tuple);
		ret = __ct_lookup(map, skb, tuple, action, dir, ct_state,
				  is_tcp, tcp_flags, monitor);
	}
out:
	cilium_dbg(skb, DBG_CT_VERDICT, ret < 0 ? -ret : ret, ct_state->rev_nat_index);
	if (conn_is_dns(tuple->dport))
		*monitor = MTU;
	return ret;
}

static inline void __inline__ ct_delete6(void *map, struct ipv6_ct_tuple *tuple, struct __sk_buff *skb)
{
	int err;

	if ((err = map_delete_elem(map, tuple)) < 0)
		cilium_dbg(skb, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);
}

static inline void __inline__ ct_update6_slave(void *map,
					       struct ipv6_ct_tuple *tuple,
					       struct ct_state *state)
{
	struct ct_entry *entry;

	entry = map_lookup_elem(map, tuple);
	if (!entry)
		return;

	entry->slave = state->slave;
	return;
}


/* Offset must point to IPv6 */
static inline int __inline__ ct_create6(void *map, struct ipv6_ct_tuple *tuple,
					struct __sk_buff *skb, int dir,
					struct ct_state *ct_state)
{
	/* Create entry in original direction */
	struct ct_entry entry = { };
	bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
	union tcp_flags seen_flags = { .value = 0 };

	entry.rev_nat_index = ct_state->rev_nat_index;
	entry.lb_loopback = ct_state->loopback;
	entry.slave = ct_state->slave;
	seen_flags.value |= is_tcp ? TCP_FLAG_SYN : 0;
	ct_update_timeout(&entry, is_tcp, dir, seen_flags);

	if (dir == CT_INGRESS) {
		entry.rx_packets = 1;
		entry.rx_bytes = skb->len;
	} else {
		entry.tx_packets = 1;
		entry.tx_bytes = skb->len;
	}

	cilium_dbg3(skb, DBG_CT_CREATED6, entry.rev_nat_index, ct_state->src_sec_id, 0);

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

	entry.seen_non_syn = true; /* For ICMP, there is no SYN. */

	ipv6_addr_copy(&icmp_tuple.daddr, &tuple->daddr);
	ipv6_addr_copy(&icmp_tuple.saddr, &tuple->saddr);

	/* FIXME: We could do a lookup and check if an L3 entry already exists */
	if (map_update_elem(map, &icmp_tuple, &entry, 0) < 0) {
		/* Previous map update succeeded, we could delete it
		 * but we might as well just let it time out.
		 */
		return DROP_CT_CREATE_FAILED;
	}

	return 0;
}

static inline void __inline__ ct_delete4(void *map, struct ipv4_ct_tuple *tuple, struct __sk_buff *skb)
{
	int err;

	if ((err = map_delete_elem(map, tuple)) < 0)
		cilium_dbg(skb, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);
}

static inline void __inline__ ct_update4_slave(void *map,
					       struct ipv4_ct_tuple *tuple,
					       struct ct_state *state)
{
	struct ct_entry *entry;

	entry = map_lookup_elem(map, tuple);
	if (!entry)
		return;

	entry->slave = state->slave;
	return;
}

static inline int __inline__ ct_create4(void *map, struct ipv4_ct_tuple *tuple,
					struct __sk_buff *skb, int dir,
					struct ct_state *ct_state)
{
	/* Create entry in original direction */
	struct ct_entry entry = { };
	bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
	union tcp_flags seen_flags = { .value = 0 };

	entry.rev_nat_index = ct_state->rev_nat_index;
	entry.lb_loopback = ct_state->loopback;
	entry.slave = ct_state->slave;
	seen_flags.value |= is_tcp ? TCP_FLAG_SYN : 0;
	ct_update_timeout(&entry, is_tcp, dir, seen_flags);

	if (dir == CT_INGRESS) {
		entry.rx_packets = 1;
		entry.rx_bytes = skb->len;
	} else {
		entry.tx_packets = 1;
		entry.tx_bytes = skb->len;
	}

#ifdef ENABLE_NAT46
	if (skb->cb[CB_NAT46_STATE] == NAT64)
		entry.nat46 = dir == CT_EGRESS;
#endif

	cilium_dbg3(skb, DBG_CT_CREATED4, entry.rev_nat_index, ct_state->src_sec_id, ct_state->addr);

	entry.src_sec_id = ct_state->src_sec_id;
	if (map_update_elem(map, tuple, &entry, 0) < 0)
		return DROP_CT_CREATE_FAILED;

	if (ct_state->addr) {
		__u8 flags = tuple->flags;
		__be32 saddr, daddr;

		saddr = tuple->saddr;
		daddr = tuple->daddr;
		if (dir == CT_INGRESS)
			tuple->saddr = ct_state->addr;
		else
			tuple->daddr = ct_state->addr;

		/* We are looping back into the origin endpoint through a service,
		 * set up a conntrack tuple for the reply to ensure we do rev NAT
		 * before attempting to route the destination address which will
		 * not point back to the right source. */
		if (ct_state->loopback) {
			tuple->flags = TUPLE_F_IN;
			if (dir == CT_INGRESS)
				tuple->daddr = ct_state->svc_addr;
			else
				tuple->saddr = ct_state->svc_addr;
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

	entry.seen_non_syn = true; /* For ICMP, there is no SYN. */

	/* FIXME: We could do a lookup and check if an L3 entry already exists */
	if (map_update_elem(map, &icmp_tuple, &entry, 0) < 0)
		return DROP_CT_CREATE_FAILED;

	return 0;
}

#else /* !CONNTRACK */
static inline int __inline__ ct_lookup6(void *map, struct ipv6_ct_tuple *tuple,
					struct __sk_buff *skb, int off, int dir,
					struct ct_state *ct_state, __u32 *monitor)
{
	return 0;
}

static inline int __inline__ ct_lookup4(void *map, struct ipv4_ct_tuple *tuple,
					struct __sk_buff *skb, int off, int dir,
					struct ct_state *ct_state, __u32 *monitor)
{
	return 0;
}

static inline void __inline__ ct_delete6(void *map, struct ipv6_ct_tuple *tuple, struct __sk_buff *skb)
{
}

static inline void __inline__ ct_update6_slave(void *map,
					      struct ipv6_ct_tuple *tuple,
					      struct ct_state *state)
{
}

static inline int __inline__ ct_create6(void *map, struct ipv6_ct_tuple *tuple,
					struct __sk_buff *skb, int dir,
					struct ct_state *ct_state)
{
	return 0;
}

static inline void __inline__ ct_delete4(void *map, struct ipv4_ct_tuple *tuple, struct __sk_buff *skb)
{
}

static inline void __inline__ ct_update4_slave(void *map,
					       struct ipv4_ct_tuple *tuple,
					       struct ct_state *state)
{
}

static inline int __inline__ ct_create4(void *map, struct ipv4_ct_tuple *tuple,
					struct __sk_buff *skb, int dir,
					struct ct_state *ct_state)
{
	return 0;
}

#endif

#endif
