/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_CONNTRACK_H_
#define __LIB_CONNTRACK_H_

#include <linux/icmpv6.h>
#include <linux/icmp.h>

#include <bpf/verifier.h>

#include "common.h"
#include "utils.h"
#include "ipv4.h"
#include "ipv6.h"
#include "dbg.h"
#include "l4.h"
#include "signal.h"

enum {
	ACTION_UNSPEC,
	ACTION_CREATE,
	ACTION_CLOSE,
};

#ifdef ENABLE_IPV4
struct ct_buffer4 {
	struct ipv4_ct_tuple tuple;
	struct ct_state ct_state;
	__u32 monitor;
	int ret;
};
#endif

#ifdef ENABLE_IPV6
struct ct_buffer6 {
	struct ipv6_ct_tuple tuple;
	struct ct_state ct_state;
	__u32 monitor;
	int ret;
};
#endif

static __always_inline bool ct_entry_seen_both_syns(const struct ct_entry *entry)
{
	bool rx_syn = entry->rx_flags_seen & TCP_FLAG_SYN;
	bool tx_syn = entry->tx_flags_seen & TCP_FLAG_SYN;

	return rx_syn && tx_syn;
}

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
static __always_inline __u32 __ct_update_timeout(struct ct_entry *entry,
						 __u32 lifetime, enum ct_dir dir,
						 union tcp_flags flags,
						 __u8 report_mask)
{
	__u32 now = bpf_mono_now();
	__u8 accumulated_flags;
	__u8 seen_flags = flags.lower_bits & report_mask;
	__u32 last_report;

	WRITE_ONCE(entry->lifetime, now + lifetime);

	if (dir == CT_INGRESS) {
		accumulated_flags = READ_ONCE(entry->rx_flags_seen);
		last_report = READ_ONCE(entry->last_rx_report);
	} else {
		accumulated_flags = READ_ONCE(entry->tx_flags_seen);
		last_report = READ_ONCE(entry->last_tx_report);
	}
	seen_flags |= accumulated_flags;

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
	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
	    accumulated_flags != seen_flags) {
		/* verifier workaround: we don't use reference here. */
		if (dir == CT_INGRESS) {
			WRITE_ONCE(entry->rx_flags_seen, seen_flags);
			WRITE_ONCE(entry->last_rx_report, now);
		} else {
			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
			WRITE_ONCE(entry->last_tx_report, now);
		}
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
static __always_inline __u32 ct_update_timeout(struct ct_entry *entry,
					       bool tcp, enum ct_dir dir,
					       union tcp_flags seen_flags)
{
	__u32 lifetime = dir == CT_SERVICE ?
			 bpf_sec_to_mono(CT_SERVICE_LIFETIME_NONTCP) :
			 bpf_sec_to_mono(CT_CONNECTION_LIFETIME_NONTCP);
	bool syn = seen_flags.value & TCP_FLAG_SYN;

	if (tcp) {
		entry->seen_non_syn |= !syn;
		if (entry->seen_non_syn) {
			lifetime = dir == CT_SERVICE ?
				   bpf_sec_to_mono(CT_SERVICE_LIFETIME_TCP) :
				   bpf_sec_to_mono(CT_CONNECTION_LIFETIME_TCP);
		} else {
			lifetime = bpf_sec_to_mono(CT_SYN_TIMEOUT);
		}
	}

	return __ct_update_timeout(entry, lifetime, dir, seen_flags,
				   CT_REPORT_FLAGS);
}

static __always_inline void ct_reset_closing(struct ct_entry *entry)
{
	entry->rx_closing = 0;
	entry->tx_closing = 0;
}

static __always_inline bool ct_entry_alive(const struct ct_entry *entry)
{
	return !entry->rx_closing || !entry->tx_closing;
}

static __always_inline bool ct_entry_closing(const struct ct_entry *entry)
{
	return entry->tx_closing || entry->rx_closing;
}

static __always_inline bool
ct_entry_expired_rebalance(const struct ct_entry *entry)
{
	__u32 wait_time = bpf_sec_to_mono(CT_SERVICE_CLOSE_REBALANCE);

	/* This doesn't check last_rx_report because we don't see closing
	 * in RX direction for CT_SERVICE.
	 */
	return READ_ONCE(entry->last_tx_report) + wait_time <= bpf_mono_now();
}

static __always_inline __u8 __ct_lookup(const void *map, struct __ctx_buff *ctx,
					const void *tuple, int action, enum ct_dir dir,
					struct ct_state *ct_state,
					bool is_tcp, union tcp_flags seen_flags,
					__u32 *monitor)
{
	bool syn = seen_flags.value & TCP_FLAG_SYN;
	struct ct_entry *entry;
	int reopen;

	relax_verifier();

	entry = map_lookup_elem(map, tuple);
	if (entry) {
		cilium_dbg(ctx, DBG_CT_MATCH, entry->lifetime, entry->rev_nat_index);
#ifdef HAVE_LARGE_INSN_LIMIT
		if (dir == CT_SERVICE && syn &&
		    ct_entry_closing(entry) &&
		    ct_entry_expired_rebalance(entry))
			goto ct_new;
#endif
		if (ct_entry_alive(entry))
			*monitor = ct_update_timeout(entry, is_tcp, dir, seen_flags);
		if (ct_state) {
			ct_state->rev_nat_index = entry->rev_nat_index;
			if (dir == CT_SERVICE) {
				ct_state->backend_id = entry->backend_id;
				ct_state->syn = syn;
			} else if (dir == CT_INGRESS || dir == CT_EGRESS) {
#ifndef DISABLE_LOOPBACK_LB
				ct_state->loopback = entry->lb_loopback;
#endif
				ct_state->node_port = entry->node_port;
				ct_state->dsr = entry->dsr;
				ct_state->proxy_redirect = entry->proxy_redirect;
				ct_state->from_l7lb = entry->from_l7lb;
				ct_state->from_tunnel = entry->from_tunnel;
				ct_state->ifindex = entry->ifindex;
			}
		}
#ifdef CONNTRACK_ACCOUNTING
		/* FIXME: This is slow, per-cpu counters? */
		if (dir == CT_INGRESS) {
			__sync_fetch_and_add(&entry->rx_packets, 1);
			__sync_fetch_and_add(&entry->rx_bytes, ctx_full_len(ctx));
		} else if (dir == CT_EGRESS) {
			__sync_fetch_and_add(&entry->tx_packets, 1);
			__sync_fetch_and_add(&entry->tx_bytes, ctx_full_len(ctx));
		}
#endif
		switch (action) {
		case ACTION_CREATE:
			reopen = entry->rx_closing | entry->tx_closing;
			reopen |= seen_flags.value & TCP_FLAG_SYN;
			if (unlikely(reopen == (TCP_FLAG_SYN|0x1))) {
				ct_reset_closing(entry);
				*monitor = ct_update_timeout(entry, is_tcp, dir, seen_flags);
				return CT_REOPENED;
			}
			break;

		case ACTION_CLOSE:
			/* If we got an RST and have not seen both SYNs,
			 * terminate the connection. (For CT_SERVICE, we do not
			 * see both directions, so flags of established
			 * connections would not include both SYNs.)
			 */
			if (!ct_entry_seen_both_syns(entry) &&
			    (seen_flags.value & TCP_FLAG_RST) &&
			    dir != CT_SERVICE) {
				entry->rx_closing = 1;
				entry->tx_closing = 1;
			} else if (dir == CT_INGRESS) {
				entry->rx_closing = 1;
			} else {
				entry->tx_closing = 1;
			}

			*monitor = TRACE_PAYLOAD_LEN;
			if (ct_entry_alive(entry))
				break;
			__ct_update_timeout(entry, bpf_sec_to_mono(CT_CLOSE_TIMEOUT),
					    dir, seen_flags, CT_REPORT_FLAGS);
			break;
		}

		return CT_ESTABLISHED;
	}

ct_new: __maybe_unused;
	*monitor = TRACE_PAYLOAD_LEN;
	return CT_NEW;
}

static __always_inline int
ipv6_extract_tuple(struct __ctx_buff *ctx, struct ipv6_ct_tuple *tuple,
		   int *l4_off)
{
	int ret, l3_off = ETH_HLEN;
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple->nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple->daddr, (union v6addr *)&ip6->daddr);
	ipv6_addr_copy(&tuple->saddr, (union v6addr *)&ip6->saddr);

	ret = ipv6_hdrlen(ctx, &tuple->nexthdr);
	if (ret < 0)
		return ret;

	if (unlikely(tuple->nexthdr != IPPROTO_TCP &&
#ifdef ENABLE_SCTP
			 tuple->nexthdr != IPPROTO_SCTP &&
#endif  /* ENABLE_SCTP */
		     tuple->nexthdr != IPPROTO_UDP))
		return DROP_CT_UNKNOWN_PROTO;

	if (ret < 0)
		return ret;

	*l4_off = l3_off + ret;
	return CTX_ACT_OK;
}

static __always_inline void ct_flip_tuple_dir6(struct ipv6_ct_tuple *tuple)
{
	if (tuple->flags & TUPLE_F_IN)
		tuple->flags &= ~TUPLE_F_IN;
	else
		tuple->flags |= TUPLE_F_IN;
}

static __always_inline void
__ipv6_ct_tuple_reverse(struct ipv6_ct_tuple *tuple)
{
	union v6addr tmp_addr = {};
	__be16 tmp;

	ipv6_addr_copy(&tmp_addr, &tuple->saddr);
	ipv6_addr_copy(&tuple->saddr, &tuple->daddr);
	ipv6_addr_copy(&tuple->daddr, &tmp_addr);

	tmp = tuple->sport;
	tuple->sport = tuple->dport;
	tuple->dport = tmp;
}

static __always_inline void
ipv6_ct_tuple_reverse(struct ipv6_ct_tuple *tuple)
{
	__ipv6_ct_tuple_reverse(tuple);
	ct_flip_tuple_dir6(tuple);
}

static __always_inline void
ipv6_ct_tuple_swap_ports(struct ipv6_ct_tuple *tuple)
{
	__be16 tmp;

	/* Conntrack code uses tuples that have source and destination ports in
	 * the reversed order. Other code, such as BPF helpers and NAT, requires
	 * normal tuples that match the actual packet contents. This function
	 * converts between these two formats.
	 */
	tmp = tuple->sport;
	tuple->sport = tuple->dport;
	tuple->dport = tmp;
}

static __always_inline int
__ct_lookup6(const void *map, struct ipv6_ct_tuple *tuple, struct __ctx_buff *ctx,
	     int l4_off, int action, enum ct_dir dir, struct ct_state *ct_state,
	     __u32 *monitor)
{
	bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
	union tcp_flags tcp_flags = { .value = 0 };
	int ret;

	if (is_tcp) {
		if (l4_load_tcp_flags(ctx, l4_off, &tcp_flags) < 0)
			return DROP_CT_INVALID_HDR;

		if (unlikely(tcp_flags.value & (TCP_FLAG_RST | TCP_FLAG_FIN)))
			action = ACTION_CLOSE;
	}

	/* Lookup the reverse direction
	 *
	 * This will find an existing flow in the reverse direction.
	 * The reverse direction is the one where reverse nat index is stored.
	 */
	cilium_dbg3(ctx, DBG_CT_LOOKUP6_1, (__u32)tuple->saddr.p4, (__u32)tuple->daddr.p4,
		    (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
	cilium_dbg3(ctx, DBG_CT_LOOKUP6_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
	ret = __ct_lookup(map, ctx, tuple, action, dir, ct_state, is_tcp,
			  tcp_flags, monitor);
	if (ret != CT_NEW) {
		if (likely(ret == CT_ESTABLISHED || ret == CT_REOPENED)) {
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
		ret = __ct_lookup(map, ctx, tuple, action, dir, ct_state,
				  is_tcp, tcp_flags, monitor);
	}
out:
	cilium_dbg(ctx, DBG_CT_VERDICT, ret < 0 ? -ret : ret, ct_state->rev_nat_index);
	return ret;
}

/* An IPv6 version of ct_lazy_lookup4. */
static __always_inline int
ct_lazy_lookup6(const void *map, struct ipv6_ct_tuple *tuple,
		struct __ctx_buff *ctx, int l4_off, int action, enum ct_dir dir,
		struct ct_state *ct_state, __u32 *monitor)
{
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

	return __ct_lookup6(map, tuple, ctx, l4_off, action, dir,
			    ct_state, monitor);
}

/* Offset must point to IPv6 */
static __always_inline int ct_lookup6(const void *map,
				      struct ipv6_ct_tuple *tuple,
				      struct __ctx_buff *ctx, int l4_off,
				      enum ct_dir dir, struct ct_state *ct_state,
				      __u32 *monitor)
{
	int action = ACTION_UNSPEC;

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
			__be16 identifier = 0;
			__u8 type;

			if (ctx_load_bytes(ctx, l4_off, &type, 1) < 0)
				return DROP_CT_INVALID_HDR;
			if ((type == ICMPV6_ECHO_REQUEST || type == ICMPV6_ECHO_REPLY) &&
			     ctx_load_bytes(ctx, l4_off + offsetof(struct icmp6hdr,
								   icmp6_dataun.u_echo.identifier),
					    &identifier, 2) < 0)
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
				tuple->sport = identifier;
				break;

			case ICMPV6_ECHO_REQUEST:
				tuple->dport = identifier;
				/* fall through */
			default:
				action = ACTION_CREATE;
				break;
			}
		}
		break;

	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		/* load sport + dport into tuple */
		if (ctx_load_bytes(ctx, l4_off, &tuple->dport, 4) < 0)
			return DROP_CT_INVALID_HDR;

		action = ACTION_CREATE;
		break;

	default:
		/* Can't handle extension headers yet */
		return DROP_CT_UNKNOWN_PROTO;
	}

	return __ct_lookup6(map, tuple, ctx, action, l4_off, dir, ct_state, monitor);
}

static __always_inline int
ipv4_extract_tuple(struct __ctx_buff *ctx, struct ipv4_ct_tuple *tuple,
		   int *l4_off)
{
	int l3_off = ETH_HLEN;
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple->nexthdr = ip4->protocol;

	if (unlikely(tuple->nexthdr != IPPROTO_TCP &&
#ifdef ENABLE_SCTP
			 tuple->nexthdr != IPPROTO_SCTP &&
#endif  /* ENABLE_SCTP */
		     tuple->nexthdr != IPPROTO_UDP))
		return DROP_CT_UNKNOWN_PROTO;

	tuple->daddr = ip4->daddr;
	tuple->saddr = ip4->saddr;

	*l4_off = l3_off + ipv4_hdrlen(ip4);
	return CTX_ACT_OK;
}

static __always_inline void ct_flip_tuple_dir4(struct ipv4_ct_tuple *tuple)
{
	if (tuple->flags & TUPLE_F_IN)
		tuple->flags &= ~TUPLE_F_IN;
	else
		tuple->flags |= TUPLE_F_IN;
}

static __always_inline void
__ipv4_ct_tuple_reverse(struct ipv4_ct_tuple *tuple)
{
	__be32 tmp_addr = tuple->saddr;
	__be16 tmp;

	tuple->saddr = tuple->daddr;
	tuple->daddr = tmp_addr;

	tmp = tuple->sport;
	tuple->sport = tuple->dport;
	tuple->dport = tmp;
}

static __always_inline void
ipv4_ct_tuple_reverse(struct ipv4_ct_tuple *tuple)
{
	__ipv4_ct_tuple_reverse(tuple);
	ct_flip_tuple_dir4(tuple);
}

static __always_inline void
ipv4_ct_tuple_swap_ports(struct ipv4_ct_tuple *tuple)
{
	__be16 tmp;

	/* Conntrack code uses tuples that have source and destination ports in
	 * the reversed order. Other code, such as BPF helpers and NAT, requires
	 * normal tuples that match the actual packet contents. This function
	 * converts between these two formats.
	 */
	tmp = tuple->sport;
	tuple->sport = tuple->dport;
	tuple->dport = tmp;
}

static __always_inline int ipv4_ct_extract_l4_ports(struct __ctx_buff *ctx,
						    int off,
						    enum ct_dir dir __maybe_unused,
						    struct ipv4_ct_tuple *tuple,
						    bool *has_l4_header __maybe_unused)
{
#ifdef ENABLE_IPV4_FRAGMENTS
	void *data, *data_end;
	struct iphdr *ip4;

	/* This function is called from ct_lookup4(), which is sometimes called
	 * after data has been invalidated (see handle_ipv4_from_lxc())
	 */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_CT_INVALID_HDR;

	return ipv4_handle_fragmentation(ctx, ip4, off, dir,
				    (struct ipv4_frag_l4ports *)&tuple->dport,
				    has_l4_header);
#else
	/* load sport + dport into tuple */
	if (ctx_load_bytes(ctx, off, &tuple->dport, 4) < 0)
		return DROP_CT_INVALID_HDR;
#endif

	return CTX_ACT_OK;
}

static __always_inline int
ct_extract_ports4(struct __ctx_buff *ctx, int off, enum ct_dir dir,
		  struct ipv4_ct_tuple *tuple, bool *has_l4_header)
{
	int err;

	switch (tuple->nexthdr) {
	case IPPROTO_ICMP:
		if (1) {
			__be16 identifier = 0;
			__u8 type;

			if (ctx_load_bytes(ctx, off, &type, 1) < 0)
				return DROP_CT_INVALID_HDR;
			if ((type == ICMP_ECHO || type == ICMP_ECHOREPLY) &&
			     ctx_load_bytes(ctx, off + offsetof(struct icmphdr, un.echo.id),
					    &identifier, 2) < 0)
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
				tuple->sport = identifier;
				break;
			case ICMP_ECHO:
				tuple->dport = identifier;
				/* fall through */
			default:
				return ACTION_CREATE;
			}
		}
		break;

	/* TCP, UDP, and SCTP all have the ports at the same location */
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		err = ipv4_ct_extract_l4_ports(ctx, off, dir, tuple, has_l4_header);
		if (err < 0)
			return err;

		return ACTION_CREATE;

	default:
		/* Can't handle extension headers yet */
		return DROP_CT_UNKNOWN_PROTO;
	}

	return ACTION_UNSPEC;
}

/* The function determines whether an egress flow identified by the given
 * tuple is a reply.
 *
 * The datapath creates a CT entry in a reverse order. E.g., if a pod sends a
 * request to outside, the CT entry stored in the BPF map will be TUPLE_F_IN:
 * pod => outside. So, we can leverage this fact to determine whether the given
 * flow is a reply.
 */
static __always_inline int
ct_is_reply4(const void *map, struct __ctx_buff *ctx, int off,
	     struct ipv4_ct_tuple *tuple, bool *is_reply)
{
	int err = 0;

	err = ct_extract_ports4(ctx, off, CT_EGRESS, tuple, NULL);
	if (err < 0)
		return err;

	tuple->flags = TUPLE_F_IN;

	*is_reply = map_lookup_elem(map, tuple) != NULL;

	return 0;
}

static __always_inline int
__ct_lookup4(const void *map, struct ipv4_ct_tuple *tuple, struct __ctx_buff *ctx,
	     int l4_off, bool has_l4_header, int action, enum ct_dir dir,
	     struct ct_state *ct_state, __u32 *monitor)
{
	bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
	union tcp_flags tcp_flags = { .value = 0 };
	int ret;

	if (is_tcp && has_l4_header) {
		if (l4_load_tcp_flags(ctx, l4_off, &tcp_flags) < 0)
			return DROP_CT_INVALID_HDR;

		if (unlikely(tcp_flags.value & (TCP_FLAG_RST | TCP_FLAG_FIN)))
			action = ACTION_CLOSE;
	}

	/* Lookup the reverse direction
	 *
	 * This will find an existing flow in the reverse direction.
	 */
#ifndef QUIET_CT
	cilium_dbg3(ctx, DBG_CT_LOOKUP4_1, tuple->saddr, tuple->daddr,
		    (bpf_ntohs(tuple->sport) << 16) | bpf_ntohs(tuple->dport));
	cilium_dbg3(ctx, DBG_CT_LOOKUP4_2, (tuple->nexthdr << 8) | tuple->flags, 0, 0);
#endif
	ret = __ct_lookup(map, ctx, tuple, action, dir, ct_state, is_tcp,
			  tcp_flags, monitor);
	if (ret != CT_NEW) {
		if (likely(ret == CT_ESTABLISHED || ret == CT_REOPENED)) {
			if (unlikely(tuple->flags & TUPLE_F_RELATED))
				ret = CT_RELATED;
			else
				ret = CT_REPLY;
		}
		goto out;
	}

	relax_verifier();

	/* Lookup entry in forward direction */
	if (dir != CT_SERVICE) {
		ipv4_ct_tuple_reverse(tuple);
		ret = __ct_lookup(map, ctx, tuple, action, dir, ct_state,
				  is_tcp, tcp_flags, monitor);
	}
out:
	cilium_dbg(ctx, DBG_CT_VERDICT, ret < 0 ? -ret : ret, ct_state->rev_nat_index);
	return ret;
}

/** Lookup a CT entry for a fully populated CT tuple
 * @arg map		CT map
 * @arg tuple		CT tuple (with populated L4 ports)
 * @arg ctx		packet
 * @arg l4_off		offset to L4 header
 * @arg has_l4_header	packet has L4 header
 * @arg dir		lookup direction
 * @arg ct_state	returned CT entry
 * @arg monitor		monitor feedback for trace aggregation
 * @arg action          ACTION_CREATE or ACTION_UNSPEC for __ct_lookup
 *
 * This differs from ct_lookup4(), as here we expect that the CT tuple has its
 * L4 ports populated.
 *
 * Note that certain ICMP types are not supported by this function (see cases
 * where ct_extract_ports4 sets tuple->flags), because it overwrites
 * tuple->flags, but this works well in LB and NAT flows that don't pass these
 * ICMP types to ct_lazy_lookup4.
 */
static __always_inline int
ct_lazy_lookup4(const void *map, struct ipv4_ct_tuple *tuple,
		struct __ctx_buff *ctx, int l4_off, bool has_l4_header,
		int action, enum ct_dir dir, struct ct_state *ct_state,
		__u32 *monitor)
{
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

	return __ct_lookup4(map, tuple, ctx, l4_off, has_l4_header,
			    action, dir, ct_state, monitor);
}

/* Offset must point to IPv4 header */
static __always_inline int ct_lookup4(const void *map,
				      struct ipv4_ct_tuple *tuple,
				      struct __ctx_buff *ctx, int off, enum ct_dir dir,
				      struct ct_state *ct_state, __u32 *monitor)
{
	int action;
	bool has_l4_header = true;

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

	action = ct_extract_ports4(ctx, off, dir, tuple, &has_l4_header);
	if (action < 0)
		return action;

	return __ct_lookup4(map, tuple, ctx, off, has_l4_header,
			    action, dir, ct_state, monitor);
}

/* Offset must point to IPv6 */
static __always_inline int ct_create6(const void *map_main, const void *map_related,
				      struct ipv6_ct_tuple *tuple,
				      struct __ctx_buff *ctx, const enum ct_dir dir,
				      const struct ct_state *ct_state,
				      bool proxy_redirect, bool from_l7lb,
				      __s8 *ext_err)
{
	/* Create entry in original direction */
	struct ct_entry entry = { };
	bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
	union tcp_flags seen_flags = { .value = 0 };
	int err;

	if (dir == CT_SERVICE) {
		entry.backend_id = ct_state->backend_id;
	} else if (dir == CT_INGRESS || dir == CT_EGRESS) {
		entry.node_port = ct_state->node_port;
		entry.dsr = ct_state->dsr;
		entry.ifindex = ct_state->ifindex;

		/* Note if this is a proxy connection so that replies can be redirected
		 * back to the proxy.
		 */
		entry.proxy_redirect = proxy_redirect;
		entry.from_l7lb = from_l7lb;
	}

	entry.rev_nat_index = ct_state->rev_nat_index;
	seen_flags.value |= is_tcp ? TCP_FLAG_SYN : 0;
	ct_update_timeout(&entry, is_tcp, dir, seen_flags);

	if (dir == CT_INGRESS) {
		entry.rx_packets = 1;
		entry.rx_bytes = ctx_full_len(ctx);
	} else if (dir == CT_EGRESS) {
		entry.tx_packets = 1;
		entry.tx_bytes = ctx_full_len(ctx);
	}

	cilium_dbg3(ctx, DBG_CT_CREATED6, entry.rev_nat_index, ct_state->src_sec_id, 0);

	entry.src_sec_id = ct_state->src_sec_id;
	err = map_update_elem(map_main, tuple, &entry, 0);
	if (unlikely(err < 0))
		goto err_ct_fill_up;

	if (map_related != NULL) {
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

		err = map_update_elem(map_related, &icmp_tuple, &entry, 0);
		if (unlikely(err < 0))
			goto err_ct_fill_up;
	}
	return 0;

err_ct_fill_up:
	if (ext_err)
		*ext_err = (__s8)err;
	send_signal_ct_fill_up(ctx, SIGNAL_PROTO_V6);
	return DROP_CT_CREATE_FAILED;
}

static __always_inline int ct_create4(const void *map_main,
				      const void *map_related,
				      struct ipv4_ct_tuple *tuple,
				      struct __ctx_buff *ctx, const enum ct_dir dir,
				      const struct ct_state *ct_state,
				      bool proxy_redirect, bool from_l7lb,
				      __s8 *ext_err)
{
	/* Create entry in original direction */
	struct ct_entry entry = { };
	bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
	union tcp_flags seen_flags = { .value = 0 };
	int err;

	if (dir == CT_SERVICE) {
		entry.backend_id = ct_state->backend_id;
	} else if (dir == CT_INGRESS || dir == CT_EGRESS) {
#ifndef DISABLE_LOOPBACK_LB
		entry.lb_loopback = ct_state->loopback;
#endif
		entry.node_port = ct_state->node_port;
		entry.dsr = ct_state->dsr;
		entry.from_tunnel = ct_state->from_tunnel;
		entry.ifindex = ct_state->ifindex;

		/* Note if this is a proxy connection so that replies can be redirected
		 * back to the proxy.
		 */
		entry.proxy_redirect = proxy_redirect;
		entry.from_l7lb = from_l7lb;
	}

	entry.rev_nat_index = ct_state->rev_nat_index;
	seen_flags.value |= is_tcp ? TCP_FLAG_SYN : 0;
	ct_update_timeout(&entry, is_tcp, dir, seen_flags);

	if (dir == CT_INGRESS) {
		entry.rx_packets = 1;
		entry.rx_bytes = ctx_full_len(ctx);
	} else if (dir == CT_EGRESS) {
		entry.tx_packets = 1;
		entry.tx_bytes = ctx_full_len(ctx);
	}

	cilium_dbg3(ctx, DBG_CT_CREATED4, entry.rev_nat_index,
		    ct_state->src_sec_id, 0);

	entry.src_sec_id = ct_state->src_sec_id;
	err = map_update_elem(map_main, tuple, &entry, 0);
	if (unlikely(err < 0))
		goto err_ct_fill_up;

#ifndef DISABLE_LOOPBACK_LB
	if (dir == CT_EGRESS && ct_state->addr && ct_state->loopback) {
		__u8 flags = tuple->flags;
		__be32 saddr, daddr;

		saddr = tuple->saddr;
		daddr = tuple->daddr;

		/* We are looping back into the origin endpoint through a
		 * service. Set up a conntrack tuple for the reply to ensure we
		 * do rev NAT before attempting to route the destination
		 * address which will not point back to the right source.
		 */
		tuple->flags = TUPLE_F_IN;
		tuple->saddr = ct_state->svc_addr;
		tuple->daddr = ct_state->addr;

		err = map_update_elem(map_main, tuple, &entry, 0);
		if (unlikely(err < 0))
			goto err_ct_fill_up;

		tuple->saddr = saddr;
		tuple->daddr = daddr;
		tuple->flags = flags;
	}
#endif

	if (map_related != NULL) {
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
		/* Previous map update succeeded, we could delete it in case
		 * the below throws an error, but we might as well just let
		 * it time out.
		 */
		err = map_update_elem(map_related, &icmp_tuple, &entry, 0);
		if (unlikely(err < 0))
			goto err_ct_fill_up;
	}
	return 0;

err_ct_fill_up:
	if (ext_err)
		*ext_err = (__s8)err;
	send_signal_ct_fill_up(ctx, SIGNAL_PROTO_V4);
	return DROP_CT_CREATE_FAILED;
}

/* The function tries to determine whether the flow identified by the given
 * CT_INGRESS tuple belongs to a NodePort traffic (i.e., outside client => N/S
 * LB => local backend).
 *
 * When the client send the NodePort request, the NodePort BPF
 * (nodeport_lb{4,6}()) creates the CT_EGRESS entry for the
 * (saddr=client,daddr=backend) tuple. So, to derive whether the reply packet
 * backend => client belongs to the LB flow we can query the CT_EGRESS entry.
 */
static __always_inline bool
ct_has_nodeport_egress_entry4(const void *map,
			      struct ipv4_ct_tuple *ingress_tuple,
			      bool check_dsr)
{
	__u8 prev_flags = ingress_tuple->flags;
	struct ct_entry *entry;

	ingress_tuple->flags = TUPLE_F_OUT;
	entry = map_lookup_elem(map, ingress_tuple);
	ingress_tuple->flags = prev_flags;

	if (entry)
		return entry->node_port || (check_dsr && entry->dsr);

	return 0;
}

static __always_inline bool
ct_has_dsr_egress_entry4(const void *map, struct ipv4_ct_tuple *ingress_tuple)
{
	__u8 prev_flags = ingress_tuple->flags;
	struct ct_entry *entry;

	ingress_tuple->flags = TUPLE_F_OUT;
	entry = map_lookup_elem(map, ingress_tuple);
	ingress_tuple->flags = prev_flags;

	if (entry)
		return entry->dsr;

	return 0;
}

static __always_inline bool
ct_has_nodeport_egress_entry6(const void *map,
			      struct ipv6_ct_tuple *ingress_tuple,
			      bool check_dsr)
{
	__u8 prev_flags = ingress_tuple->flags;
	struct ct_entry *entry;

	ingress_tuple->flags = TUPLE_F_OUT;
	entry = map_lookup_elem(map, ingress_tuple);
	ingress_tuple->flags = prev_flags;

	if (entry)
		return entry->node_port || (check_dsr && entry->dsr);

	return 0;
}

static __always_inline bool
ct_has_dsr_egress_entry6(const void *map, struct ipv6_ct_tuple *ingress_tuple)
{
	__u8 prev_flags = ingress_tuple->flags;
	struct ct_entry *entry;

	ingress_tuple->flags = TUPLE_F_OUT;
	entry = map_lookup_elem(map, ingress_tuple);
	ingress_tuple->flags = prev_flags;

	if (entry)
		return entry->dsr;

	return 0;
}

static __always_inline void
ct_update_svc_entry(const void *map, const void *tuple,
		    __u32 backend_id, __u16 rev_nat_index)
{
	struct ct_entry *entry;

	entry = map_lookup_elem(map, tuple);
	if (!entry)
		return;

	entry->backend_id = backend_id;
	entry->rev_nat_index = rev_nat_index;
}

static __always_inline void
ct_update_rev_nat_index(const void *map, const void *tuple,
			const struct ct_state *state)
{
	struct ct_entry *entry;

	entry = map_lookup_elem(map, tuple);
	if (!entry)
		return;

	entry->rev_nat_index = state->rev_nat_index;
}

static __always_inline void
ct_update_dsr(const void *map, const void *tuple, const bool dsr)
{
	struct ct_entry *entry;

	entry = map_lookup_elem(map, tuple);
	if (!entry)
		return;

	entry->dsr = dsr;
}

static __always_inline void
ct_update_nodeport(const void *map, const void *tuple, const bool node_port)
{
	struct ct_entry *entry;

	entry = map_lookup_elem(map, tuple);
	if (!entry)
		return;

	entry->node_port = node_port;
}
#endif /* __LIB_CONNTRACK_H_ */
