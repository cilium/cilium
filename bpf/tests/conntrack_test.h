/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2020 Authors of Cilium */

enum {
	__TUPLE_EXIST,
	__TUPLE_NOEXIST,
};

static struct ct_entry __ipv4_map[] = {
	{},
};

static void *__map_lookup_elem(const void *map, const void *tuple)
{
	if (map == __ipv4_map) {
		__u64 idx = (__u64)tuple;

		if (idx == __TUPLE_EXIST)
			return &__ipv4_map[idx];
	}
	return NULL;
}
#define map_lookup_elem(map, tuple) __map_lookup_elem(map, tuple)
#include "lib/conntrack.h"
#undef map_lookup_elem

#define REPORT_ALL_FLAGS 0xFF
#define REPORT_NO_FLAGS 0x0

/* Advance global (fake) time by one unit. */
void advance_time(void)
{
	__now = __now + 1;
}

/* Return true IFF 'entry' will expire in 'seconds'. */
bool timeout_in(const struct ct_entry *entry, int seconds)
{
	return entry->lifetime == __now + seconds;
}

static void test___ct_update_timeout(void)
{
	struct ct_entry entry = {};
	union tcp_flags flags = {};
	__u32 then;
	int monitor;

	/* No update initially; mostly just because __now is less than the
	 * default report interval.
	 */
	monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_ALL_FLAGS);
	assert(!monitor);

	/* When a full report interval has passed, report. */
	__now += 1+CT_REPORT_INTERVAL;
	monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_ALL_FLAGS);
	assert(monitor);
	assert(entry.last_rx_report == __now);
	assert(entry.last_tx_report == 0);
	assert(entry.rx_flags_seen == 0);
	/* If <= a full report interval passes, don't report. */
	then = __now;
	__now += CT_REPORT_INTERVAL;
	monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_ALL_FLAGS);
	assert(!monitor);
	assert(entry.last_rx_report == then);

	/* When flags change, report. */
	flags.value |= TCP_FLAG_SYN;
	monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_ALL_FLAGS);
	assert(monitor);
	assert(entry.last_rx_report == __now);
	assert(entry.rx_flags_seen == bpf_ntohs(TCP_FLAG_SYN));
	assert(entry.last_tx_report == 0);
	assert(entry.tx_flags_seen == 0);
	/* Same call; no report. */
	monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_ALL_FLAGS);
	assert(!monitor);

	/* If flags change but flag reporting is disabled, skip it. */
	flags.value |= TCP_FLAG_FIN;
	monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_NO_FLAGS);
	assert(!monitor);
	assert(entry.rx_flags_seen == bpf_ntohs(TCP_FLAG_SYN));
	assert(entry.tx_flags_seen == 0);
}

static void test___ct_lookup(void)
{
	void *map = __ipv4_map;
	struct ct_entry *entry = &__ipv4_map[0];
	struct __ctx_buff ctx = {};
	void *tuple = (void *)__TUPLE_EXIST;

	struct ct_state ct_state;
	union tcp_flags seen_flags = {0};
	__u32 monitor;
	int res;

	seen_flags.value |= TCP_FLAG_SYN;

	/* First packet is monitored */
	res = __ct_lookup(map, &ctx, tuple, ACTION_CREATE, CT_INGRESS,
			  &ct_state, true, seen_flags, &monitor);
	assert(res == CT_ESTABLISHED);
	assert(monitor == TRACE_PAYLOAD_LEN);
	assert(timeout_in(entry, CT_SYN_TIMEOUT));

	/* Second packet with the same flags is not monitored; it does reset
	 * lifetime back to CT_SYN_TIMEOUT.
	 */
	advance_time();
	res = __ct_lookup(map, &ctx, tuple, ACTION_CREATE, CT_INGRESS,
			  &ct_state, true, seen_flags, &monitor);
	assert(res == CT_ESTABLISHED);
	assert(monitor == 0);
	assert(timeout_in(entry, CT_SYN_TIMEOUT));

	/* Subsequent non-SYN packets result in a default TCP lifetime */
	advance_time();
	seen_flags.value &= ~TCP_FLAG_SYN;
	res = __ct_lookup(map, &ctx, tuple, ACTION_CREATE, CT_INGRESS,
			  &ct_state, true, seen_flags, &monitor);
	assert(res == CT_ESTABLISHED);
	assert(monitor == 0);
	assert(timeout_in(entry, CT_CONNECTION_LIFETIME_TCP));

	/* Monitor if the connection is closing on one side */
	advance_time();
	seen_flags.value |= TCP_FLAG_FIN;
	res = __ct_lookup(map, &ctx, tuple, ACTION_CLOSE, CT_INGRESS,
			  &ct_state, true, seen_flags, &monitor);
	assert(res == CT_ESTABLISHED);
	assert(monitor == TRACE_PAYLOAD_LEN);
	assert(timeout_in(entry, CT_CONNECTION_LIFETIME_TCP));

	/* This doesn't automatically trigger monitor for subsequent packets */
	advance_time();
	seen_flags.value &= ~TCP_FLAG_FIN;
	res = __ct_lookup(map, &ctx, tuple, ACTION_CREATE, CT_INGRESS,
			  &ct_state, true, seen_flags, &monitor);
	assert(res == CT_ESTABLISHED);
	assert(monitor == 0);
	assert(timeout_in(entry, CT_CONNECTION_LIFETIME_TCP));

	/* Monitor if the connection is closing on the other side. This
	 * second FIN on the other side will reset lifetime to
	 * CT_CLOSE_TIMEOUT.
	 */
	advance_time();
	seen_flags.value |= TCP_FLAG_FIN;
	res = __ct_lookup(map, &ctx, tuple, ACTION_CLOSE, CT_EGRESS,
			  &ct_state, true, seen_flags, &monitor);
	assert(res == CT_ESTABLISHED);
	assert(monitor == TRACE_PAYLOAD_LEN);
	assert(timeout_in(entry, CT_CLOSE_TIMEOUT));

	/* This doesn't automatically trigger monitor for subsequent packets */
	advance_time();
	monitor = 0;
	seen_flags.value &= ~TCP_FLAG_FIN;
	res = __ct_lookup(map, &ctx, tuple, ACTION_CREATE, CT_EGRESS,
			  &ct_state, true, seen_flags, &monitor);
	assert(res == CT_ESTABLISHED);
	assert(monitor == 0);
	assert(timeout_in(entry, CT_CLOSE_TIMEOUT - 1));

	/* A connection is reopened due to a newly seen SYN.*/
	advance_time();
	monitor = 0;
	seen_flags.value = TCP_FLAG_SYN;
	res = __ct_lookup(map, &ctx, tuple, ACTION_CREATE, CT_EGRESS,
			  &ct_state, true, seen_flags, &monitor);
	assert(res == CT_REOPENED);
	assert(monitor == TRACE_PAYLOAD_LEN);
	assert(timeout_in(entry, CT_CONNECTION_LIFETIME_TCP));

	/* Label connection as new if the tuple wasn't previously tracked */
	tuple = (void *)__TUPLE_NOEXIST;
	seen_flags.value = TCP_FLAG_SYN;
	res = __ct_lookup(map, &ctx, tuple, ACTION_CREATE, CT_INGRESS,
			  &ct_state, true, seen_flags, &monitor);
	assert(res == CT_NEW);
	assert(monitor == TRACE_PAYLOAD_LEN);
}
