// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include "bpf/ctx/skb.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT

#include "node_config.h"
#include "lib/common.h"

static __u64 __now;

#define ktime_get_ns()	(__now * NSEC_PER_SEC)
#define jiffies64()	(__now)

/* Is not part of these tests, and is causing issues in the CI */
#undef CONNTRACK_ACCOUNTING

#include "lib/conntrack.h"
#include "lib/conntrack_map.h"

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

CHECK("tc", "conntrack")
int bpf_test(__maybe_unused struct __sk_buff *sctx)
{
	test_init();

	TEST("ct_update_timeout", {
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
		__now += 1 + CT_REPORT_INTERVAL;
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
		assert(entry.rx_flags_seen == tcp_flags_to_u8(TCP_FLAG_SYN));
		assert(entry.last_tx_report == 0);
		assert(entry.tx_flags_seen == 0);
		/* Same call; no report. */
		monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_ALL_FLAGS);
		assert(!monitor);

		/* If flags change but flag reporting is disabled, skip it. */
		flags.value |= TCP_FLAG_FIN;
		monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_NO_FLAGS);
		assert(!monitor);
		assert(entry.rx_flags_seen == tcp_flags_to_u8(TCP_FLAG_SYN));
		assert(entry.tx_flags_seen == 0);
	});

	TEST("ct_lookup", {
		struct __ctx_buff ctx = {};
		int res;
		struct ipv4_ct_tuple tuple = {
			.nexthdr = IPPROTO_TCP
		};

		struct ct_entry ct_entry_new = {};

		res = map_update_elem(get_ct_map4(&tuple), &tuple, &ct_entry_new, BPF_ANY);
		if (IS_ERR(res))
			test_fatal("map_update_elem: %lld", res);

		struct ct_entry *entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

		if (!entry)
			test_fatal("ct entry lookup failed");

		union tcp_flags seen_flags = {0};
		__u32 monitor;

		seen_flags.value |= TCP_FLAG_SYN;

		/* First packet is monitored */
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_INGRESS,
				  CT_ENTRY_ANY, NULL, true, seen_flags, &monitor);
		assert(res == CT_ESTABLISHED);
		assert(monitor == TRACE_PAYLOAD_LEN);
		assert(timeout_in(entry, CT_SYN_TIMEOUT));

		/* Second packet with the same flags is not monitored; it does reset
		 * lifetime back to CT_SYN_TIMEOUT.
		 */
		advance_time();
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_INGRESS,
				  CT_ENTRY_ANY, NULL, true, seen_flags, &monitor);
		assert(res == CT_ESTABLISHED);
		assert(monitor == 0);
		assert(timeout_in(entry, CT_SYN_TIMEOUT));

		/* Subsequent non-SYN packets result in a default TCP lifetime */
		advance_time();
		seen_flags.value &= ~TCP_FLAG_SYN;
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_INGRESS,
				  CT_ENTRY_ANY, NULL, true, seen_flags, &monitor);
		assert(res == CT_ESTABLISHED);
		assert(monitor == 0);
		assert(timeout_in(entry, CT_CONNECTION_LIFETIME_TCP));

		/* Monitor if the connection is closing on one side */
		advance_time();
		seen_flags.value |= TCP_FLAG_FIN;
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_INGRESS,
				  CT_ENTRY_ANY, NULL, true, seen_flags, &monitor);
		assert(res == CT_ESTABLISHED);
		assert(monitor == TRACE_PAYLOAD_LEN);
		assert(timeout_in(entry, CT_CONNECTION_LIFETIME_TCP));

		/* This doesn't automatically trigger monitor for subsequent packets */
		advance_time();
		seen_flags.value &= ~TCP_FLAG_FIN;
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_INGRESS,
				  CT_ENTRY_ANY, NULL, true, seen_flags, &monitor);
		assert(res == CT_ESTABLISHED);
		assert(monitor == 0);
		assert(timeout_in(entry, CT_CONNECTION_LIFETIME_TCP));

		/* Monitor if the connection is closing on the other side. This
		 * second FIN on the other side will reset lifetime to
		 * CT_CLOSE_TIMEOUT.
		 */
		advance_time();
		seen_flags.value |= TCP_FLAG_FIN;
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_EGRESS,
				  CT_ENTRY_ANY, NULL, true, seen_flags, &monitor);
		assert(res == CT_ESTABLISHED);
		assert(monitor == TRACE_PAYLOAD_LEN);
		assert(timeout_in(entry, CT_CLOSE_TIMEOUT));

		/* This doesn't automatically trigger monitor for subsequent packets */
		advance_time();
		monitor = 0;
		seen_flags.value &= ~TCP_FLAG_FIN;
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_EGRESS,
				  CT_ENTRY_ANY, NULL, true, seen_flags, &monitor);
		assert(res == CT_ESTABLISHED);
		assert(monitor == 0);
		assert(timeout_in(entry, CT_CLOSE_TIMEOUT - 1));

		/* A connection is reopened due to a newly seen SYN.*/
		advance_time();
		monitor = 0;
		seen_flags.value = TCP_FLAG_SYN;
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_EGRESS,
				  CT_ENTRY_ANY, NULL, true, seen_flags, &monitor);
		assert(res == CT_NEW);
		assert(monitor == TRACE_PAYLOAD_LEN);
		assert(timeout_in(entry, CT_SYN_TIMEOUT));

		/* Label connection as new if the tuple wasn't previously tracked */
		tuple.saddr = 123;
		seen_flags.value = TCP_FLAG_SYN;
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_INGRESS,
				  CT_ENTRY_ANY, NULL, true, seen_flags, &monitor);
		assert(res == CT_NEW);
		assert(monitor == TRACE_PAYLOAD_LEN);
	});

	test_finish();
}

CHECK("tc", "conntrack_svc")
int svc_test(__maybe_unused struct __sk_buff *sctx)
{
	test_init();

	TEST("ct_lookup_svc", {
		struct __ctx_buff ctx = {};
		int res;
		struct ipv4_ct_tuple tuple = {};
		struct ct_state ct_state = {};
		union tcp_flags seen_flags = {0};
		__u32 monitor;

		tuple.nexthdr = IPPROTO_TCP;
		tuple.flags = CT_SERVICE;

		struct ct_entry ct_entry_new = {};

		res = map_update_elem(get_ct_map4(&tuple), &tuple, &ct_entry_new, BPF_ANY);
		if (IS_ERR(res))
			test_fatal("map_update_elem: %lld", res);

		struct ct_entry *entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

		if (!entry)
			test_fatal("ct entry lookup failed");

		seen_flags.value |= TCP_FLAG_SYN;

		/* First packet is monitored */
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_SERVICE,
				  CT_ENTRY_SVC, &ct_state, true, seen_flags, &monitor);
		assert(res == CT_ESTABLISHED);
		assert(monitor == TRACE_PAYLOAD_LEN);
		assert(timeout_in(entry, CT_SYN_TIMEOUT));

		/* Second packet with the same flags is not monitored; it does reset
		 * lifetime back to CT_SYN_TIMEOUT.
		 */
		advance_time();
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_SERVICE,
				  CT_ENTRY_SVC, &ct_state, true, seen_flags, &monitor);
		assert(res == CT_ESTABLISHED);
		assert(monitor == 0);
		assert(timeout_in(entry, CT_SYN_TIMEOUT));

		/* Subsequent non-SYN packets result in a default SVC TCP lifetime */
		advance_time();
		seen_flags.value &= ~TCP_FLAG_SYN;
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_SERVICE,
				  CT_ENTRY_SVC, &ct_state, true, seen_flags, &monitor);
		assert(res == CT_ESTABLISHED);
		assert(monitor == 0);
		assert(timeout_in(entry, CT_SERVICE_LIFETIME_TCP));

		/* Monitor & lower lifetime if the connection is closing on just one side */
		advance_time();
		seen_flags.value |= TCP_FLAG_FIN;
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_SERVICE,
				  CT_ENTRY_SVC, &ct_state, true, seen_flags, &monitor);
		assert(res == CT_ESTABLISHED);
		assert(monitor == TRACE_PAYLOAD_LEN);
		assert(timeout_in(entry, CT_CLOSE_TIMEOUT));

		/* Label connection as new if the tuple wasn't previously tracked */
		tuple.saddr = 456;
		seen_flags.value = TCP_FLAG_SYN;
		res = __ct_lookup(get_ct_map4(&tuple), &ctx, &tuple,
				  ct_tcp_select_action(seen_flags), CT_SERVICE,
				  CT_ENTRY_SVC, &ct_state, true, seen_flags, &monitor);
		assert(res == CT_NEW);
		assert(monitor == TRACE_PAYLOAD_LEN);
	});

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
