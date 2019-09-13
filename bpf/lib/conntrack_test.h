// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018-2019 Authors of Cilium

/* Declare before lib/conntrack.h or die! */
static uint32_t __now = 0;

#define bpf_ktime_get_sec() __now
#include "lib/conntrack.h"

#define REPORT_ALL_FLAGS 0xFF
#define REPORT_NO_FLAGS 0x0

static void test___ct_update_timeout()
{
	struct ct_entry entry = {};
	union tcp_flags flags = {};
	uint32_t then;
	int monitor;

	// No update initially; mostly just because __now is less than the
	// default report interval.
	monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_ALL_FLAGS);
	assert(!monitor);

	// When a full report interval has passed, report.
	__now += 1+CT_REPORT_INTERVAL;
	monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_ALL_FLAGS);
	assert(monitor);
	assert(entry.last_rx_report == __now);
	assert(entry.last_tx_report == 0);
	assert(entry.rx_flags_seen == 0);
	// If <= a full report interval passes, don't report.
	then = __now;
	__now += CT_REPORT_INTERVAL;
	monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_ALL_FLAGS);
	assert(!monitor);
	assert(entry.last_rx_report == then);

	// When flags change, report.
	flags.value |= TCP_FLAG_SYN;
	monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_ALL_FLAGS);
	assert(monitor);
	assert(entry.last_rx_report == __now);
	assert(entry.rx_flags_seen == bpf_ntohs(TCP_FLAG_SYN));
	assert(entry.last_tx_report == 0);
	assert(entry.tx_flags_seen == 0);
	// Same call; no report
	monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_ALL_FLAGS);
	assert(!monitor);

	// If flags change but flag reporting is disabled, skip it.
	flags.value |= TCP_FLAG_FIN;
	monitor = __ct_update_timeout(&entry, 1000, CT_INGRESS, flags, REPORT_NO_FLAGS);
	assert(!monitor);
	assert(entry.rx_flags_seen == bpf_ntohs(TCP_FLAG_SYN));
	assert(entry.tx_flags_seen == 0);
}
