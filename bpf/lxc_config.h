/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

/*
 * This is just a dummy header with dummy values to allow for test
 * compilation without the full code generation engine backend.
 */
#include "lib/utils.h"

DEFINE_IPV6(LXC_IP, 0xbe, 0xef, 0, 0, 0, 0, 0, 0x1, 0, 0, 0, 0x1, 0x01, 0x65, 0x82, 0xbc);
DEFINE_U32(LXC_IPV4, 0x10203040);
#define LXC_IPV4 fetch_u32(LXC_IPV4)
DEFINE_U32(LXC_ID, 0x2A);
#define LXC_ID fetch_u32(LXC_ID)
DEFINE_U32(SECLABEL, 0xfffff);
#define SECLABEL fetch_u32(SECLABEL)
DEFINE_U32(SECLABEL_NB, 0xfffff);
#define SECLABEL_NB fetch_u32(SECLABEL_NB)

DEFINE_U32(POLICY_VERDICT_LOG_FILTER, 0xffff);
#define POLICY_VERDICT_LOG_FILTER fetch_u32(POLICY_VERDICT_LOG_FILTER)

#define POLICY_MAP test_cilium_policy_65535

#ifndef SKIP_DEBUG
#define DEBUG
#endif
#define DROP_NOTIFY
#define TRACE_NOTIFY
#define POLICY_VERDICT_NOTIFY
#define CT_MAP_TCP6 test_cilium_ct_tcp6_65535
#define CT_MAP_ANY6 test_cilium_ct_any6_65535
#define CT_MAP_TCP4 test_cilium_ct_tcp4_65535
#define CT_MAP_ANY4 test_cilium_ct_any4_65535
#define CT_MAP_SIZE_TCP 4096
#define CT_MAP_SIZE_ANY 4096
#define CALLS_MAP test_cilium_calls_65535
#define LB_L3
#define LB_L4
#define LOCAL_DELIVERY_METRICS
#define CONNTRACK
#define CONNTRACK_ACCOUNTING

/* It appears that we can support around the below number of prefixes in an
 * unrolled loop for LPM CIDR handling in older kernels along with the rest of
 * the logic in the datapath, hence the defines below. This number was arrived
 * to by adjusting the number of prefixes and running:
 *
 *    $ make -C bpf && sudo test/bpf/verifier-test.sh
 *
 *  If you're from a future where all supported kernels include LPM map type,
 *  consider deprecating the hash-based CIDR lookup and removing the below.
 */
#define IPCACHE4_PREFIXES 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, \
4, 3, 2, 1
#define IPCACHE6_PREFIXES 4, 3, 2, 1
