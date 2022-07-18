/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * This is just a dummy header with dummy values to allow for test
 * compilation without the full code generation engine backend.
 */
#include "lib/utils.h"

#ifndef ___EP_CONFIG____
#define ___EP_CONFIG____

DEFINE_IPV6(LXC_IP, 0xbe, 0xef, 0, 0, 0, 0, 0, 0x1, 0, 0, 0, 0x1, 0x01, 0x65, 0x82, 0xbc);

#ifndef LXC_IPV4
DEFINE_U32(LXC_IPV4, 0x10203040);
#define LXC_IPV4 fetch_u32(LXC_IPV4)
#endif /* LXC_IPV4 */

/*
 * Both the LXC_ID and the HOST_EP_ID are defined here to ease compile testing,
 * but in the actual header files, only one of them will be present.
 */
DEFINE_U16(LXC_ID, 0x2A);
#define LXC_ID fetch_u16(LXC_ID)
DEFINE_U32(SECLABEL, 0xfffff);
#define SECLABEL fetch_u32(SECLABEL)
DEFINE_U32(SECLABEL_NB, 0xfffff);
#define SECLABEL_NB fetch_u32(SECLABEL_NB)

DEFINE_U32(POLICY_VERDICT_LOG_FILTER, 0xffff);
#define POLICY_VERDICT_LOG_FILTER fetch_u32(POLICY_VERDICT_LOG_FILTER)

#define HOST_EP_ID 0x1092

#define POLICY_MAP test_cilium_policy_65535

#ifndef SKIP_DEBUG
#define DEBUG
#endif
#define DROP_NOTIFY
#define TRACE_NOTIFY
#define CT_MAP_TCP6 test_cilium_ct_tcp6_65535
#define CT_MAP_ANY6 test_cilium_ct_any6_65535
#define CT_MAP_TCP4 test_cilium_ct_tcp4_65535
#define CT_MAP_ANY4 test_cilium_ct_any4_65535
#define CT_MAP_SIZE_TCP 4096
#define CT_MAP_SIZE_ANY 4096
#define CALLS_MAP test_cilium_calls_65535
#define CUSTOM_CALLS_MAP test_cilium_calls_custom_65535
#define LOCAL_DELIVERY_METRICS
#define CONNTRACK_ACCOUNTING
#define DIRECT_ROUTING_DEV_IFINDEX 0

#endif
