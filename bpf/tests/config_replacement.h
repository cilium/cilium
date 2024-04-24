/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This file is a replacement for ep_config.h which replaces global data
 * With pre-defined macros since our test suite doesn't perform global data
 * inlining at the moment.
 */

#ifndef ___EP_CONFIG____
#define ___EP_CONFIG____

#include "lib/static_data.h"

#ifndef LXC_IP
DEFINE_IPV6(LXC_IP, 0xbe, 0xef, 0, 0, 0, 0, 0, 0x1, 0, 0, 0, 0x1, 0x01, 0x65, 0x82, 0xbc);
#endif /* LXC_IP */

#ifndef LXC_IPV4
#define LXC_IPV4 0x10203040
#endif /* LXC_IPV4 */

/*
 * Both the LXC_ID and the HOST_EP_ID are defined here to ease compile testing,
 * but in the actual header files, only one of them will be present.
 */
#ifndef LXC_ID
#define LXC_ID 0x2A
#endif

#ifndef SECLABEL
#define SECLABEL 0xfffff
#endif

#ifndef SECLABEL_IPV4
#define SECLABEL_IPV4 0xfffff
#endif

#ifndef SECLABEL_IPV6
#define SECLABEL_IPV6 0xfffff
#endif

#ifndef SECLABEL_NB
#define SECLABEL_NB 0xfffff
#endif

#ifndef POLICY_VERDICT_LOG_FILTER
#define POLICY_VERDICT_LOG_FILTER 0xffff
#endif

#ifndef HOST_EP_ID
#define HOST_EP_ID 0x1092
#endif

#ifndef POLICY_MAP
#define POLICY_MAP test_cilium_policy_65535
#endif

#ifndef SKIP_DEBUG
#define DEBUG
#endif

#define DROP_NOTIFY
#define TRACE_NOTIFY
#define CT_MAP_TCP6 test_cilium_ct_tcp6_65535
#define CT_MAP_ANY6 test_cilium_ct_any6_65535
#define CT_MAP_TCP4 test_cilium_ct_tcp4_65535
#define CT_MAP_ANY4 test_cilium_ct_any4_65535
#define PER_CLUSTER_CT_TCP6 test_cilium_per_cluster_ct_tcp6
#define PER_CLUSTER_CT_ANY6 test_cilium_per_cluster_ct_any6
#define PER_CLUSTER_CT_TCP4 test_cilium_per_cluster_ct_tcp4
#define PER_CLUSTER_CT_ANY4 test_cilium_per_cluster_ct_any4
#define CT_MAP_SIZE_TCP 4096
#define CT_MAP_SIZE_ANY 4096
#define CALLS_MAP test_cilium_calls_65535
#define CUSTOM_CALLS_MAP test_cilium_calls_custom_65535
#define LOCAL_DELIVERY_METRICS
#define CONNTRACK_ACCOUNTING
#define POLICY_ACCOUNTING
#define DIRECT_ROUTING_DEV_IFINDEX 0

#endif /* ___EP_CONFIG____ */
