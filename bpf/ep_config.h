/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/*
 * This is just a dummy header with dummy values to allow for test
 * compilation without the full code generation engine backend.
 */
#include "lib/utils.h"

#define HOST_EP_ID 0x1092

#define POLICY_MAP test_cilium_policy_v2_65535

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
#define CUSTOM_CALLS_MAP test_cilium_calls_custom_65535
#define LOCAL_DELIVERY_METRICS
#define CONNTRACK_ACCOUNTING
#define POLICY_ACCOUNTING
#define DIRECT_ROUTING_DEV_IFINDEX 0
