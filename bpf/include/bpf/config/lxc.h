/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This configuration data is specific to workload endpoints (bpf_lxc.c). Do not
 * import into any other program.
 */

#pragma once

#include <lib/static_data.h>

DECLARE_CONFIG(__u16, endpoint_id, "The endpoint's security ID")
#define LXC_ID CONFIG(endpoint_id) /* Backwards compatibility */

DECLARE_CONFIG(union v4addr, endpoint_ipv4, "The endpoint's IPv4 address")
DECLARE_CONFIG(union v6addr, endpoint_ipv6, "The endpoint's IPv6 address")

DECLARE_CONFIG(__u64, endpoint_netns_cookie, "The endpoint's network namespace cookie")

DECLARE_CONFIG(__u32, fib_table_id, "FIB routing table ID for egress lookups")
