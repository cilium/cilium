/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This configuration data is specific to workload endpoints (bpf_lxc.c). Do not
 * import into any other program.
 */

#pragma once

#include <lib/static_data.h>

DECLARE_CONFIG(__u16, endpoint_id, "The endpoint's security ID")
#define LXC_ID CONFIG(endpoint_id) /* Backwards compatibility */

DECLARE_CONFIG(__u32, endpoint_ipv4, "The endpoint's IPv4 address")
#define LXC_IPV4 CONFIG(endpoint_ipv4) /* Backwards compatibility */

DECLARE_CONFIG(__u64, endpoint_ipv6_1, "The endpoint's first 64 bits of the IPv6 address")
DECLARE_CONFIG(__u64, endpoint_ipv6_2, "The endpoint's second 64 bits of the IPv6 address")
#define LXC_IP endpoint_ipv6 /* Backwards compatibility */

DECLARE_CONFIG(__u64, endpoint_netns_cookie, "The endpoint's network namespace cookie")
#define ENDPOINT_NETNS_COOKIE CONFIG(endpoint_netns_cookie) /* Backwards compatibility */
