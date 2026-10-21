/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define ENABLE_NODEPORT		1

#include "kpr_dsr_lb.h"

ASSIGN_CONFIG(__u32, encap4_ifindex, 42)
ASSIGN_CONFIG(__u32, encap6_ifindex, 42)
ASSIGN_CONFIG(struct dsr_config, dsr_cfg, { .enable = true, .enable_icmp_errors = true, .encap_mode = DSR_ENCAP_IPIP })
