/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1

#define TEST_DSR_OPT_NETWORK_BYTE_ORDER

#include "kpr_dsr_lb.h"

ASSIGN_CONFIG(bool, enable_ipv4, true)
ASSIGN_CONFIG(bool, enable_nodeport, true)
ASSIGN_CONFIG(struct dsr_config, dsr_cfg, {
	.enable = true,
	.enable_icmp_errors = true,
	.encap_mode = DSR_ENCAP_NONE,
})
