/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define ENABLE_NODEPORT		1
#define ENABLE_DSR		1
#define DSR_ENCAP_GENEVE        3

#define TEST_DSR_OPT_NETWORK_BYTE_ORDER

#include "kpr_dsr_lb.h"
