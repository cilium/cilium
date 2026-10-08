/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#define ATTACHMENT_XDP

#define ENABLE_IPV4			1
#define ENABLE_IPV6			1
#define ENABLE_NODEPORT			1
#define ENABLE_DSR			1
#define DSR_ENCAP_IPIP			2
#define DSR_ENCAP_GENEVE		3
#define DSR_ENCAP_MODE			DSR_ENCAP_GENEVE
#define ENCAP_IFINDEX			42

#define ENABLE_NODEPORT_ACCELERATION	1

#include "kpr_dsr_lb.h"
