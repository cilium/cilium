// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define __CONFIG_ENABLE_NETKIT
#define ENABLE_IPV6 1
#undef USE_BPF_PROG_FOR_INGRESS_POLICY
#include "tc_redirect_host.h"
