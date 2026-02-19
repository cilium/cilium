// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#undef __CONFIG_ENABLE_NETKIT
#define ENABLE_IPV4 1
#define USE_BPF_PROG_FOR_INGRESS_POLICY 1
#include "tc_redirect_host.h"
