// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define TUNNEL_MODE		        1

#include "encrypt_host.h"

ASSIGN_CONFIG(bool, enable_ipsec, true)
ASSIGN_CONFIG(__u32, encap_ifindex, 42)
