// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENCAP_IFINDEX		        42

#include "encrypt_host.h"

ASSIGN_CONFIG(bool, enable_ipsec, true)
ASSIGN_CONFIG(bool, enable_tunnel_mode, true)
