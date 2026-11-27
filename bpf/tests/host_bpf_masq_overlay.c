// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "host_bpf_masq.h"

ASSIGN_CONFIG(bool, enable_tunnel_mode, true)
ASSIGN_CONFIG(__u32, encap_ifindex, 42)
