// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define TUNNEL_MODE	1

#include "host_bpf_masq.h"

ASSIGN_CONFIG(__u32, encap_ifindex, 42)
