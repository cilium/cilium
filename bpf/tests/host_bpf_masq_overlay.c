// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENCAP_IFINDEX	42

#include "host_bpf_masq.h"

ASSIGN_CONFIG(bool, enable_tunnel_mode, true)
