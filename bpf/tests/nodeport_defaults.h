/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/config/node.h>

ASSIGN_CONFIG(__u16, nodeport_port_min, 30000)
ASSIGN_CONFIG(__u16, nodeport_port_max, 32767)
