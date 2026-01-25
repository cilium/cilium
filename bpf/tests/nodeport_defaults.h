/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/config/node.h>

#ifndef NODEPORT_PORT_MIN
#define NODEPORT_PORT_MIN 30000
#endif

#ifndef NODEPORT_PORT_MAX
#define NODEPORT_PORT_MAX 32767
#endif

#ifndef NODEPORT_PORT_MIN_NAT
#define NODEPORT_PORT_MIN_NAT 32768
#endif

#ifndef NODEPORT_PORT_MAX_NAT
#define NODEPORT_PORT_MAX_NAT 65535
#endif

ASSIGN_CONFIG(__u16, nodeport_port_min, NODEPORT_PORT_MIN)
ASSIGN_CONFIG(__u16, nodeport_port_max, NODEPORT_PORT_MAX)
ASSIGN_CONFIG(__u16, nodeport_port_min_nat, NODEPORT_PORT_MIN_NAT)
ASSIGN_CONFIG(__u16, nodeport_port_max_nat, NODEPORT_PORT_MAX_NAT)
