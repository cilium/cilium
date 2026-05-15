// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_DSR
#define ENCAP_IFINDEX		1

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_SCTP
#define ENABLE_NODEPORT
#define ENABLE_MASQUERADE_IPV4		1
#define ENABLE_MASQUERADE_IPV6		1

#include "bpf_nat_icmp.h"
#include "bpf_nat_icmp6.h"
