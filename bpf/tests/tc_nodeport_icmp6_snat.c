// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "bpf_nat_icmp6.h"

#undef TUNNEL_MODE
#define DEBUG

#include "bpf_host.c"

#include <bpf/config/node.h>

#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

#include "bpf_nat_tuples.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"

PMTU_TEST(snat)
