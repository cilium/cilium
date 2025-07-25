// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "bpf_nat_icmp6.h"

#define DEBUG

#define ENABLE_DSR
#define ENCAP_IFINDEX 1

#include "bpf_host.c"

#include <bpf/config/node.h>

#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

#include "bpf_nat_tuples.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"

PMTU_TEST(snat)
