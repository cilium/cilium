// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Policy selection with the per-endpoint policy map. See policy_selection.h. */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include <node_config.h>

#define EFFECTIVE_EP_ID 1
#undef IS_BPF_HOST
#undef HOST_ID

#include <lib/policy.h>
#include "lib/policy.h"

ASSIGN_CONFIG(bool, enable_shared_policy, false)
ASSIGN_CONFIG(bool, enable_policy_accounting, true)

char ____license[] __section("license") = "Dual BSD/GPL";

#define USE_SHARED 0
#include "policy_selection.h"
