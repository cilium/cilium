// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Policy selection with the shared policy map (cilium_policy_shared). See policy_selection.h. */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include <node_config.h>

#define EFFECTIVE_EP_ID 1
#undef IS_BPF_HOST
#undef HOST_ID

#include <lib/policy.h>
#include "lib/policy.h"

ASSIGN_CONFIG(bool, enable_shared_policy, true)
ASSIGN_CONFIG(bool, enable_policy_accounting, true)

char ____license[] __section("license") = "Dual BSD/GPL";

#define USE_SHARED 1
#include "policy_selection.h"
