/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// Header of functions to be mocked in policy.h.

#define __BPF_BUILTINS__
#include <bpf/ctx/skb.h>
#include "lib/common.h"

int mock_policy_can_egress4(struct __ctx_buff *ctx, const struct ipv4_ct_tuple *tuple, __u32 src_id, __u32 dst_id, __u8 *match_type, __u8 *audited);
