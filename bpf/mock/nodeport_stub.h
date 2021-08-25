/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// Header of functions to be mocked in nodeport.h.

#define __BPF_BUILTINS__
#include <bpf/ctx/skb.h>
#include "lib/common.h"

int mock_xlate_dsr_v4(struct __ctx_buff *ctx, const struct ipv4_ct_tuple *tuple, int l4_off, bool has_l4_header);
