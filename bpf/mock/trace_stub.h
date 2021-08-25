/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// Header of functions to be mocked in trace.h.

#define __BPF_BUILTINS__
#include <bpf/ctx/skb.h>
#include "lib/common.h"

void mock_send_trace_notify(struct __ctx_buff *ctx, __u8 obs_point, __u32 src, __u32 dst, __u16 dst_id, __u32 ifindex, __u8 reason, __u32 monitor);
