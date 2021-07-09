/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// Header of functions to be mocked in conntrack.h.
// It is used to generate corresponding mock functions in conntrack.h.
// If other functions in conntrack.h are needed, please add the function declarations at the bottom.
// After adding, generate mock functions again with "$ruby cmock.rb -obpf.yaml conntrack_vacant.h".

#define __BPF_BUILTINS__
#include <bpf/ctx/skb.h>
#include "lib/common.h"


int mock_ct_lookup4(const void *map, struct ipv4_ct_tuple *tuple, struct __ctx_buff *ctx, int off, int dir, struct ct_state *ct_state, __u32 *monitor);
int mock_ct_create4(const void *map_main, const void *map_related, struct ipv4_ct_tuple *tuple, struct __ctx_buff *ctx, const int dir, const struct ct_state *ct_state, bool proxy_redirect);
