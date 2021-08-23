/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// Header of functions to be mocked in common.h.
// It is used to generate corresponding mock functions in common.h.
// If other functions in common.h are needed, please add the function
// declarations at the bottom. To avoid conflict between functions in
// bpf/builtins.h and string.h, define __BPF_BUILTINS__ in conntrack_stub.h to
// make sure the mock library can be compiled without functions in
// bpf/builtins.h. To avoid conflict, we do not name the mock customized
// functions as the original name like mock helper functions because customized
// functions are actually implemented. Instead, we use "mock_" as the prefix of
// each mock customized function.
#define __BPF_BUILTINS__
#include <bpf/ctx/skb.h>
#include "lib/common.h"

bool mock_revalidate_data(struct __ctx_buff *ctx, void **data, void **data_end, void **ip);
