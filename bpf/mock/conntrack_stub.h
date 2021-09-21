/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright Authors of Cilium */

// Header of functions to be mocked in conntrack.h.
// It is used to generate corresponding mock functions in conntrack.h.
// If other functions in conntrack.h are needed, please add the function
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


int mock_ct_lookup4(const void *map, struct ipv4_ct_tuple *tuple, struct __ctx_buff *ctx,
		    int off, int dir, struct ct_state *ct_state, __u32 *monitor);
int mock_ct_create4(const void *map_main, const void *map_related,
		    struct ipv4_ct_tuple *tuple, struct __ctx_buff *ctx,
		    const int dir, const struct ct_state *ct_state,
		    bool proxy_redirect, bool from_l7lb);
