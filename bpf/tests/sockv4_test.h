/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// It contains function definitions for testing "__sock4_xlate_fwd". If other
// functions in bpf_sock.c need to be tested, please add the function
// definitions at the bottom.

#define __BPF_HELPERS_SKB__
#define __BPF_HELPERS__

#define ENABLE_IPV4
#define ENABLE_SESSION_AFFINITY

#include <stdio.h>
#include <assert.h>

#include "unity.h"
#include "mocks/mock_helpers.h"
#include "mocks/mock_helpers_skb.h"

#undef __BPF_BUILTINS__
#include "bpf/builtins.h"

#include "bpf/ctx/skb.h"

#include "bpf_sock.c"

struct bpf_sock_addr ctx;
struct bpf_sock_addr ctx_full;
struct lb4_service svc;
struct lb4_backend backend;
struct lb_affinity_val val;

void test___sock4_xlate_fwd() {

    // udp_only is set to false and sock_proto_enabled returns false.
    assert(__sock4_xlate_fwd(&ctx, &ctx_full, false) == -ENOTSUP);

    // lb4_lookup_service return false.
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    assert(__sock4_xlate_fwd(&ctx, &ctx_full, true) == -ENXIO);

    // svc is found and __lb4_lookup_backend_slot returns 0.
    svc.count = 1;
    svc.flags = SVC_FLAG_AFFINITY;
    val.last_used = 1;
    val.backend_id = 1;
    map_lookup_elem_ExpectAnyArgsAndReturn(&svc);
    map_lookup_elem_ExpectAnyArgsAndReturn(&val);
    ktime_get_ns_ExpectAndReturn(0);
    map_lookup_elem_ExpectAnyArgsAndReturn(&svc);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    map_update_elem_ExpectAnyArgsAndReturn(0);
    assert(__sock4_xlate_fwd(&ctx, &ctx_full, true) == -ENOENT);

    // backend_slot is found and backend is not found.
    map_lookup_elem_ExpectAnyArgsAndReturn(&svc);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    map_lookup_elem_ExpectAnyArgsAndReturn(&svc);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    map_update_elem_ExpectAnyArgsAndReturn(0);
    assert(__sock4_xlate_fwd(&ctx, &ctx_full, true) == -ENOENT);

    // backend is found
    map_lookup_elem_ExpectAnyArgsAndReturn(&svc);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    map_lookup_elem_ExpectAnyArgsAndReturn(&svc);
    map_lookup_elem_ExpectAnyArgsAndReturn(&backend);
    ktime_get_ns_ExpectAndReturn(0);
    map_update_elem_ExpectAnyArgsAndReturn(0);
    assert(__sock4_xlate_fwd(&ctx, &ctx_full, true) == 0);
}
