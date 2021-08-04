/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// sample unit test program for functions in nat.h
// It contains function definitions for testing "snat_v4_track_local".
// "test_snat_v4_track_local" uses mock functions in conntrack.h. If other
// functions in nat.h need to be tested, please add the function definitions
// at the bottom. Do not forget to generate mock libraries for functions in
// conntrack.h before testing.

#define __BPF_HELPERS_SKB__
#define __BPF_HELPERS__
#define ENABLE_IPV4
#define ENABLE_NODEPORT

#define htons bpf_htons
#define ntohs bpf_ntohs

#include <stdio.h>
#include <assert.h>

// Include unity test framework and all the mock libraries.
#include "unity.h"
#include "mock/mock_helpers.h"
#include "mock/mock_helpers_skb.h"
#include "mock/mock_conntrack_stub.h"

// To avoid conflict between functions in bpf/builtins.h and string.h, define
// __BPF_BUILTINS__ in conntrack_stub.h to make sure the mock library can be
// compiled without functions in bpf/builtins.h. Undefine __BPF_BUILTINS__ and
// include bpf/builtins.h here.
#undef __BPF_BUILTINS__
#include "bpf/builtins.h"

#include "bpf/ctx/skb.h"
#include "node_config.h"

// To use mock library for functions in lib/conntrack.h, lib/conntrack.h must
// be inlcude as well as mock/mock_conntrack_stub.h.
#include "lib/conntrack.h"

// Define macros like the followings to make sure the original customized
// functions are mapped to the mock functions. To avoid conflict, we do not
// name the mock customized functions as the original name like mock helper
// functions because customized functions are actually implemented. Instead, we
// use "mock_" as the prefix of each mock customized function.
#define ct_lookup4 mock_ct_lookup4
#define ct_create4 mock_ct_create4

// The file containing the functions to be tested must be included after
// defining the above macros.
#include "lib/nat.h"

// Undefine the original customized functions.
#undef ct_lookup4
#undef ct_create4

void test_snat_v4_track_local() {
    struct __ctx_buff ctx;
    struct ipv4_ct_tuple tuple;
    struct ipv4_nat_entry state;
    struct ipv4_nat_target target;


    // If there is an error in ct_lookup4, it will return a negative value. We
    // can simply assume it to be -1 because the actually value does not matter.
    mock_ct_lookup4_ExpectAnyArgsAndReturn(-1);
    // So snat_v4_track_local will return exactly the same value which means
    // an error occurs when snat_v4_track_local is looking for the ipv4_ct_tuple.
    assert(snat_v4_track_local(&ctx, &tuple, &state, NAT_DIR_EGRESS, 0,
                               &target) == -1);

    // If ct_lookup4 finds an entry, it will return a positive value. We can
    // also assume it to be 1 because the actually value does not matter.
    mock_ct_lookup4_ExpectAnyArgsAndReturn(1);
    // So snat_v4_track_local will return 0 which means snat_v4_track_local
    // successfully tracks ipv4_ct_tuple.
    assert(!snat_v4_track_local(&ctx, &tuple, &state, NAT_DIR_EGRESS, 0,
                                &target));

    // If ct_lookup4 does not find an entry, it will return CT_NEW which equals
    // to zero. Then if ct_create4 fails creating the entry, it will return a
    // negative value which is assumed as -1 since the actual value does not
    // matter.
    mock_ct_lookup4_ExpectAnyArgsAndReturn(CT_NEW);
    mock_ct_create4_ExpectAnyArgsAndReturn(-1);
    // So snat_v4_track_local will return that value which means an error occurs
    // when snat_v4_track_local is trying to create the ipv4_ct_tuple.
    assert(snat_v4_track_local(&ctx, &tuple, &state, NAT_DIR_EGRESS, 0,
                               &target) == -1);

    // If ct_lookup4 does not find an entry, it will return CT_NEW which equals
    // to zero. Then if ct_create4 successfully creates the entry, it will
    // return 0.
    mock_ct_lookup4_ExpectAnyArgsAndReturn(CT_NEW);
    mock_ct_create4_ExpectAnyArgsAndReturn(0);
    // So snat_v4_track_local will return 0 which means snat_v4_track_local
    // successfully creates the ipv4_ct_tuple.
    assert(!snat_v4_track_local(&ctx, &tuple, &state, NAT_DIR_EGRESS, 0,
                                &target));
}
