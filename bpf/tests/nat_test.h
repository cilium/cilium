/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// sample unit test program for some functions in nat.h
// It contains function definitions for testing "snat_v4_new_mapping" and "snat_v4_track_local".
// It is used to perform unit test on the above two functions.
// "test_snat_v4_new_mapping" uses mock helper functions.
// "test_snat_v4_track_local" uses mock functions in conntrack.h.
// If other functions in nat.h need to be tested, please add the function definitions at the bottom.
// Do not forget to generate mock libraries for functions in conntrack.h before testing.

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

// To avoid conflict between functions in bpf/builtins.h and string.h,
// define __BPF_BUILTINS__ in conntrack_stub.h to make sure the mock library can
// be compiled without functions in bpf/builtins.h. Undefine __BPF_BUILTINS__ and
// include bpf/builtins.h here.
#undef __BPF_BUILTINS__
#include "bpf/builtins.h"

#include "bpf/ctx/skb.h"
#include "node_config.h"

// To use mock library for functions in lib/conntrack.h, lib/conntrack.h must be
// inlcude as well as mock/mock_conntrack_stub.h.
#include "lib/conntrack.h"

// Define macros like the followings to make sure the original customized
// functions are mapped to the mock functions.
#define ct_lookup4 mock_ct_lookup4
#define ct_create4 mock_ct_create4

// The file containing the functions to be tested must be included after
// defining the above macros.
#include "lib/nat.h"

// Undefine the original customized functions.
#undef ct_lookup4
#undef ct_create4

void test_snat_v4_new_mapping() {
  int i;
  struct __ctx_buff ctx;
  struct ipv4_ct_tuple otuple;
  struct ipv4_nat_entry ostate;
  struct ipv4_nat_target target;

  // Stub the helper functions to be used before making the assertion.
  get_prandom_u32_ExpectAndReturn(0);
  map_lookup_elem_IgnoreAndReturn(NULL);
  map_update_elem_IgnoreAndReturn(0);
  ktime_get_ns_ExpectAndReturn(0);
  assert(!snat_v4_new_mapping(&ctx, &otuple, &ostate, &target));  // rtuple is not found in the map during the first retry and is updated successfully.

  // Each time you stub a function, it will only work when the function is first
  // called, which means you need to stub a function exactly the same times as
  // the number of times it will be called.
  get_prandom_u32_ExpectAndReturn(0);
  map_lookup_elem_IgnoreAndReturn(NULL);
  map_update_elem_IgnoreAndReturn(1);
  map_lookup_elem_IgnoreAndReturn(NULL);
  map_update_elem_IgnoreAndReturn(0);
  ktime_get_ns_ExpectAndReturn(0);
  ktime_get_ns_ExpectAndReturn(0);
  assert(!snat_v4_new_mapping(&ctx, &otuple, &ostate, &target));  // rtuple fails to get updated during the first retry and updated successfully during the second retry.

  for (i = 0; i < SNAT_COLLISION_RETRIES; i++) {
    map_lookup_elem_IgnoreAndReturn(NULL);
    map_update_elem_IgnoreAndReturn(1);
    ktime_get_ns_ExpectAndReturn(0);
    get_prandom_u32_ExpectAndReturn(0);
  }
  skb_event_output_IgnoreAndReturn(0);
  assert(snat_v4_new_mapping(&ctx, &otuple, &ostate, &target) == DROP_NAT_NO_MAPPING);  // rtuple keeps failing to get updated until exceeding SNAT_COLLISION_RETRIES.
}

void test_snat_v4_track_local() {
  struct __ctx_buff ctx;
  struct ipv4_ct_tuple tuple;
  struct ipv4_nat_entry state;
  struct ipv4_nat_target target;

  mock_ct_lookup4_ExpectAnyArgsAndReturn(-1);
  assert(snat_v4_track_local(&ctx, &tuple, &state, NAT_DIR_EGRESS, 0, &target) == -1);  // ct_lookup4 returns a negative value so snat_v4_track_local will return that value.

  mock_ct_lookup4_ExpectAnyArgsAndReturn(1);
  assert(!snat_v4_track_local(&ctx, &tuple, &state, NAT_DIR_EGRESS, 0, &target)); // ct_lookup4 returns a nonnegative value other than CT_NEW so snat_v4_track_local will return 0.

  mock_ct_lookup4_ExpectAnyArgsAndReturn(CT_NEW);
  mock_ct_create4_ExpectAnyArgsAndReturn(-1);
  assert(snat_v4_track_local(&ctx, &tuple, &state, NAT_DIR_EGRESS, 0, &target) == -1); // ct_lookup4 returns CT_NEW but ct_create4 returns a negative value so snat_v4_track_local will return that value.

  mock_ct_lookup4_ExpectAnyArgsAndReturn(CT_NEW);
  mock_ct_create4_ExpectAnyArgsAndReturn(0);
  assert(!snat_v4_track_local(&ctx, &tuple, &state, NAT_DIR_EGRESS, 0, &target)); // ct_lookup4 returns CT_NEW and ct_create4 returns a nonnegative value so snat_v4_track_local will return 0.
}

