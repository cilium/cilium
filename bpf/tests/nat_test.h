/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// sample unit test program for functions in nat.h
// It contains function definitions for testing "snat_v4_track_local" and
// "snat_v4_process". If other functions in nat.h need to be tested, please add
// the function definitions at the bottom.

#define __BPF_HELPERS_SKB__
#define __BPF_HELPERS__
#define ENABLE_IPV4
#define ENABLE_NODEPORT

#include <stdio.h>
#include <assert.h>
#include <errno.h>

// Include unity test framework and all the mock libraries.
#include "unity.h"
#include "mocks/mock_helpers.h"
#include "mocks/mock_helpers_skb.h"
#include "mocks/mock_conntrack_stub.h"
#include "mocks/mock_common_stub.h"

// To avoid conflict between functions in bpf/builtins.h and string.h, define
// __BPF_BUILTINS__ in conntrack_stub.h to make sure the mock library can be
// compiled without functions in bpf/builtins.h. Undefine __BPF_BUILTINS__ and
// include bpf/builtins.h here.
#undef __BPF_BUILTINS__
#include "bpf/builtins.h"

#include "bpf/ctx/skb.h"
#include "node_config.h"

// To use mock library for functions in lib/conntrack.h, lib/conntrack.h must
// be included as well as mock/mock_conntrack_stub.h.
#include "lib/conntrack.h"

// Define macros like the followings to make sure the original customized
// functions are mapped to the mock functions. To avoid conflict, we do not
// name the mock customized functions as the original name like mock helper
// functions because customized functions are actually implemented. Instead, we
// use "mock_" as the prefix of each mock customized function.
#define ct_lookup4 mock_ct_lookup4
#define ct_create4 mock_ct_create4
#define revalidate_data mock_revalidate_data

// The function to be tested must be included after defining the above macros.
#include "lib/nat.h"

void test_snat_v4_track_local() {
    struct __ctx_buff ctx;
    struct ipv4_ct_tuple tuple;
    struct ipv4_nat_entry state;
    struct ipv4_nat_target target;


    // If there is an error in ct_lookup4, it will return a negative value. We
    // can simply assume it to be -1 because the actual value does not matter.
    mock_ct_lookup4_ExpectAnyArgsAndReturn(-1);
    // So snat_v4_track_local will return exactly the same value which means
    // an error occurs when snat_v4_track_local is looking for the ipv4_ct_tuple.
    assert(snat_v4_track_local(&ctx, &tuple, &state, NAT_DIR_EGRESS, 0,
                               &target) == -1);

    // If ct_lookup4 finds an entry, it will return a positive value. We can
    // also assume it to be 1 because the actual value does not matter.
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

// Define the structs and tailcalls
struct iphdr ip4;
struct icmphdr icmp;

bool revalidate_data_true(struct __ctx_buff *ctx, void **data, void **data_end,
                          void **ip, int cmock_num_calls) {
  *ip = &ip4;
  return true;
}

int skb_load_bytes_icmphdr(struct __sk_buff* skb, __u32 off, const void* to, __u32 len,
                           int cmock_num_calls) {
  *(struct icmphdr *)to = icmp;
  return 0;
}

struct __ctx_buff ctx;
struct ipv4_nat_target target;
struct ipv4_nat_entry state;

void test_snat_v4_process() {
  // Egress
  // The data in ctx is not valid, revalidate_data returns false.
  mock_revalidate_data_ExpectAnyArgsAndReturn(false);
  assert(snat_v4_process(&ctx, NAT_DIR_EGRESS, &target, false) == DROP_INVALID);

  // The protocol of iphdr in ctx is not IPPROTO_TCP, IPPROTO_UDP, or
  // IPPROTO_ICMP.
  ip4.protocol = IPPROTO_IGMP;
  mock_revalidate_data_Stub(revalidate_data_true);
  assert(snat_v4_process(&ctx, NAT_DIR_EGRESS, &target, false) == NAT_PUNT_TO_STACK);

  // The protocol of iphdr in ctx is IPPROTO_ICMP and ctx_load_bytes fails and
  // returns a negative value.
  ip4.protocol = IPPROTO_ICMP;
  skb_load_bytes_ExpectAnyArgsAndReturn(-1);
  assert(snat_v4_process(&ctx, NAT_DIR_EGRESS, &target, false) == DROP_INVALID);

  // The protocol of iphdr in ctx is IPPROTO_TCP and ctx_load_bytes fails and
  // returns a negative value.
  ip4.protocol = IPPROTO_TCP;
  skb_load_bytes_ExpectAnyArgsAndReturn(-1);
  assert(snat_v4_process(&ctx, NAT_DIR_EGRESS, &target, false) == DROP_INVALID);

  // The protocol of iphdr in ctx is IPPROTO_UDP and ctx_load_bytes fails and
  // returns a negative value.
  ip4.protocol = IPPROTO_UDP;
  skb_load_bytes_ExpectAnyArgsAndReturn(-1);
  assert(snat_v4_process(&ctx, NAT_DIR_EGRESS, &target, false) == DROP_INVALID);

  // The protocol of iphdr in ctx is IPPROTO_UDP and snat_v4_handle_mapping
  // returns a negative value.
  skb_load_bytes_ExpectAnyArgsAndReturn(0);
  map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
  mock_ct_lookup4_ExpectAnyArgsAndReturn(-1);
  assert(snat_v4_process(&ctx, NAT_DIR_EGRESS, &target, true) == -1);

  // The protocol of iphdr in ctx is IPPROTO_ICMP and the type of icmphdr is
  // neither ICMP_ECHO nor ICMP_ECHOREPLY.
  ip4.protocol = IPPROTO_ICMP;
  icmp.type = ICMP_DEST_UNREACH;
  skb_load_bytes_Stub(skb_load_bytes_icmphdr);
  assert(snat_v4_process(&ctx, NAT_DIR_EGRESS, &target, false) == DROP_NAT_UNSUPP_PROTO);

  // The protocol of iphdr in ctx is IPPROTO_ICMP and snat_v4_handle_mapping
  // returns a negative value.
  ip4.protocol = IPPROTO_ICMP;
  icmp.type = ICMP_ECHO;
  map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
  mock_ct_lookup4_ExpectAnyArgsAndReturn(-1);
  assert(snat_v4_process(&ctx, NAT_DIR_EGRESS, &target, true) == -1);

  // The protocol of iphdr in ctx is IPPROTO_ICMP and snat_v4_handle_mapping
  // returns NAT_CONTINUE_XLATE, then snat_v4_rewrite_egress returns 0.
  map_lookup_elem_ExpectAnyArgsAndReturn(&state);
  mock_ct_lookup4_ExpectAnyArgsAndReturn(1);
  assert(snat_v4_process(&ctx, NAT_DIR_EGRESS, &target, true) == 0);

  // Ingress
  map_lookup_elem_ExpectAnyArgsAndReturn(&state);
  mock_ct_lookup4_ExpectAnyArgsAndReturn(1);
  assert(snat_v4_process(&ctx, NAT_DIR_INGRESS, &target, true) == 0);
}

