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
#include <errno.h>

// Include unity test framework and all the mock libraries.
#include "unity.h"
#include "mocks/mock_helpers.h"
#include "mocks/mock_helpers_skb.h"
#include "mocks/mock_conntrack_stub.h"
#include "fake_maps.h"

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

// Create a fake map
HASHMAP(struct ipv4_ct_tuple, struct ipv4_nat_entry) ipv4_ct_tuple_map;

// Define the compare_func
// We need to wrap the cmp func upon using since memcmp requires the length.
int bpf_compare_ipv4_ct_tuple(const void *a, const void *b)
{
    return __bpf_memcmp_builtin(a, b, sizeof(struct ipv4_ct_tuple));
}

// Define the hash_func
// We need to wrap the cmp func upon using since hashmap_hash_default also
// requires the length.
size_t bpf_hash_ipv4_ct_tuple(const void *key)
{
    return hashmap_hash_default(key, sizeof(struct ipv4_ct_tuple));
}

// Wrap the fake map operations into callbacks
// The "map" argument (the real map) is actually not used, but it has to be
// encoded in the callback functions as required by the stub functions in CMock.
// So we need different callback funcs for different fake maps.
void *ipv4_ct_tuple_map_lookup_elem_callback(const void* map, const void* key, int cmock_num_calls) {
  return fake_lookup_elem((hashmap_void_t *)&ipv4_ct_tuple_map, key);
}

int ipv4_ct_tuple_map_update_elem_callback(const void* map, const void* key, const void* value, __u32 flags, int cmock_num_calls) {
  return fake_update_elem((hashmap_void_t *)&ipv4_ct_tuple_map, key, value, flags,
			 SNAT_MAPPING_IPV4_SIZE);
}

int ipv4_ct_tuple_map_delete_elem_callback(const void* map, const void* key, int cmock_num_calls) {
  return fake_delete_elem((hashmap_void_t *)&ipv4_ct_tuple_map, key);
}

void test_snat_v4_new_mapping() {
    struct __ctx_buff ctx;
    struct ipv4_ct_tuple otuple;
    struct ipv4_nat_entry ostate;
    struct ipv4_nat_target target;

    // Initiate the map.
    fake_init_map((hashmap_void_t *)&ipv4_ct_tuple_map, bpf_hash_ipv4_ct_tuple,
		  bpf_compare_ipv4_ct_tuple);

    get_prandom_u32_ExpectAndReturn(0);
    // Stub the map helpers with the callbacks defined above.
    map_lookup_elem_Stub(ipv4_ct_tuple_map_lookup_elem_callback);
    map_update_elem_Stub(ipv4_ct_tuple_map_update_elem_callback);
    map_update_elem_Stub(ipv4_ct_tuple_map_update_elem_callback);
    ktime_get_ns_ExpectAndReturn(0);
    skb_event_output_IgnoreAndReturn(0);
    // snat_v4_new_mapping will return 0 because rtuple will not be found by
    // snat_v4_lookup and then snat_v4_update will update successfully.
    assert(!snat_v4_new_mapping(&ctx, &otuple, &ostate, &target));
}
