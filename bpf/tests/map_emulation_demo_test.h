/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// demo on how to unit-test with user-space map emulation library

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
#include "fake_maps.h"

#include "bpf/ctx/skb.h"
#include "node_config.h"

#include "lib/nat.h"

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
  return fake_lookup_elem(&ipv4_ct_tuple_map, key);
}

int ipv4_ct_tuple_map_update_elem_callback(const void* map, const void* key, const void* value, __u32 flags, int cmock_num_calls) {
  return fake_update_elem(&ipv4_ct_tuple_map, key, value, flags, SNAT_MAPPING_IPV4_SIZE);
}

int ipv4_ct_tuple_map_delete_elem_callback(const void* map, const void* key, int cmock_num_calls) {
  return fake_delete_elem(&ipv4_ct_tuple_map, key);
}

void test_snat_v4_new_mapping() {
    struct __ctx_buff ctx;
    struct ipv4_ct_tuple otuple;
    struct ipv4_nat_entry ostate;
    struct ipv4_nat_target target;

    // Initiate the map.
    fake_init_map(&ipv4_ct_tuple_map, bpf_hash_ipv4_ct_tuple, bpf_compare_ipv4_ct_tuple);

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

