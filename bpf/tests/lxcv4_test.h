/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// It contains function definitions for testing "handle_ipv4_from_lxc". If other
// functions in bpf_lxc.c need to be tested, please add the function definitions
// at the bottom.

#define __BPF_HELPERS_SKB__
#define __BPF_HELPERS__

#define ENABLE_IPV4
#define ENABLE_ROUTING 1
#define ENABLE_WIREGUARD
#define ENABLE_NODEPORT
#define ENABLE_DSR


#include <stdio.h>
#include <assert.h>

#include "unity.h"
#include "mocks/mock_helpers.h"
#include "mocks/mock_helpers_skb.h"
#include "mocks/mock_conntrack_stub.h"
#include "mocks/mock_policy_stub.h"
#include "mocks/mock_lb_stub.h"
#include "mocks/mock_l3_stub.h"
#include "mocks/mock_nodeport_stub.h"
#include "mocks/mock_common_stub.h"
#include "mocks/mock_trace_stub.h"

#undef __BPF_BUILTINS__
#include "bpf/builtins.h"

#include "bpf/ctx/skb.h"
#include <ep_config.h>
#include <node_config.h>
#include "lib/conntrack.h"
#include "lib/policy.h"
#include "lib/lb.h"
#include "lib/l3.h"
#include "lib/nodeport.h"
#include "lib/trace.h"


#define ct_lookup4 mock_ct_lookup4
#define ct_create4 mock_ct_create4
#define revalidate_data mock_revalidate_data
#define lb4_extract_key mock_lb4_extract_key
#define lb4_lookup_service mock_lb4_lookup_service
#define lb4_local mock_lb4_local
#define lb4_rev_nat mock_lb4_rev_nat
#define policy_can_egress4 mock_policy_can_egress4
#define ipv4_local_delivery mock_ipv4_local_delivery
#define ipv4_l3 mock_ipv4_l3
#define ep_tail_call(a, b) tail_call(a, b, 0)
#define xlate_dsr_v4 mock_xlate_dsr_v4
#define send_trace_notify mock_send_trace_notify
#include "bpf_lxc.c"


struct __ctx_buff ctx;
__u32 dst_id;
struct iphdr ip4;
struct lb4_service svc;
struct remote_endpoint_info info;
struct endpoint_info ep;
struct ct_state state;

bool revalidate_data_callback(struct __ctx_buff *ctx, void **data, void **data_end,
                          void **ip, int cmock_num_calls) {
  *ip = &ip4;
  return true;
}

int ct_lookup4_callback(const void* map, struct ipv4_ct_tuple* tuple, struct __ctx_buff* ctx, int off, int dir, struct ct_state* ct_state, __u32* monitor, int cmock_num_calls) {
  *ct_state = state;
  return CT_REPLY;
}

void test_handle_ipv4_from_lxc() {

    // revalidate_data returns 0.
    mock_revalidate_data_ExpectAnyArgsAndReturn(0);
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == DROP_INVALID);

    // If IPv4 fragmentation is disabled AND a IPv4 fragmented packet is
    // received, then drop the packet.
    mock_revalidate_data_Stub(revalidate_data_callback);
    ip4.frag_off = 1;
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == DROP_FRAG_NOSUPPORT);

    // is_valid_lxc_src_ipv4 returns 0.
    ip4.frag_off = 0;
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == DROP_INVALID_SIP);

    // lb4_extract_key returns -1.
    ip4.saddr = LXC_IPV4;
    mock_lb4_extract_key_ExpectAnyArgsAndReturn(-1);
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == -1);

    // lb4_local returns -1.
    mock_lb4_extract_key_ExpectAnyArgsAndReturn(-1);
    mock_lb4_lookup_service_ExpectAnyArgsAndReturn(&svc);
    mock_lb4_local_ExpectAnyArgsAndReturn(-1);
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == -1);

    // ct_lookup4 returns -1.
    mock_lb4_extract_key_ExpectAnyArgsAndReturn(DROP_UNKNOWN_L4);
    mock_ct_lookup4_ExpectAnyArgsAndReturn(-1);
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == -1);

    // policy_can_egress4 returns -1.
    info.sec_label = 1;
    mock_lb4_extract_key_ExpectAnyArgsAndReturn(DROP_UNKNOWN_L4);
    mock_ct_lookup4_ExpectAnyArgsAndReturn(CT_NEW);
    map_lookup_elem_ExpectAnyArgsAndReturn(&info);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    skb_event_output_IgnoreAndReturn(0);
    mock_policy_can_egress4_ExpectAnyArgsAndReturn(-1);
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == -1);

    // ct_create4 returns -1.
    mock_lb4_extract_key_ExpectAnyArgsAndReturn(DROP_UNKNOWN_L4);
    mock_ct_lookup4_ExpectAnyArgsAndReturn(CT_NEW);
    map_lookup_elem_ExpectAnyArgsAndReturn(&info);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    mock_policy_can_egress4_ExpectAnyArgsAndReturn(0);
    mock_ct_create4_ExpectAnyArgsAndReturn(-1);
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == -1);

    // ipv4_l3 returns DROP_INVALID.
    ep.flags = 1;
    mock_lb4_extract_key_ExpectAnyArgsAndReturn(DROP_UNKNOWN_L4);
    mock_ct_lookup4_ExpectAnyArgsAndReturn(CT_REOPENED);
    map_lookup_elem_ExpectAnyArgsAndReturn(&info);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    mock_policy_can_egress4_ExpectAnyArgsAndReturn(0);
    map_lookup_elem_ExpectAnyArgsAndReturn(&ep);
    mock_ipv4_l3_ExpectAnyArgsAndReturn(DROP_INVALID);
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == DROP_INVALID);

    // ipv4_local_delivery returns 0.
    ep.flags = 0;
    mock_lb4_extract_key_ExpectAnyArgsAndReturn(DROP_UNKNOWN_L4);
    mock_ct_lookup4_ExpectAnyArgsAndReturn(CT_REOPENED);
    map_lookup_elem_ExpectAnyArgsAndReturn(&info);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    mock_policy_can_egress4_ExpectAnyArgsAndReturn(0);
    map_lookup_elem_ExpectAnyArgsAndReturn(&ep);
    mock_ipv4_local_delivery_ExpectAnyArgsAndReturn(0);
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == 0);

    // CT_REPLY
    // ct_state.node_port != 0
    state.node_port = 1;
    mock_lb4_extract_key_ExpectAnyArgsAndReturn(DROP_UNKNOWN_L4);
    mock_ct_lookup4_Stub(ct_lookup4_callback);
    map_lookup_elem_ExpectAnyArgsAndReturn(&info);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    mock_policy_can_egress4_ExpectAnyArgsAndReturn(0);
    tail_call_Ignore();
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == DROP_MISSED_TAIL_CALL);

    // xlate_dsr_v4 returns -1.
    state.node_port = 0;
    state.dsr = 1;
    mock_lb4_extract_key_ExpectAnyArgsAndReturn(DROP_UNKNOWN_L4);
    map_lookup_elem_ExpectAnyArgsAndReturn(&info);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    mock_policy_can_egress4_ExpectAnyArgsAndReturn(0);
    mock_xlate_dsr_v4_ExpectAnyArgsAndReturn(-1);
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == -1);

    // lb4_rev_nat returns -1.
    state.dsr = 0;
    state.rev_nat_index = 1;
    mock_lb4_extract_key_ExpectAnyArgsAndReturn(DROP_UNKNOWN_L4);
    map_lookup_elem_ExpectAnyArgsAndReturn(&info);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    mock_policy_can_egress4_ExpectAnyArgsAndReturn(0);
    mock_lb4_rev_nat_ExpectAnyArgsAndReturn(-1);
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == -1);

    // The function returns CTX_ACT_OK at the end.
    state.rev_nat_index = 0;
    mock_lb4_extract_key_ExpectAnyArgsAndReturn(DROP_UNKNOWN_L4);
    map_lookup_elem_ExpectAnyArgsAndReturn(&info);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    mock_policy_can_egress4_ExpectAnyArgsAndReturn(0);
    map_lookup_elem_ExpectAnyArgsAndReturn(NULL);
    mock_ipv4_l3_ExpectAnyArgsAndReturn(CTX_ACT_OK);
    mock_send_trace_notify_Ignore();
    assert(handle_ipv4_from_lxc(&ctx, &dst_id) == CTX_ACT_OK);
}
