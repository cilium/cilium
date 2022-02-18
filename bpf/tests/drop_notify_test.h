/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

// sample unit test program for some functions in drop.h
// It contains function definitions for testing "send_drop_notify" and "__send_drop_notify".
// It is used to perform unit test on the above two functions to demonstrate how
// to handle tailcalls.
// There is a tailcall at the end of function send_drop_notif which actually
// calls function __send_drop_notify. We can stub the tailcall and actually call
// the function with callback.
// If other functions in drop.h need to be tested, please add the function definitions at the bottom.

#define __BPF_HELPERS_SKB__
#define __BPF_HELPERS__
#define DROP_NOTIFY

#include <stdio.h>
#include <assert.h>

// Include unity test framework and all the mock libraries.
#include "unity.h"
#include "mocks/mock_helpers.h"
#include "mocks/mock_helpers_skb.h"

#include "bpf/ctx/skb.h"
#include "node_config.h"

// Include lib/metrics.h which contains the definition of ep_tail_call first to
// avoid it to be included again in lib/drop.h.
#include "lib/metrics.h"

// Define macros like the followings to make sure the original tailcall is redirected
// to the mock tailcall function, the last 0 does not matter because we do not
// actually use the arguments.
#define ep_tail_call(a, b) tail_call(a, NULL, 0)

// The file containing the functions to be tested must be included after
// defining the above macros.
#include "lib/drop.h"

// Undefine ep_tail_call to stop redirecting to the mock. It is not necessary
// unless you would like to include something else that might conflict with the
// redirection.
#undef ep_tail_call


// This is the function we use as the callback when stubbing the tailcall.
void __send_drop_notify_tailcall(void* ctx, const void* map, __u32 index, int cmock_num_calls) {

  // We can even unit-test the function which is actually called by the tailcall
  // within the callback.
  skb_event_output_IgnoreAndReturn(0);
  assert(!__send_drop_notify(ctx));
}

// A sample test for function send_drop_notify
// It is a demo to show how we handle tailcalls.
void test_send_drop_notify() {
  struct __ctx_buff ctx;

  // Set the expectations for the helpers functions called before the tailcall.
  map_lookup_elem_IgnoreAndReturn(NULL);
  map_update_elem_IgnoreAndReturn(0);

  // We stub the tailcall here by calling callback.
  tail_call_Stub(__send_drop_notify_tailcall);
  assert(!send_drop_notify(&ctx, 0, 0, 0, 0, 0, 0));
}

