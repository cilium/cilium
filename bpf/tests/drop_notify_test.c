// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/*
 * sample unit test program for some functions in drop.h
 * It contains function definitions for testing "send_drop_notify" and "__send_drop_notify".
 * It is used to perform unit test on the above two functions to demonstrate how
 * to handle tailcalls.
 * There is a tailcall at the end of function send_drop_notif which actually
 * calls function __send_drop_notify. We can stub the tailcall and actually call
 * the function with callback.
 * If other functions in drop.h need to be tested, please add the function definitions at the bottom.
 */

#include "common.h"

#define DROP_NOTIFY

/* Include node config */
#include "bpf/ctx/skb.h"
#include "node_config.h"

/* Include lib/metrics.h which contains the definition of ep_tail_call first to */
/* avoid it to be included again in lib/drop.h. */
#include "lib/metrics.h"

/* Forward declare the mock func */
void mock_tail_call(void *ctx, const void *map, __u32 index);

/* Define macros like the following to make sure the original tailcall is redirected */
/* to the mock tailcall function, the last 0 does not matter because we do not */
/* actually use the arguments. */
#define ep_tail_call(a, b) mock_tail_call(a, NULL, 0)

/* The file containing the functions to be tested must be included after */
/* defining the above macros. */
#include "lib/drop.h"

/* Undefine ep_tail_call to stop redirecting to the mock. It is not necessary */
/* unless you would like to include something else that might conflict with the */
/* redirection. */
#undef ep_tail_call

static int __send_drop_notify_res;

/* This is the function we use as the callback when stubbing the tailcall. */
void mock_tail_call(void *ctx, __maybe_unused const void *map, __maybe_unused __u32 index)
{
  /* We can even unit-test the function which is actually called by the tailcall */
  /* within the callback. */
  __send_drop_notify_res = __send_drop_notify(ctx);
}

/* A sample test for function send_drop_notify */
/* It is a demo to show how we handle tailcalls. */
CHECK("tc", "send_drop_notify")
int test_send_drop_notify(struct __ctx_buff ctx)
{
	test_init();

	assert(!send_drop_notify(&ctx, 0, 0, 0, 0, 0, 0));
	assert(!__send_drop_notify_res);

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
