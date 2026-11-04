// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "l7_lb_local_backend.h"

ASSIGN_CONFIG(bool, enable_bpf_routing, true)
/* BPF_PROG_TEST_RUN are executed with `ctx->ifindex = 1` (loopback device) as in
 * the kernel `bpf_prog_test_run_skb()` function.
 * (see https://github.com/torvalds/linux/blob/0257f64bdac7fdca30fa3cae0df8b9ecbec7733a/net/bpf/test_run.c#L991)
 * To simulate the expected behavior of the code under test, we will set the cilium_host_ifindex
 * accordingly, given we cannot change ctx->ifindex.
 * We are tail calling from cilium_host.
 */
ASSIGN_CONFIG(__u32, cilium_host_ifindex, 1)
