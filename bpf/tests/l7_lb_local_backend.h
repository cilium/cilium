/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright Authors of Cilium
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_L7_LB

/* Needed variables for the setup */
#define CLIENT_IP		v4_pod_one
#define CLIENT_IP6		v6_pod_one
#define CLIENT_PORT		tcp_src_one

#define BACKEND_IP		v4_svc_one
#define BACKEND_IP6		v6_svc_one
#define BACKEND_PORT		tcp_svc_one

#define CLIENT_EP_ID		127

/* Mockup redirect, so that we track the ifindex used in ctx_redirect calls if needed. */
static volatile __u32 redirect_ifindex;

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex, __u32 flags __maybe_unused)
{
	redirect_ifindex = (__u32)ifindex;
	return CTX_ACT_REDIRECT;
}

/* Mockup tail call dynamic, so that we can use tail_call_egress_policy.
 * We forward declare it, and will be defined once imported bpf_lxc.c.
 */
__section_entry
int cil_lxc_policy_egress(struct __ctx_buff *ctx __maybe_unused);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_cilium_egresscall_policy __section(".maps") = {
	.values = {
		[CLIENT_EP_ID] = &cil_lxc_policy_egress,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_cilium_egresscall_policy, slot);
}

/* BPF_PROG_TEST_RUN are executed with `ctx->ifindex = 1` (loopback device) as in
 * the kernel `bpf_prog_test_run_skb()` function.
 * (see https://github.com/torvalds/linux/blob/0257f64bdac7fdca30fa3cae0df8b9ecbec7733a/net/bpf/test_run.c#L991)
 * To simulate the expected behavior of the code under test, we will set the
 * cilium_host_ifindex accordingly, given we cannot change ctx->ifindex.
 */
#ifdef ENABLE_ROUTING
/* We are tail calling from cilium_host */
# define CILIUM_HOST_IFINDEX 1
#endif

#define CILIUM_NET_IFINDEX 10

#include "lib/bpf_lxc.h"
#include "lib/policy.h"

ASSIGN_CONFIG(__u32, interface_ifindex, 12)

/* Test that a packet received from a L7LB for a local backend gets correctly handled:
 * - in case of per-endpoint routes disabled, packet tail calls from
     cil_from_host, and it will return to stack
 * Given we cannot import both bpf_host and bpf_lxc, in our SETUP functions
 * we will simulate hitting the `tail_call_egress_policy(ctx, lxc_id)` codepath.
 */
PKTGEN("tc", "l7_lb_local_backend_v4")
int l7_lb_local_backend_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_host,
					  CLIENT_IP, BACKEND_IP,
					  CLIENT_PORT, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "l7_lb_local_backend_v4")
int l7_lb_local_backend_v4_setup(struct __ctx_buff *ctx)
{
	/* We need this to allow the packet proceeding. */
	policy_add_egress_allow_all_entry();

	/* Simulate hitting the codepath. */
	return tail_call_egress_policy(ctx, CLIENT_EP_ID);
}

CHECK("tc", "l7_lb_local_backend_v4")
int l7_lb_local_backend_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

#ifdef ENABLE_ROUTING
	assert(*status_code == CTX_ACT_OK);
#endif

	test_finish();
}

/* See IPv4 test for comments. */
PKTGEN("tc", "l7_lb_local_backend_v6")
int l7_lb_local_backend_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_host,
					  (__u8 *)CLIENT_IP6, (__u8 *)BACKEND_IP6,
					  CLIENT_PORT, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "l7_lb_local_backend_v6")
int l7_lb_local_backend_v6_setup(struct __ctx_buff *ctx)
{
	/* We need this to allow the packet proceeding. */
	policy_add_egress_allow_all_entry();

	/* Simulate hitting the codepath. */
	return tail_call_egress_policy(ctx, CLIENT_EP_ID);
}

CHECK("tc", "l7_lb_local_backend_v6")
int l7_lb_local_backend_v6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

#ifdef ENABLE_ROUTING
	assert(*status_code == CTX_ACT_OK);
#endif

	test_finish();
}
