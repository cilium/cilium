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

/* The local backend, only populated in the endpoint map by the local delivery
 * tests. A separate client port keeps them from sharing a CT entry with the
 * tests above.
 */
#define BACKEND_EP_ID		128
#define BACKEND_IFINDEX		25
#define LOCAL_CLIENT_PORT	tcp_src_two

/* Mockup redirect, so that we track the ifindex and the flags used in
 * ctx_redirect calls. The flags are what tells redirect_self() (flags 0) apart
 * from the redirect into cilium_host's ingress hook (BPF_F_INGRESS): both land
 * on ifindex 1 under BPF_PROG_TEST_RUN.
 */
static volatile __u32 redirect_ifindex;
static volatile __u32 redirect_flags;

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex, __u32 flags)
{
	redirect_ifindex = (__u32)ifindex;
	redirect_flags = flags;
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

# include "lib/bpf_lxc.h"
#include "lib/endpoint.h"
#include "lib/policy.h"

/* BPF_PROG_TEST_RUN are executed with `ctx->ifindex = 1` (loopback device) as in
 * the kernel `bpf_prog_test_run_skb()` function.
 * (see https://github.com/torvalds/linux/blob/0257f64bdac7fdca30fa3cae0df8b9ecbec7733a/net/bpf/test_run.c#L991)
 * L7 LB traffic is always tail called from cil_from_host, so the ctx sits on
 * cilium_host in both configurations. Set cilium_host_ifindex to the ifindex
 * the test run gives us, given we cannot change ctx->ifindex.
 */
ASSIGN_CONFIG(__u32, cilium_host_ifindex, 1)

ASSIGN_CONFIG(__u32, cilium_net_ifindex, 10)
ASSIGN_CONFIG(__u32, interface_ifindex, 12)

/* !ENABLE_ROUTING is the per-endpoint routes configuration. */
#ifdef ENABLE_ROUTING
ASSIGN_CONFIG(bool, enable_endpoint_routes, false)
#else
ASSIGN_CONFIG(bool, enable_endpoint_routes, true)
#endif

/* Test that a packet received from a L7LB for a local backend gets correctly handled:
 * - in case of per-endpoint routes disabled, packet tail calls from
     cil_from_host, and it will return to stack
 * - in case of per-endpoint routes, packet tail calls from
     cil_from_host as well, and is redirected into cilium_host's ingress hook so
     that the stack routes it.
 * Given we cannot import both bpf_host and bpf_lxc, in our SETUP functions
 * we will simulate hitting the `tail_call_egress_policy(ctx, lxc_id)` codepath.
 */
PKTGEN(PROG_TYPE, "l7_lb_local_backend_v4")
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

SETUP(PROG_TYPE, "l7_lb_local_backend_v4")
int l7_lb_local_backend_v4_setup(struct __ctx_buff *ctx)
{
	/* We need this to allow the packet proceeding. */
	policy_add_egress_allow_all_entry();

	/* Simulate hitting the codepath. */
	return tail_call_egress_policy(ctx, CLIENT_EP_ID);
}

CHECK(PROG_TYPE, "l7_lb_local_backend_v4")
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
#else
	assert(*status_code == CTX_ACT_REDIRECT);

	/* Redirected into cilium_host's ingress hook, not looped back out of
	 * the device the ctx sits on.
	 */
	assert(redirect_ifindex == CONFIG(cilium_host_ifindex));
	assert(redirect_flags == BPF_F_INGRESS);
#endif

	test_finish();
}

/* See IPv4 test for comments. */
PKTGEN(PROG_TYPE, "l7_lb_local_backend_v6")
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

SETUP(PROG_TYPE, "l7_lb_local_backend_v6")
int l7_lb_local_backend_v6_setup(struct __ctx_buff *ctx)
{
	/* We need this to allow the packet proceeding. */
	policy_add_egress_allow_all_entry();

	/* Simulate hitting the codepath. */
	return tail_call_egress_policy(ctx, CLIENT_EP_ID);
}

CHECK(PROG_TYPE, "l7_lb_local_backend_v6")
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
#else
	assert(*status_code == CTX_ACT_REDIRECT);

	assert(redirect_ifindex == CONFIG(cilium_host_ifindex));
	assert(redirect_flags == BPF_F_INGRESS);
#endif

	test_finish();
}

#ifndef ENABLE_ROUTING
/* With per-endpoint routes the endpoint lookup in ipv{4,6}_forward_to_destination()
 * used to be closed for L7 LB traffic unless BPF host routing was enabled, so a
 * local backend fell through to pass_to_stack. Now that the traffic is tail
 * called from cil_from_host, it has to be delivered here instead: check that a
 * backend present in the endpoint map is redirected to its lxc device.
 */
PKTGEN(PROG_TYPE, "l7_lb_local_backend_delivery_v4")
int l7_lb_local_backend_delivery_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_host,
					  CLIENT_IP, BACKEND_IP,
					  LOCAL_CLIENT_PORT, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP(PROG_TYPE, "l7_lb_local_backend_delivery_v4")
int l7_lb_local_backend_delivery_v4_setup(struct __ctx_buff *ctx)
{
	/* We need this to allow the packet proceeding. */
	policy_add_egress_allow_all_entry();

	/* The backend is a local endpoint on this node. */
	endpoint_v4_add_entry(BACKEND_IP, BACKEND_IFINDEX, BACKEND_EP_ID, 0, 0, 0,
			      (const __u8 *)mac_two, (const __u8 *)mac_three);

	/* Simulate hitting the codepath. */
	return tail_call_egress_policy(ctx, CLIENT_EP_ID);
}

CHECK(PROG_TYPE, "l7_lb_local_backend_delivery_v4")
int l7_lb_local_backend_delivery_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v4_del_entry(BACKEND_IP);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	/* Delivered to the backend's lxc device, not to cilium_host. */
	assert(redirect_ifindex == BACKEND_IFINDEX);
	assert(redirect_flags == 0);

	test_finish();
}

/* See IPv4 test for comments. */
PKTGEN(PROG_TYPE, "l7_lb_local_backend_delivery_v6")
int l7_lb_local_backend_delivery_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_host,
					  (__u8 *)CLIENT_IP6, (__u8 *)BACKEND_IP6,
					  LOCAL_CLIENT_PORT, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP(PROG_TYPE, "l7_lb_local_backend_delivery_v6")
int l7_lb_local_backend_delivery_v6_setup(struct __ctx_buff *ctx)
{
	/* We need this to allow the packet proceeding. */
	policy_add_egress_allow_all_entry();

	/* The backend is a local endpoint on this node. */
	endpoint_v6_add_entry((const union v6addr *)BACKEND_IP6, BACKEND_IFINDEX,
			      BACKEND_EP_ID, 0, 0,
			      (const __u8 *)mac_two, (const __u8 *)mac_three);

	/* Simulate hitting the codepath. */
	return tail_call_egress_policy(ctx, CLIENT_EP_ID);
}

CHECK(PROG_TYPE, "l7_lb_local_backend_delivery_v6")
int l7_lb_local_backend_delivery_v6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v6_del_entry((const union v6addr *)BACKEND_IP6);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	assert(redirect_ifindex == BACKEND_IFINDEX);
	assert(redirect_flags == 0);

	test_finish();
}
#endif /* !ENABLE_ROUTING */
