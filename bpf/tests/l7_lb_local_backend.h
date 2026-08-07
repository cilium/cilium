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
#define REUSED_CLIENT_PORT	tcp_src_two

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

# include "lib/bpf_lxc.h"
#include "lib/policy.h"

/* BPF_PROG_TEST_RUN are executed with `ctx->ifindex = 1` (loopback device) as in
 * the kernel `bpf_prog_test_run_skb()` function.
 * (see https://github.com/torvalds/linux/blob/0257f64bdac7fdca30fa3cae0df8b9ecbec7733a/net/bpf/test_run.c#L991)
 * To simulate the expected behavior of the code under test, we will set the
 * cilium_host_ifindex accordingly, given we cannot change ctx->ifindex.
 */
#ifdef ENABLE_ROUTING
/* We are tail calling from cilium_host */
ASSIGN_CONFIG(__u32, cilium_host_ifindex, 1)
#else
/* We are tail calling from bpf_lxc, let's change cilium_host ifindex */
ASSIGN_CONFIG(__u32, cilium_host_ifindex, 2)
#endif

ASSIGN_CONFIG(__u32, cilium_net_ifindex, 10)
ASSIGN_CONFIG(__u32, interface_ifindex, 12)

/* Test that a packet received from a L7LB for a local backend gets correctly handled:
 * - in case of per-endpoint routes disabled, packet tail calls from
     cil_from_host, and it will return to stack
 * - in case of per-endpoint routes, packet tail calls from
     cil_to_container, and it will be hairpinned back to handle ingress policies.
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

	assert(redirect_ifindex == ctx_get_ifindex(ctx));
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

	assert(redirect_ifindex == ctx_get_ifindex(ctx));
#endif

	test_finish();
}

static __always_inline int
l7_lb_ct_pktgen(struct __ctx_buff *ctx, bool ipv6, bool fin)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	if (ipv6)
		l4 = pktgen__push_ipv6_tcp_packet(&builder,
						  (__u8 *)mac_one, (__u8 *)mac_host,
						  (__u8 *)CLIENT_IP6, (__u8 *)BACKEND_IP6,
						  REUSED_CLIENT_PORT, BACKEND_PORT);
	else
		l4 = pktgen__push_ipv4_tcp_packet(&builder,
						  (__u8 *)mac_one, (__u8 *)mac_host,
						  CLIENT_IP, BACKEND_IP,
						  REUSED_CLIENT_PORT, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	if (fin) {
		l4->syn = 0;
		l4->fin = 1;
	}

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
l7_lb_ct_check(void *map, const void *tuple, bool from_l7lb)
{
	struct ct_entry *entry;

	test_init();

	entry = map_lookup_elem(map, tuple);
	if (!entry)
		test_fatal("no CT entry found");

	assert(entry->from_l7lb == from_l7lb);

	test_finish();
}

static __always_inline int
l7_lb_ct_v4_check(bool from_l7lb)
{
	struct ipv4_ct_tuple tuple = {
		.daddr = CLIENT_IP,
		.saddr = BACKEND_IP,
		.dport = BACKEND_PORT,
		.sport = REUSED_CLIENT_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};

	return l7_lb_ct_check(get_ct_map4(&tuple), &tuple, from_l7lb);
}

static __always_inline int
l7_lb_ct_v6_check(bool from_l7lb)
{
	struct ipv6_ct_tuple tuple = {
		.daddr = *(union v6addr *)CLIENT_IP6,
		.saddr = *(union v6addr *)BACKEND_IP6,
		.dport = BACKEND_PORT,
		.sport = REUSED_CLIENT_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};

	return l7_lb_ct_check(get_ct_map6(&tuple), &tuple, from_l7lb);
}

static __always_inline int
l7_lb_ct_setup(struct __ctx_buff *ctx, bool from_proxy)
{
	policy_add_egress_allow_all_entry();
	if (from_proxy)
		return tail_call_egress_policy(ctx, CLIENT_EP_ID);
	return pod_send_packet(ctx);
}

/* A direct SYN reusing an Envoy upstream tuple must take ownership of its CT
 * entry. Later packets from the old Envoy connection must not take it back.
 */
PKTGEN("tc", "l7_lb_ct_v4_1_proxy_syn")
int l7_lb_ct_v4_1_proxy_syn_pktgen(struct __ctx_buff *ctx)
{
	return l7_lb_ct_pktgen(ctx, false, false);
}

SETUP("tc", "l7_lb_ct_v4_1_proxy_syn")
int l7_lb_ct_v4_1_proxy_syn_setup(struct __ctx_buff *ctx)
{
	return l7_lb_ct_setup(ctx, true);
}

CHECK("tc", "l7_lb_ct_v4_1_proxy_syn")
int l7_lb_ct_v4_1_proxy_syn_check(const struct __ctx_buff *ctx __maybe_unused)
{
	return l7_lb_ct_v4_check(true);
}

PKTGEN("tc", "l7_lb_ct_v4_2_direct_syn")
int l7_lb_ct_v4_2_direct_syn_pktgen(struct __ctx_buff *ctx)
{
	return l7_lb_ct_pktgen(ctx, false, false);
}

SETUP("tc", "l7_lb_ct_v4_2_direct_syn")
int l7_lb_ct_v4_2_direct_syn_setup(struct __ctx_buff *ctx)
{
	return l7_lb_ct_setup(ctx, false);
}

CHECK("tc", "l7_lb_ct_v4_2_direct_syn")
int l7_lb_ct_v4_2_direct_syn_check(const struct __ctx_buff *ctx __maybe_unused)
{
	return l7_lb_ct_v4_check(false);
}

PKTGEN("tc", "l7_lb_ct_v4_3_proxy_fin")
int l7_lb_ct_v4_3_proxy_fin_pktgen(struct __ctx_buff *ctx)
{
	return l7_lb_ct_pktgen(ctx, false, true);
}

SETUP("tc", "l7_lb_ct_v4_3_proxy_fin")
int l7_lb_ct_v4_3_proxy_fin_setup(struct __ctx_buff *ctx)
{
	return l7_lb_ct_setup(ctx, true);
}

CHECK("tc", "l7_lb_ct_v4_3_proxy_fin")
int l7_lb_ct_v4_3_proxy_fin_check(const struct __ctx_buff *ctx __maybe_unused)
{
	return l7_lb_ct_v4_check(false);
}

PKTGEN("tc", "l7_lb_ct_v6_1_proxy_syn")
int l7_lb_ct_v6_1_proxy_syn_pktgen(struct __ctx_buff *ctx)
{
	return l7_lb_ct_pktgen(ctx, true, false);
}

SETUP("tc", "l7_lb_ct_v6_1_proxy_syn")
int l7_lb_ct_v6_1_proxy_syn_setup(struct __ctx_buff *ctx)
{
	return l7_lb_ct_setup(ctx, true);
}

CHECK("tc", "l7_lb_ct_v6_1_proxy_syn")
int l7_lb_ct_v6_1_proxy_syn_check(const struct __ctx_buff *ctx __maybe_unused)
{
	return l7_lb_ct_v6_check(true);
}

PKTGEN("tc", "l7_lb_ct_v6_2_direct_syn")
int l7_lb_ct_v6_2_direct_syn_pktgen(struct __ctx_buff *ctx)
{
	return l7_lb_ct_pktgen(ctx, true, false);
}

SETUP("tc", "l7_lb_ct_v6_2_direct_syn")
int l7_lb_ct_v6_2_direct_syn_setup(struct __ctx_buff *ctx)
{
	return l7_lb_ct_setup(ctx, false);
}

CHECK("tc", "l7_lb_ct_v6_2_direct_syn")
int l7_lb_ct_v6_2_direct_syn_check(const struct __ctx_buff *ctx __maybe_unused)
{
	return l7_lb_ct_v6_check(false);
}

PKTGEN("tc", "l7_lb_ct_v6_3_proxy_fin")
int l7_lb_ct_v6_3_proxy_fin_pktgen(struct __ctx_buff *ctx)
{
	return l7_lb_ct_pktgen(ctx, true, true);
}

SETUP("tc", "l7_lb_ct_v6_3_proxy_fin")
int l7_lb_ct_v6_3_proxy_fin_setup(struct __ctx_buff *ctx)
{
	return l7_lb_ct_setup(ctx, true);
}

CHECK("tc", "l7_lb_ct_v6_3_proxy_fin")
int l7_lb_ct_v6_3_proxy_fin_check(const struct __ctx_buff *ctx __maybe_unused)
{
	return l7_lb_ct_v6_check(false);
}
