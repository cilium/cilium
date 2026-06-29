// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"
#include "../lib/ipv6_core.h"

/* This test is a simplified version of 'tc_nodeport_lb_nat_lb', solely
 * testing the support for dynamic SNAT feature.
 *
 * It is expected that all tests pass in 'tc_nodeport_lb_nat_lb', to fully
 * test the nodeport load balancing feature set.
 */

/* Enable code paths under test */
#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define ENABLE_NODEPORT 1

#define CLIENT_IP		v4_ext_one
#define CLIENT_IPV6		{ .addr = v6_ext_node_one_addr }
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP_REMOTE	v4_svc_two
#define FRONTEND_IPV6		{ .addr = v6_svc_one_addr }
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_one
#define LB_IPV6			{ .addr = v6_node_one_addr }
#define IPV4_DIRECT_ROUTING	LB_IP
#define IPV6_DIRECT_ROUTING	LB_IPV6

#define IPV4_SNAT_TARGET	0xDEADBEEF
#define IPV6_SNAT_TARGET_ADDR	{ 0xDE, 0xAD, 0, 0, 0, 0, 0, 0, \
				  0, 0, 0, 0, 0, 0, 0, 1 }
#define IPV6_SNAT_TARGET	{ .addr = IPV6_SNAT_TARGET_ADDR }

#define BACKEND_IP_REMOTE	v4_pod_two
#define BACKEND_IPV6		{ .addr = v6_pod_two_addr }
#define BACKEND_PORT		__bpf_htons(8080)

#define DEFAULT_IFACE		24

#define fib_lookup mock_fib_lookup
static __always_inline __maybe_unused long
mock_fib_lookup(__maybe_unused struct __ctx_buff * volatile ctx,
		struct bpf_fib_lookup *params,
		__maybe_unused int plen, __maybe_unused __u32 flags);

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	return CTX_ACT_REDIRECT;
}

#include "lib/bpf_host.h"

long mock_fib_lookup(__maybe_unused struct __ctx_buff * volatile ctx,
		     struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	/* Verifier doesn't know that params is not NULL when verifying this
	 * function separately (see btf_prepare_func_args in kernel/bpf/btf.c).
	 * There is no appropriate EINVAL-like error code in this helper, so
	 * return some arbitrary error.
	 */
	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;

	/* This is the fib request for resolving SNAT, return the target SNAT
	 * address
	 */
	if (flags & BPF_FIB_LOOKUP_SRC) {
		if (params->family == AF_INET) {
			params->ipv4_src = IPV4_SNAT_TARGET;
		} else {
			union v6addr target = IPV6_SNAT_TARGET;

			__bpf_memcpy_builtin((void *)&params->ipv6_src, &target,
					     sizeof(union v6addr));
		}
	}

	return BPF_FIB_LKUP_RET_SUCCESS;
}

#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(bool, enable_bpf_host_routing, true)
ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)
ASSIGN_CONFIG(bool, supports_fib_lookup_src, true)
ASSIGN_CONFIG(bool, enable_nodeport_source_lookup, true)

/* Set port ranges to have deterministic source port selection */
#include "nodeport_defaults.h"

/* packet defined in ./scapy/tc_nodeport_lb4_nat_lb_dynamic_pkt_defs.py */
const __u8 tc_nodeport_lb4_nat_lb_dynamic_pre[] = {
	SCAPY_BUF_BYTES(tc_nodeport_lb4_nat_lb_dynamic_pre)
};

/* packet defined in ./scapy/tc_nodeport_lb4_nat_lb_dynamic_pkt_defs.py */
const __u8 tc_nodeport_lb4_nat_lb_dynamic_post[] = {
	SCAPY_BUF_BYTES(tc_nodeport_lb4_nat_lb_dynamic_post)
};

/* packet defined in ./scapy/tc_nodeport_lb6_nat_lb_dynamic_pkt_defs.py */
const __u8 tc_nodeport_lb6_nat_lb_dynamic_pre[] = {
	SCAPY_BUF_BYTES(tc_nodeport_lb6_nat_lb_dynamic_pre)
};

/* packet defined in ./scapy/tc_nodeport_lb6_nat_lb_dynamic_pkt_defs.py */
const __u8 tc_nodeport_lb6_nat_lb_dynamic_post[] = {
	SCAPY_BUF_BYTES(tc_nodeport_lb6_nat_lb_dynamic_post)
};

/* Test that a SVC request that is LBed to a NAT remote backend using a
 * dynamically resolved source IP.
 * - gets DNATed and SNATed,
 * - gets redirected back out by TC
 */
PKTGEN("tc", "tc_nodeport_lb4_nat_lb_dynamic")
int tc_nodeport_lb4_nat_lb_dynamic_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, tc_nodeport_lb4_nat_lb_dynamic_pre,
			sizeof(tc_nodeport_lb4_nat_lb_dynamic_pre));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb4_nat_lb_dynamic")
int tc_nodeport_lb4_nat_lb_dynamic_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP_REMOTE, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP_REMOTE, FRONTEND_PORT, 1, 124,
			  BACKEND_IP_REMOTE, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v4_add_entry(BACKEND_IP_REMOTE, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb4_nat_lb_dynamic")
int tc_nodeport_lb4_nat_lb_dynamic_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	ASSERT_CTX_BUF_OFF("dynamic_snat_ok", "Ether", ctx, sizeof(__u32),
			   tc_nodeport_lb4_nat_lb_dynamic_post,
			   sizeof(struct ethhdr) + sizeof(struct iphdr));

	test_finish();
}

/* Test that a SVC request that is LBed to a NAT remote backend using a
 * dynamically resolved source IP.
 * - gets DNATed and SNATed,
 * - gets redirected back out by TC
 */
PKTGEN("tc", "tc_nodeport_lb6_nat_lb_dynamic")
int tc_nodeport_lb6_nat_lb_dynamic_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, tc_nodeport_lb6_nat_lb_dynamic_pre,
			sizeof(tc_nodeport_lb6_nat_lb_dynamic_pre));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb6_nat_lb_dynamic")
int tc_nodeport_lb6_nat_lb_dynamic_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IPV6;
	union v6addr backend_ip = BACKEND_IPV6;
	__u16 revnat_id = 2;

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip, FRONTEND_PORT, 1, 124,
			  &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v6_add_entry(&backend_ip, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb6_nat_lb_dynamic")
int tc_nodeport_lb6_nat_lb_dynamic_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	ASSERT_CTX_BUF_OFF("dynamic_snat6_ok", "Ether", ctx, sizeof(__u32),
			   tc_nodeport_lb6_nat_lb_dynamic_post,
			   sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

	test_finish();
}
