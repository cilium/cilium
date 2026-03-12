// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* This test is a simplified version of 'tc_nodeport_lb6_nat_lb', solely
 * testing the support for dynamic SNAT feature.
 *
 * It is expected that all tests pass in 'tc_nodeport_lb6_nat_lb', to fully
 * test the nodeport load balancing feature set.
 */

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_HOST_ROUTING

#define CLIENT_IP		{ .addr = v6_ext_node_one_addr }
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		{ .addr = v6_svc_one_addr }
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			{ .addr = v6_node_one_addr }
#define IPV6_DIRECT_ROUTING	LB_IP

#define BACKEND_IP		{ .addr = v6_pod_two_addr }
#define BACKEND_PORT		__bpf_htons(8080)

#define IPV6_SNAT_TARGET_ADDR	{ 0xDE, 0xAD, 0, 0, 0, 0, 0, 0, \
				  0, 0, 0, 0, 0, 0, 0, 1 }
#define IPV6_SNAT_TARGET	{ .addr = IPV6_SNAT_TARGET_ADDR }

#define DEFAULT_IFACE		24

#define fib_lookup mock_fib_lookup

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;

long mock_fib_lookup(__maybe_unused struct __ctx_buff * volatile ctx,
		     const struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;

	return BPF_FIB_LKUP_RET_SUCCESS;
}

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	return CTX_ACT_REDIRECT;
}

/*
 * This is the entire dependency chain required to import bpf/lib/fib.h for
 * mocking below
 */
#define EVENT_SOURCE		CONFIG(host_ep_id)
#define ACTION_UNKNOWN_ICMP6_NS	CTX_ACT_OK
#include "../node_config.h"
#include "../include/bpf/config/node.h"
#include "../include/bpf/config/global.h"
#include "../include/bpf/config/endpoint.h"
#include "../lib/fib.h"

/* mock the fib_lookup_src_v6 library function to always return our
 * test SNAT ip.
 */
#define fib_lookup_src_v6 mock_fib_lookup_src_v6

static __always_inline int
mock_fib_lookup_src_v6(struct __ctx_buff *ctx __maybe_unused,
		       struct in6_addr *src,
		       const struct in6_addr *dst __maybe_unused)
{
	union v6addr target = IPV6_SNAT_TARGET;

	__bpf_memcpy_builtin(src, &target, sizeof(union v6addr));
	return BPF_FIB_LKUP_RET_SUCCESS;
}

#include "lib/bpf_host.h"

#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)
ASSIGN_CONFIG(bool, enable_nodeport_source_lookup, true)

/* Set port ranges to have deterministic source port selection */
#include "nodeport_defaults.h"

/* Test that a SVC request that is LBed to a NAT remote backend using a
 * dynamically resolved source IP.
 * - gets DNATed and SNATed,
 * - gets redirected back out by TC
 */
PKTGEN("tc", "tc_nodeport_lb6_nat_lb_dynamic")
int tc_nodeport_lb6_nat_lb_dynamic_pktgen(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IP;
	union v6addr client_ip = CLIENT_IP;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)&client_ip, (__u8 *)&frontend_ip,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb6_nat_lb_dynamic")
int tc_nodeport_lb6_nat_lb_dynamic_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IP;
	union v6addr backend_ip = BACKEND_IP;
	__u16 revnat_id = 1;

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip, FRONTEND_PORT, 1, 124,
			  &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v6_add_entry(&backend_ip, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb6_nat_lb_dynamic")
int tc_nodeport_lb6_nat_lb_dynamic_check(__maybe_unused const struct __ctx_buff *ctx)
{
	union v6addr snat_target = IPV6_SNAT_TARGET;
	union v6addr backend_ip = BACKEND_IP;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &snat_target))
		test_fatal("src IP hasn't been NATed to dynamic SNAT IP");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip))
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (l4->source == CLIENT_PORT)
		test_fatal("src port hasn't been NATed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	test_finish();
}
