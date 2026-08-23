// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6			1
#define SERVICE_NO_BACKEND_RESPONSE	1

#define CLIENT_IP		v6_pod_one
#define CLIENT_PORT		tcp_src_one

#define TRACKED_IP		v6_svc_one
#define TRACKED_REVNAT		1
#define UNTRACKED_IP		v6_svc_two
#define UNTRACKED_REVNAT	2

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(bool, enable_scale_to_zero, true)
/* The default: services without endpoints are rejected right away. The hold
 * has to win over that.
 */
ASSIGN_CONFIG(bool, enable_no_service_endpoints_routable, true)

#include "lib/lb.h"

static __always_inline int build_packet(struct __ctx_buff *ctx,
					const __u8 *svc_ip)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)CLIENT_IP, (__u8 *)svc_ip,
					  CLIENT_PORT, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

static __always_inline void add_service(const __u8 *svc_ip, __u16 rev_nat_index)
{
	union v6addr addr = {};

	memcpy(addr.addr, (void *)svc_ip, 16);
	lb_v6_add_service(&addr, tcp_svc_one, IPPROTO_TCP, 0, rev_nat_index);
}

PKTGEN("tc", "tc_lb_scale_to_zero6_hold")
int hold_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, (const __u8 *)TRACKED_IP);
}

SETUP("tc", "tc_lb_scale_to_zero6_hold")
int hold_setup(struct __ctx_buff *ctx)
{
	add_service((const __u8 *)TRACKED_IP, TRACKED_REVNAT);
	lb_track_scale_to_zero(TRACKED_REVNAT, 0);

	return pod_send_packet(ctx);
}

/* A tracked service without backends holds the packet instead of answering
 * with an ICMPv6 error.
 */
CHECK("tc", "tc_lb_scale_to_zero6_hold")
int hold_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = -DROP_SERVICE_SCALED_TO_ZERO,
		.dir = METRIC_EGRESS,
	};
	__u64 count = 1;
	__u32 *status_code;
	struct ipv6hdr *l3;
	void *data_end;
	void *data;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == TC_ACT_SHOT);

	assert_metrics_count(key, count);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 header out of bounds");

	/* The request is still the original one: no ICMPv6 error was generated. */
	assert(l3->nexthdr == IPPROTO_TCP);

	test_finish();
}

PKTGEN("tc", "tc_lb_scale_to_zero6_untracked")
int untracked_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, (const __u8 *)UNTRACKED_IP);
}

SETUP("tc", "tc_lb_scale_to_zero6_untracked")
int untracked_setup(struct __ctx_buff *ctx)
{
	add_service((const __u8 *)UNTRACKED_IP, UNTRACKED_REVNAT);

	return pod_send_packet(ctx);
}

/* A service that did not opt in keeps being rejected with an ICMPv6 error. */
CHECK("tc", "tc_lb_scale_to_zero6_untracked")
int untracked_check(const struct __ctx_buff *ctx)
{
	__u32 *status_code;
	struct ipv6hdr *l3;
	void *data_end;
	void *data;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 header out of bounds");

	assert(l3->nexthdr == IPPROTO_ICMPV6);

	test_finish();
}
