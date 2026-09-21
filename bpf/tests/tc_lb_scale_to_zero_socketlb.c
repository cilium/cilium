// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test.
 *
 * Full socket LB normally turns per-packet LB off. Scale-to-zero relies on it:
 * bpf_sock lets a connection to a service without backends through
 * untranslated, so bpf_lxc has to hold and later translate the packets. This
 * test fails if ENABLE_SCALE_TO_ZERO stops selecting ENABLE_PER_PACKET_LB.
 */
#define ENABLE_IPV4		1
#define ENABLE_SOCKET_LB_FULL	1
#define ENABLE_SCALE_TO_ZERO	1

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		tcp_src_one
#define SVC_IP			v4_svc_one
#define SVC_REVNAT		1

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(bool, enable_scale_to_zero, true)
ASSIGN_CONFIG(bool, enable_no_service_endpoints_routable, true)

#include "lib/lb.h"
#include "lib/policy.h"

PKTGEN("tc", "tc_lb_scale_to_zero_socketlb")
int socketlb_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, SVC_IP,
					  CLIENT_PORT, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lb_scale_to_zero_socketlb")
int socketlb_setup(struct __ctx_buff *ctx)
{
	lb_v4_add_service(SVC_IP, tcp_svc_one, IPPROTO_TCP, 0, SVC_REVNAT);
	lb_track_scale_to_zero(SVC_REVNAT, 0);

	/* Without per-packet LB the packet would be forwarded, not dropped. */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lb_scale_to_zero_socketlb")
int socketlb_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = -DROP_SERVICE_SCALED_TO_ZERO,
		.dir = METRIC_EGRESS,
	};
	__u64 count = 1;
	__u32 *status_code;
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

	test_finish();
}
