// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

/* Enable CT debug output */
#undef QUIET_CT

#include "pktgen.h"

/* Enable code paths under test*/
#define ENABLE_IPV4

/* Skip ingress policy checks */
#define USE_BPF_PROG_FOR_INGRESS_POLICY

#include "lib/bpf_lxc.h"

/* Set the LXC source address to be the address of pod one */
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one})
ASSIGN_CONFIG(union v4addr, service_loopback_ipv4, { .be32 = v4_svc_loopback })
ASSIGN_CONFIG(bool, enable_no_service_endpoints_routable, false)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"

/* Setup for this test:
 * +-------ClusterIP--------+    +----------Pod 1---------+
 * | v4_svc_one:tcp_svc_one | -> | v4_pod_one:tcp_svc_one |
 * +------------------------+    +------------------------+
 *            ^                            |
 *            \---------------------------/
 */

static __always_inline int build_packet(struct __ctx_buff *ctx,
					__be16 sport)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)src, (__u8 *)dst,
					  v4_pod_one, v4_svc_one,
					  sport, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

/* Test that a packet for a SVC without any backend does not get dropped (enable_no_endpoints_routable=false). */
SETUP("tc", "tc_lb_no_backend_nonroutable")
int tc_lb_no_backend_nonroutable_setup(struct __ctx_buff *ctx)
{
	int ret;

	ret = build_packet(ctx, tcp_src_two);
	if (ret)
		return ret;

	lb_v4_add_service_with_flags(v4_svc_one, tcp_svc_one, IPPROTO_TCP, 0, 1,
				     SVC_FLAG_LOADBALANCER, 0);

	/* avoid policy drop */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lb_no_backend_nonroutable")
int tc_lb_no_backend_nonroutable_check(const struct __ctx_buff *ctx)
{
	__u32 expected_status = TC_ACT_OK;
	__u32 *status_code;
	void *data_end;
	void *data;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != expected_status)
		test_fatal("status code is %lu, expected %lu", *status_code, expected_status);

	test_finish();
}

/* Test that a packet for a SVC without any backend with eTP=Local gets dropped. */
SETUP("tc", "tc_lb_no_backend_nonroutable_etp")
int tc_lb_no_backend_nonroutable_etp_setup(struct __ctx_buff *ctx)
{
	int ret;

	ret = build_packet(ctx, tcp_src_two);
	if (ret)
		return ret;

	lb_v4_add_service_with_flags(v4_svc_one, tcp_svc_one, IPPROTO_TCP, 0, 1,
				     SVC_FLAG_LOADBALANCER | SVC_FLAG_EXT_LOCAL_SCOPE, 0);

	/* avoid policy drop */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lb_no_backend_nonroutable_etp")
int tc_lb_no_backend_nonroutable_etp_check(const struct __ctx_buff *ctx)
{
	__u32 expected_status = TC_ACT_SHOT;
	__u32 *status_code;
	void *data_end;
	void *data;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != expected_status)
		test_fatal("status code is %lu, expected %lu", *status_code, expected_status);

	test_finish();
}
