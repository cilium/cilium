// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4		1

#include "lib/bpf_host.h"

ASSIGN_CONFIG(bool, enable_ipv4, true)
ASSIGN_CONFIG(__u32, interface_ifindex, 1)

/* By default (knob off) cil_to_netdev keeps returning TCX_PASS (0), i.e. stock behaviour. */
PKTGEN(PROG_TYPE, "tc_egress_chain_continue_disabled_v4")
int tc_egress_chain_continue_disabled_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_zero, (__u8 *)mac_zero,
					  v4_pod_one, v4_ext_one,
					  tcp_dst_one, tcp_src_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "tc_egress_chain_continue_disabled_v4")
int tc_egress_chain_continue_disabled_v4_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "tc_egress_chain_continue_disabled_v4")
int tc_egress_chain_continue_disabled_v4_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if ((int)*status_code != CTX_ACT_OK)
		test_fatal("unexpected verdict %d, expected %d",
			   (int)*status_code, CTX_ACT_OK);

	/* Without the knob the helper must be the identity function. */
	assert(egress_chain_verdict(CTX_ACT_OK) == CTX_ACT_OK);
	assert(egress_chain_verdict(CTX_ACT_DROP) == CTX_ACT_DROP);
	assert(egress_chain_verdict(CTX_ACT_REDIRECT) == CTX_ACT_REDIRECT);

	test_finish();
}
