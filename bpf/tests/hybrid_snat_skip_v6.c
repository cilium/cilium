// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_REMOTE_NODE_MASQUERADE 0
#include "hybrid_snat_skip_v6.h"

PKTGEN("tc", "hybrid_snat_v6_same_subnet_hook")
int hybrid_snat_v6_same_subnet_hook_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *tcp;

	pktgen__init(&builder, ctx);
	tcp = pktgen__push_ipv6_tcp_packet(&builder,
					   (__u8 *)mac_one, (__u8 *)mac_two,
					   (__u8 *)v6_pod_one, (__u8 *)v6_node_two,
					   tcp_src_one, tcp_svc_two);
	if (!tcp)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "hybrid_snat_v6_same_subnet_hook")
int hybrid_snat_v6_same_subnet_hook_setup(struct __ctx_buff *ctx)
{
	union v6addr src = IPV6_SRC_ADDR;
	union v6addr dst = IPV6_DST_ADDR;

	subnet_v6_add_entry(&src, 100);
	subnet_v6_add_entry(&dst, 100);
	ipcache_v6_add_entry(&dst, 0, REMOTE_NODE_ID, 0, 0);
	endpoint_v6_add_entry(&src, 0, 0, 0, 0, NULL, NULL);

	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);
	return netdev_send_packet(ctx);
}

CHECK("tc", "hybrid_snat_v6_same_subnet_hook")
int hybrid_snat_v6_same_subnet_hook_check(const struct __ctx_buff *ctx)
{
	union v6addr src = IPV6_SRC_ADDR;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *ip6;

	test_init();
	endpoint_v6_del_entry(&src);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	data += sizeof(*status_code) + sizeof(struct ethhdr);
	if (data + sizeof(*ip6) > data_end)
		test_fatal("ctx doesn't fit IPv6 header");
	ip6 = data;
	assert(ipv6_addr_equals((union v6addr *)&ip6->saddr, &src));

	test_finish();
}

CHECK("tc", "hybrid_snat_v6_same_subnet")
int test_hybrid_snat_v6_same_subnet(struct __ctx_buff *ctx)
{
	test_init();
	assert(run_hybrid_snat_v6_test(ctx, 100, 100) == NAT_PUNT_TO_STACK);
	test_finish();
}

/* These cases continue past the hybrid routing decision. With an empty test
 * context, the later NAT path returns DROP_NAT_NOT_NEEDED, proving that the
 * subnet check did not punt them to the stack.
 */
CHECK("tc", "hybrid_snat_v6_different_subnet")
int test_hybrid_snat_v6_different_subnet(struct __ctx_buff *ctx)
{
	test_init();
	assert(run_hybrid_snat_v6_test(ctx, 100, 200) == DROP_NAT_NOT_NEEDED);
	test_finish();
}

CHECK("tc", "hybrid_snat_v6_zero_subnet")
int test_hybrid_snat_v6_zero_subnet(struct __ctx_buff *ctx)
{
	test_init();
	assert(run_hybrid_snat_v6_test(ctx, 0, 0) == DROP_NAT_NOT_NEEDED);
	test_finish();
}
