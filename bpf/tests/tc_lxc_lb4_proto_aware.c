// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_HOST_ROUTING

#define CLIENT_IP			v4_pod_one
#define CLIENT_PORT			__bpf_htons(33000)

#define FRONTEND_IP			v4_svc_one
#define FRONTEND_PORT		__bpf_htons(53)

#define BACKEND_PORT		__bpf_htons(8080)
#define BACKEND_IDENTITY	112233

#include <bpf_lxc.c>

#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"

#define FROM_CONTAINER	0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_CONTAINER] = &cil_from_container,
	},
};

static __always_inline int setup(struct __ctx_buff *ctx)
{
	lb_v4_add_service_with_proto(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, 1);
	lb_v4_add_service_with_proto(FRONTEND_IP, FRONTEND_PORT, IPPROTO_UDP, 1, 2);

	/* TCP -> pod_two */
	/* UDP -> pod_three */

	lb_v4_add_backend_with_proto(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP,
				     1, 124, v4_pod_two, BACKEND_PORT, IPPROTO_TCP, 0);
	lb_v4_add_backend_with_proto(FRONTEND_IP, FRONTEND_PORT, IPPROTO_UDP,
				     1, 125, v4_pod_three, BACKEND_PORT, IPPROTO_UDP, 0);

	ipcache_v4_add_entry(v4_pod_two, 0, BACKEND_IDENTITY, 0, 0);
	ipcache_v4_add_entry(v4_pod_three, 0, BACKEND_IDENTITY, 0, 0);

	policy_add_egress_allow_entry(BACKEND_IDENTITY, IPPROTO_TCP, BACKEND_PORT);
	policy_add_egress_allow_entry(BACKEND_IDENTITY, IPPROTO_UDP, BACKEND_PORT);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, FROM_CONTAINER);

	/* Fail if we didn't jump */
	return TEST_ERROR;
}

static __always_inline int check(const struct __ctx_buff *ctx, __be32 addr, __u8 proto)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	test_log("Status code: %d", *status_code);
	assert(*status_code == CTX_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->daddr != addr)
		test_fatal("dst IP isn't the right backend IP");

	if (l3->protocol != proto)
		test_fatal("doesn't have correct L4 protocol");

	test_finish();
}

SETUP("tc", "tc_lxc_lb4_tcp")
int lxc_lb4_tcp_setup(struct __ctx_buff *ctx)
{
	return setup(ctx);
}

PKTGEN("tc", "tc_lxc_lb4_tcp")
int lxc_lb4_tcp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  CLIENT_IP, FRONTEND_IP,
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

CHECK("tc", "tc_lxc_lb4_tcp")
int lxc_lb4_tcp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check(ctx, v4_pod_two, IPPROTO_TCP);
}

SETUP("tc", "tc_lxc_lb4_udp")
int lxc_lb4_udp_setup(struct __ctx_buff *ctx)
{
	return setup(ctx);
}

PKTGEN("tc", "tc_lxc_lb4_udp")
int lxc_lb4_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  CLIENT_IP, FRONTEND_IP,
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

CHECK("tc", "tc_lxc_lb4_udp")
int lxc_lb4_udp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check(ctx, v4_pod_three, IPPROTO_UDP);
}
