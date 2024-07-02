// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

#define ENABLE_IPV4

#undef ctx_adjust_hroom
#define ctx_adjust_hroom mock_ctx_adjust_hroom
static __always_inline int mock_ctx_adjust_hroom(struct __ctx_buff *ctx __maybe_unused, __s32 len_diff __maybe_unused,
  __u32 mode __maybe_unused, __u64 flags __maybe_unused);

#include "bpf_host.c"
#include "lib/lb.h"

static __always_inline int mock_ctx_adjust_hroom(struct __ctx_buff *ctx __maybe_unused, __s32 len_diff __maybe_unused,
  __u32 mode __maybe_unused, __u64 flags __maybe_unused)
{
	void *data;
	void *data_end;
	struct ethhdr *l2;
	struct iphdr *outer_l3;
	struct iphdr *inner_l3;
	struct tcphdr *l4;
	__u32 *status_code;

	if (mode != BPF_ADJ_ROOM_MAC)
		return CTX_ACT_DROP;
	if (flags != BPF_F_ADJ_ROOM_FIXED_GSO)
		return CTX_ACT_DROP;
	if (len_diff != -(long)(sizeof(struct iphdr)) )
		return CTX_ACT_DROP;


	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		return CTX_ACT_DROP;

	status_code = data;
	if (*status_code != CTX_ACT_OK)
		return CTX_ACT_DROP;

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		return CTX_ACT_DROP;

	outer_l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)outer_l3 + sizeof(struct iphdr) > data_end)
		return CTX_ACT_DROP;

	inner_l3 = (void *)outer_l3 + sizeof(struct iphdr);
	if ((void *)inner_l3 + sizeof(struct iphdr) > data_end)
		return CTX_ACT_DROP;

	l4 = (void *)inner_l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		return CTX_ACT_DROP;

	memcpy((void *)outer_l3, (void *)inner_l3, sizeof(struct iphdr));
	memcpy((void *)inner_l3, (void *)l4, sizeof(struct tcphdr));
	memset(l4, 0, sizeof(struct tcphdr));

	return CTX_ACT_OK;
}

#define FROM_NETDEV     0
#define LB_IP           v4_ext_one
#define NODE_IP         v4_node_one
#define CLIENT_IP       v4_ext_two
#define LB_VIP          v4_ext_three

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
	},
};


/* Test that a packet with IPIP encapsulation
*  is decapsulated when it reached the loadbalancer service.
*  | eth | LB_IP:NODE_IP | CLIENT_IP:VIP | TCP:tcp_svc_one(80) |
*/
PKTGEN("tc", "ipip_termination_from_host")
int ipip_termination_from_host_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct iphdr *outer_l3;
	struct iphdr *inner_l3;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)mac_one, (__u8 *)mac_two);

	outer_l3 = pktgen__push_default_iphdr(&builder);
	if (!outer_l3)
		return TEST_ERROR;
	outer_l3->protocol = IPPROTO_IPIP;
	outer_l3->saddr = LB_IP;
	outer_l3->daddr = NODE_IP;

	inner_l3 = pktgen__push_default_iphdr(&builder);
	if (!inner_l3)
		return TEST_ERROR;
	inner_l3->saddr = CLIENT_IP;
	inner_l3->daddr = LB_VIP;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipip_termination_from_host")
int ipip_termination_from_host_setup(__maybe_unused struct __ctx_buff *ctx)
{
	lb_v4_add_service_with_flags(LB_VIP, tcp_svc_one, 1, 1, SVC_FLAG_LOADBALANCER, 0);
	lb_v4_add_backend(LB_VIP, tcp_svc_one, 1, 124, v4_pod_one, tcp_dst_one, IPPROTO_TCP, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);

	/* Fail if we didn't jump*/
	return TEST_ERROR;
}

CHECK("tc", "ipip_termination_from_host")
int ipip_termination_from_host_check(__maybe_unused struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	struct ethhdr *l2;
	struct iphdr *outer_l3;
	struct iphdr *inner_l3;
	struct tcphdr *l4;
	__u32 *status_code;

	int ret;
	int l4_off;
	struct ipv4_ct_tuple tuple = {};
	struct lb4_key key = {};
	struct lb4_service *svc;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	outer_l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)outer_l3 + sizeof(struct iphdr) > data_end)
		test_fatal("outer_l3 out of bounds");


	inner_l3 = (void *)outer_l3 + sizeof(struct iphdr);
	if ((void *)inner_l3 + sizeof(struct iphdr) > data_end)
		test_fatal("inner_l3 out of bounds");


	l4 = (void *)inner_l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	/* Test decap_ipip() */
	ret = lb4_extract_tuple(ctx, inner_l3, (void *)inner_l3 - data, &l4_off, &tuple);
	if (IS_ERR(ret)) {
		test_fatal("lb4_extract_tuple() failed\n");
	}

	lb4_fill_key(&key, &tuple);

	svc = lb4_lookup_service(&key, false);
	if (!svc) {
		test_fatal("svc is not found\n");
	} else {
		if (!lb4_svc_is_loadbalancer(svc)) {
			test_fatal("svc is not loadbalancer\n");
		}
		ret = ctx_adjust_hroom(ctx, -ipv4_hdrlen(outer_l3), BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO);
		if (IS_ERR(ret)) {
			test_fatal("ctx_adjust_hroom() failed\n");
		}
	}

	/* Verify decapsulation */
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	outer_l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)outer_l3 + sizeof(struct iphdr) > data_end)
		test_fatal("outer_l3 out of bounds");

	if (outer_l3->saddr != CLIENT_IP)
		test_fatal("outer_l3->saddr is not CLIENT_IP\n");
	if (outer_l3->daddr != LB_VIP)
		test_fatal("outer_l3->daddr is not LB_VIP\n");

	test_finish();
}
