// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define IS_BPF_WIREGUARD 1
#define ENABLE_WIREGUARD

#include "common.h"

#include <bpf/ctx/skb.h>
#include <bpf/helpers_skb.h>
#include "pktgen.h"

#define ETH_HLEN		0
#define SECCTX_FROM_IPCACHE	1
#define ENABLE_HOST_ROUTING
#define ENABLE_IPV4

#define TEST_IP_LOCAL		v4_pod_one
#define TEST_IP_REMOTE		v4_pod_two

static volatile const __u8 *ep_mac = mac_two;
static volatile const __u8 *node_mac = mac_one;

#include "bpf_wireguard.c"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[0] = &cil_to_wireguard,
	},
};

PKTGEN("tc", "wireguard_egress_metrics")
int wireguard_egress_metrics_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* See comment in tc_nodeport_l3_dev.c */
	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)node_mac, (__u8 *)ep_mac,
					  TEST_IP_LOCAL, TEST_IP_REMOTE,
					  tcp_svc_one, tcp_src_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "wireguard_egress_metrics")
int wireguard_egress_metrics_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;

	/* See comment in tc_nodeport_l3_dev.c */
	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);

	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "wireguard_egress_metrics")
int wireguard_egress_metrics_check(__maybe_unused const struct __ctx_buff *ctx)
{
	struct metrics_value *entry = NULL;
	struct metrics_key key = {};

	test_init();

	/* Check that the packet was recorded in the metrics. */
	key.reason = REASON_ENCRYPTING;
	key.dir = METRIC_EGRESS;

	entry = map_lookup_elem(&METRICS_MAP, &key);
	if (!entry)
		test_fatal("metrics entry not found")

	__u64 count = 1;

	assert_metrics_count(key, count);

	test_finish();
}
