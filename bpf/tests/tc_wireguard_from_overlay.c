// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_WIREGUARD
#define TUNNEL_MODE
#define ENCAP_IFINDEX 4
#define DEST_IFINDEX 5
#define DEST_LXC_ID 0

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define skb_change_type mock_skb_change_type
int mock_skb_change_type(__maybe_unused struct __sk_buff *skb, __u32 type)
{
	if (type != PACKET_HOST)
		return -1;
	return 0;
}

#define skb_get_tunnel_key mock_skb_get_tunnel_key
int mock_skb_get_tunnel_key(__maybe_unused struct __sk_buff *skb,
			    struct bpf_tunnel_key *to,
			    __maybe_unused __u32 size,
			    __maybe_unused __u32 flags)
{
	to->remote_ipv4 = v4_node_one;
	/* 0xfffff is the default SECLABEL */
	to->tunnel_id = 0xfffff;
	return 0;
}

__section_entry
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_OK;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[DEST_LXC_ID] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

static volatile const __u8 *DEST_EP_MAC = mac_three;
static volatile const __u8 *DEST_NODE_MAC = mac_four;

#include "bpf_overlay.c"
ASSIGN_CONFIG(bool, encryption_strict_ingress, true);

#include "lib/endpoint.h"

#define FROM_OVERLAY 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_OVERLAY] = &cil_from_overlay,
	},
};

PKTGEN("tc", "ipv4_wireguard_no_mark_from_overlay")
int ipv4_wireguard_no_mark_from_overlay_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one,
					  (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv4_wireguard_no_mark_from_overlay")
int ipv4_wireguard_no_mark_from_overlay_setup(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "ipv4_wireguard_no_mark_from_overlay")
int ipv4_wireguard_no_mark_from_overlay_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	/* The packet is dropped if it is missing MARK_MAGIC_DECRYPT */
	assert(*status_code == TC_ACT_SHOT);
	/* The mark should be zero, given this test doesn't set it */
	assert(ctx->mark == 0);

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 proto hasn't been set to ETH_P_IP");

	if (memcmp(l2->h_source, (__u8 *)mac_one, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to source ep's mac");

	if (memcmp(l2->h_dest, (__u8 *)mac_two, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to dest ep's mac");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != v4_pod_one)
		test_fatal("src IP was changed");

	if (l3->daddr != v4_pod_two)
		test_fatal("dest IP was changed");

	if (l3->check != bpf_htons(0xf968))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	test_finish();
}

PKTGEN("tc", "ipv4_wireguard_mark_from_overlay")
int ipv4_wireguard_mark_from_overlay_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one,
					  (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv4_wireguard_mark_from_overlay")
int ipv4_wireguard_mark_from_overlay_setup(struct __ctx_buff *ctx)
{
	/* Set the correct mark so that from-overlay doesn't drop the packet */
	ctx->mark = MARK_MAGIC_DECRYPT;
	/* Create an endpoint map entry to force local delivery */
	endpoint_v4_add_entry(v4_pod_two, DEST_IFINDEX, DEST_LXC_ID, 0, 0, 0,
			      (__u8 *)DEST_EP_MAC, (__u8 *)DEST_NODE_MAC);
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "ipv4_wireguard_mark_from_overlay")
int ipv4_wireguard_mark_from_overlay_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	/* The packet is forwarded to stack for local delivery
	 * based on our mocked policy result.
	 */
	assert(*status_code == TC_ACT_OK);
	/* Nothing should have set the mark in the expected code path. */
	assert(ctx->mark == 0);

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 proto hasn't been set to ETH_P_IP");

	if (memcmp(l2->h_source, (__u8 *)DEST_NODE_MAC, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to source ep's mac");

	if (memcmp(l2->h_dest, (__u8 *)DEST_EP_MAC, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to dest ep's mac");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != v4_pod_one)
		test_fatal("src IP was changed");

	if (l3->daddr != v4_pod_two)
		test_fatal("dest IP was changed");

	if (l3->check != bpf_htons(0xfa68))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	test_finish();
}
