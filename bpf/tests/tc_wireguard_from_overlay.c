// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_WIREGUARD 1
#define ENABLE_IDENTITY_MARK 1
#define TUNNEL_MODE
#define ENCAP_IFINDEX 4
#define DEST_IFINDEX 5
#define DEST_LXC_ID 0

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

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

#include "lib/bpf_overlay.h"
ASSIGN_CONFIG(bool, encryption_strict_ingress, true);

#include "lib/endpoint.h"

PKTGEN("tc", "ipv4_wireguard_no_mark_from_overlay")
int ipv4_wireguard_no_mark_from_overlay_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V4_OVERLAY_TCP_NO_MARK, v4_overlay_tcp_packet);
	BUILDER_PUSH_BUF(builder, V4_OVERLAY_TCP_NO_MARK);

	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP("tc", "ipv4_wireguard_no_mark_from_overlay")
int ipv4_wireguard_no_mark_from_overlay_setup(struct __ctx_buff *ctx)
{
	return overlay_receive_packet(ctx);
}

CHECK("tc", "ipv4_wireguard_no_mark_from_overlay")
int ipv4_wireguard_no_mark_from_overlay_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* The packet is dropped if it is missing MARK_MAGIC_DECRYPT */
	assert(*status_code == CTX_ACT_DROP);

	/* The mark should not have the decrypt flag set */
	assert(!ctx_is_decrypt(ctx));

	/* Verify packet was not modified before being dropped */
	BUF_DECL(EXPECTED_PKT_NO_MARK, v4_overlay_tcp_packet);
	ASSERT_CTX_BUF_OFF("pkt_unmodified", "Ether", ctx, sizeof(__u32),
			   EXPECTED_PKT_NO_MARK, sizeof(BUF(EXPECTED_PKT_NO_MARK)));

	test_finish();
}

PKTGEN("tc", "ipv4_wireguard_mark_from_overlay")
int ipv4_wireguard_mark_from_overlay_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V4_OVERLAY_TCP_WITH_MARK, v4_overlay_tcp_packet);
	BUILDER_PUSH_BUF(builder, V4_OVERLAY_TCP_WITH_MARK);

	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP("tc", "ipv4_wireguard_mark_from_overlay")
int ipv4_wireguard_mark_from_overlay_setup(struct __ctx_buff *ctx)
{
	/* Set the correct mark so that from-overlay doesn't drop the packet */
	ctx->mark = MARK_MAGIC_DECRYPT;
	/* Create an endpoint map entry to force local delivery */
	endpoint_v4_add_entry(v4_pod_two, DEST_IFINDEX, DEST_LXC_ID, 0, 0, 0,
			      (__u8 *)DEST_EP_MAC, (__u8 *)DEST_NODE_MAC);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "ipv4_wireguard_mark_from_overlay")
int ipv4_wireguard_mark_from_overlay_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* The packet is forwarded to stack for local delivery
	 * based on our mocked policy result.
	 */
	assert(*status_code == CTX_ACT_OK);

	/* The decrypt mark should be cleared after processing */
	assert(!ctx_is_decrypt(ctx));

	/* Verify MAC addresses were rewritten */
	BUF_DECL(EXPECTED_PKT_LOCAL_DELIVERY, v4_overlay_tcp_packet_rewritten);
	ASSERT_CTX_BUF_OFF("pkt_modified", "Ether", ctx, sizeof(__u32),
			   EXPECTED_PKT_LOCAL_DELIVERY, sizeof(BUF(EXPECTED_PKT_LOCAL_DELIVERY)));

	test_finish();
}
