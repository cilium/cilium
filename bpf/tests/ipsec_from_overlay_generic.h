/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#define NODE_ID 2333
#define ENCRYPT_KEY 3
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_IPSEC
#define TUNNEL_MODE
#define ENCAP_IFINDEX 4
#define DEST_IFINDEX 5
#define DEST_LXC_ID 200

#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"
#define ROUTER_IP
#define SECLABEL
#define SECLABEL_IPV4
#define SECLABEL_IPV6
#undef ROUTER_IP
#undef SECLABEL
#undef SECLABEL_IPV4
#undef SECLABEL_IPV6

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

__section("mock-handle-policy")
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	/* https://github.com/cilium/cilium/blob/v1.16.0-pre.1/bpf/bpf_lxc.c#L2040 */
#if !defined(ENABLE_ROUTING) && !defined(ENABLE_NODEPORT)
	return TC_ACT_OK;
#else
	return TC_ACT_REDIRECT;
#endif
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
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

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/node.h"

#define FROM_OVERLAY 0
#define ESP_SEQUENCE 69865

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

PKTGEN("tc", "ipv4_not_decrypted_ipsec_from_overlay")
int ipv4_not_decrypted_ipsec_from_overlay_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct ip_esp_hdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)mac_one, (__u8 *)mac_two);

	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;
	l3->saddr = v4_pod_one;
	l3->daddr = v4_pod_two;

	l4 = pktgen__push_default_esphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->spi = ENCRYPT_KEY;
	l4->seq_no = ESP_SEQUENCE;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv4_not_decrypted_ipsec_from_overlay")
int ipv4_not_decrypted_ipsec_from_overlay_setup(struct __ctx_buff *ctx)
{
	/* We need to populate the node ID map because we'll lookup into it on
	 * ingress to find the node ID to use to match against XFRM IN states.
	 */
	node_v4_add_entry(v4_pod_one, NODE_ID, 0);

	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "ipv4_not_decrypted_ipsec_from_overlay")
int ipv4_not_decrypted_ipsec_from_overlay_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct ip_esp_hdr *l4;
	__u8 *payload;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);
	assert(ctx->mark == (MARK_MAGIC_DECRYPT | NODE_ID << 16));

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

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct ip_esp_hdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->spi != ENCRYPT_KEY)
		test_fatal("ESP spi was changed");

	if (l4->seq_no != ESP_SEQUENCE)
		test_fatal("ESP seq was changed");

	payload = (void *)l4 + sizeof(struct ip_esp_hdr);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("paylaod out of bounds\n");

	if (memcmp(payload, default_data, sizeof(default_data)) != 0)
		test_fatal("tcp payload was changed");

	test_finish();
}

PKTGEN("tc", "ipv6_not_decrypted_ipsec_from_overlay")
int ipv6_not_decrypted_ipsec_from_overlay_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct ip_esp_hdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)mac_one, (__u8 *)mac_two);

	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;
	ipv6hdr__set_addrs(l3, (__u8 *)v6_pod_one, (__u8 *)v6_pod_two);

	l4 = pktgen__push_default_esphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->spi = ENCRYPT_KEY;
	l4->seq_no = ESP_SEQUENCE;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv6_not_decrypted_ipsec_from_overlay")
int ipv6_not_decrypted_ipsec_from_overlay_setup(struct __ctx_buff *ctx)
{
	/* To be able to use memcpy, we need to ensure that the memcpy'ed field is
	 * 8B aligned on the stack. Given the existing node_ip struct, the only way
	 * to achieve that is to align a parent tmp struct.
	 * We can't simply use __bpf_memcpy_builtin because that causes a
	 * relocation error in the lib.
	 */
	struct tmp {
		__u32 _;
		struct node_key k;
	} node_ip __align_stack_8 = {};
	struct node_value node_value = {
		.id = NODE_ID,
		.spi = 0,
	};

	/* We need to populate the node ID map because we'll lookup into it on
	 * ingress to find the node ID to use to match against XFRM IN states.
	 */
	node_ip.k.family = ENDPOINT_KEY_IPV6;
	memcpy((__u8 *)&node_ip.k.ip6, (__u8 *)v6_pod_one, 16);
	map_update_elem(&NODE_MAP_V2, &node_ip.k, &node_value, BPF_ANY);

	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "ipv6_not_decrypted_ipsec_from_overlay")
int ipv6_not_decrypted_ipsec_from_overlay_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct ip_esp_hdr *l4;
	__u8 *payload;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);
	assert(ctx->mark == (MARK_MAGIC_DECRYPT | NODE_ID << 16));

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IP");

	if (memcmp(l2->h_source, (__u8 *)mac_one, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to source ep's mac");

	if (memcmp(l2->h_dest, (__u8 *)mac_two, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to dest ep's mac");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (memcmp((__u8 *)&l3->saddr, (__u8 *)v6_pod_one, 16) != 0)
		test_fatal("src IP was changed");

	if (memcmp((__u8 *)&l3->daddr, (__u8 *)v6_pod_two, 16) != 0)
		test_fatal("dest IP was changed");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);

	if ((void *)l4 + sizeof(struct ip_esp_hdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->spi != ENCRYPT_KEY)
		test_fatal("ESP spi was changed");

	if (l4->seq_no != ESP_SEQUENCE)
		test_fatal("ESP seq was changed");

	payload = (void *)l4 + sizeof(struct ip_esp_hdr);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("paylaod out of bounds\n");

	if (memcmp(payload, default_data, sizeof(default_data)) != 0)
		test_fatal("tcp payload was changed");

	test_finish();
}

PKTGEN("tc", "ipv4_decrypted_ipsec_from_overlay")
int ipv4_decrypted_ipsec_from_overlay_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv4_decrypted_ipsec_from_overlay")
int ipv4_decrypted_ipsec_from_overlay_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(v4_pod_two, DEST_IFINDEX, DEST_LXC_ID, 0, 0,
			      (__u8 *)DEST_EP_MAC, (__u8 *)DEST_NODE_MAC);

	ctx->mark = MARK_MAGIC_DECRYPT;
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "ipv4_decrypted_ipsec_from_overlay")
int ipv4_decrypted_ipsec_from_overlay_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;
	__u8 *payload;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == EXPECTED_STATUS_CODE_FOR_DECRYPTED);
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

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_src_one)
		test_fatal("src TCP port was changed");

	if (l4->dest != tcp_svc_one)
		test_fatal("dst TCP port was changed");

	payload = (void *)l4 + sizeof(struct tcphdr);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("paylaod out of bounds\n");

	if (memcmp(payload, default_data, sizeof(default_data)) != 0)
		test_fatal("tcp payload was changed");

	test_finish();
}

PKTGEN("tc", "ipv6_decrypted_ipsec_from_overlay")
int ipv6_decrypted_ipsec_from_overlay_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)v6_pod_one, (__u8 *)v6_pod_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv6_decrypted_ipsec_from_overlay")
int ipv6_decrypted_ipsec_from_overlay_setup(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)v6_pod_two, DEST_IFINDEX, DEST_LXC_ID,
			      0, 0, (__u8 *)DEST_EP_MAC, (__u8 *)DEST_NODE_MAC);

	ctx->mark = MARK_MAGIC_DECRYPT;
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "ipv6_decrypted_ipsec_from_overlay")
int ipv6_decrypted_ipsec_from_overlay_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	__u8 *payload;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == EXPECTED_STATUS_CODE_FOR_DECRYPTED);
	assert(ctx->mark == 0);

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IP");

	if (memcmp(l2->h_source, (__u8 *)DEST_NODE_MAC, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to source ep's mac");

	if (memcmp(l2->h_dest, (__u8 *)DEST_EP_MAC, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to dest ep's mac");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (memcmp((__u8 *)&l3->saddr, (__u8 *)v6_pod_one, 16) != 0)
		test_fatal("src IP was changed");

	if (memcmp((__u8 *)&l3->daddr, (__u8 *)v6_pod_two, 16) != 0)
		test_fatal("dest IP was changed");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_src_one)
		test_fatal("src TCP port was changed");

	if (l4->dest != tcp_svc_one)
		test_fatal("dst TCP port was changed");

	payload = (void *)l4 + sizeof(struct tcphdr);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("paylaod out of bounds\n");

	if (memcmp(payload, default_data, sizeof(default_data)) != 0)
		test_fatal("tcp payload was changed");

	test_finish();
}
