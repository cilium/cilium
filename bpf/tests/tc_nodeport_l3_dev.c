// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include <bpf/helpers_skb.h>
#include "pktgen.h"

#define ETH_HLEN		0
#define SECCTX_FROM_IPCACHE	1
#define ENABLE_HOST_ROUTING
#define ENABLE_IPV4
#define ENABLE_IPV6
#define SKIP_ICMPV6_NS_HANDLING

#define TEST_IP_LOCAL		v4_pod_one
#define TEST_IP_REMOTE		v4_pod_two
#define TEST_IPV6_LOCAL		v6_pod_one
#define TEST_IPV6_REMOTE	v6_pod_two
#define TEST_LXC_ID_LOCAL	233

/* We wanted to tail call handle_policy from bpf_lxc, but at present it's
 * impossible to #include both bpf_host.c and bpf_lxc.c at the same time.
 * Therefore, we created a stud, mock_hanle_policy, to simply check if the
 * our skb reaches there.
 */
__section("mock-handle-policy")
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_REDIRECT;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[TEST_LXC_ID_LOCAL] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

static volatile const __u8 *ep_mac = mac_one;
static volatile const __u8 *node_mac = mac_two;

#include "bpf_host.c"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[0] = &cil_from_netdev,
	},
};

PKTGEN("tc", "ipv4_l3_to_l2_fast_redirect")
int ipv4_l3_to_l2_fast_redirect_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* We are building an L3 skb which doesn't have L2 header, so in theory
	 * we need to skip L2 header and set ctx->protocol = bpf_ntohs(ETH_P_IP),
	 * but bpf verifier doesn't allow us to do so, and kernel also doesn't
	 * handle an L3 skb properly (see https://elixir.bootlin.com/linux/v6.2.1/source/net/bpf/test_run.c#L1156).
	 * Therefore we workaround the issue by pushing L2 header in the PKTGEN
	 * and stripping it in the SETUP.
	 */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)node_mac, (__u8 *)ep_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;
	l3->saddr = TEST_IP_REMOTE;
	l3->daddr = TEST_IP_LOCAL;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;
	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "ipv4_l3_to_l2_fast_redirect")
int ipv4_l3_to_l2_fast_redirect_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;

	struct endpoint_info ep_value = {
		.lxc_id = TEST_LXC_ID_LOCAL,
	};

	memcpy(&ep_value.mac, (__u8 *)ep_mac, ETH_ALEN);
	memcpy(&ep_value.node_mac, (__u8 *)node_mac, ETH_ALEN);

	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = TEST_IP_LOCAL,
	};
	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	/* As commented in PKTGEN, now we strip the L2 header. Bpf helper
	 * skb_adjust_room will use L2 header to overwrite L3 header, so we play
	 * a trick to memcpy(ethhdr, iphdr, ETH_HLEN) ahead of skb_adjust_room
	 * so as to guarantee L3 header keeps intact.
	 */
	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);

	tail_call_static(ctx, &entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "ipv4_l3_to_l2_fast_redirect")
int ipv4_l3_to_l2_fast_redirect_check(__maybe_unused const struct __ctx_buff *ctx)
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

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_REDIRECT);

	l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 proto hasn't been set to ETH_P_IP");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to router's mac");

	if (memcmp(l2->h_dest, (__u8 *)ep_mac, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to ep's mac");

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != TEST_IP_REMOTE)
		test_fatal("src IP was changed");

	if (l3->daddr != TEST_IP_LOCAL)
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

PKTGEN("tc", "ipv6_l3_to_l2_fast_redirect")
int ipv6_l3_to_l2_fast_redirect_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* We are building an L3 skb which doesn't have L2 header, so in theory
	 * we need to skip L2 header and set ctx->protocol = bpf_ntohs(ETH_P_IP),
	 * but bpf verifier doesn't allow us to do so, and kernel also doesn't
	 * handle an L3 skb properly (see https://elixir.bootlin.com/linux/v6.2.1/source/net/bpf/test_run.c#L1156).
	 * Therefore we workaround the issue by pushing L2 header in the PKTGEN
	 * and stripping it in the SETUP.
	 */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)node_mac, (__u8 *)ep_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_ipv6hdr(&builder);

	if (!l3)
		return TEST_ERROR;
	ipv6hdr__set_addrs(l3, (__u8 *)TEST_IPV6_REMOTE, (__u8 *)TEST_IPV6_LOCAL);

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;
	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "ipv6_l3_to_l2_fast_redirect")
int ipv6_l3_to_l2_fast_redirect_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;

	struct endpoint_info ep_value = {
		.lxc_id = TEST_LXC_ID_LOCAL,
	};

	memcpy(&ep_value.mac, (__u8 *)ep_mac, ETH_ALEN);
	memcpy(&ep_value.node_mac, (__u8 *)node_mac, ETH_ALEN);

	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV6,
	};
	memcpy(&ep_key.ip6, (__u8 *)TEST_IPV6_LOCAL, 16);
	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	/* As commented in PKTGEN, now we strip the L2 header. Bpf helper
	 * skb_adjust_room will use L2 header to overwrite L3 header, so we play
	 * a trick to memcpy(ethhdr, ipv6hdr, ETH_HLEN) ahead of skb_adjust_room
	 * so as to guarantee L3 header keeps intact.
	 */
	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);

	tail_call_static(ctx, &entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "ipv6_l3_to_l2_fast_redirect")
int ipv6_l3_to_l2_fast_redirect_check(__maybe_unused const struct __ctx_buff *ctx)
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

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_REDIRECT);

	l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IPV6");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to router's mac");

	if (memcmp(l2->h_dest, (__u8 *)ep_mac, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to ep's mac");

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (memcmp((__u8 *)&l3->saddr, (__u8 *)TEST_IPV6_REMOTE, 16) != 0)
		test_fatal("src IP was changed");

	if (memcmp((__u8 *)&l3->daddr, (__u8 *)TEST_IPV6_LOCAL, 16) != 0)
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
