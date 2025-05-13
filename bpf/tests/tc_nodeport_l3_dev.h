/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ETH_HLEN 0
#define ENABLE_HOST_ROUTING
#define ENABLE_IPV4
#define ENABLE_IPV6

#define TEST_IP_LOCAL		v4_pod_one
#define TEST_IP_REMOTE		v4_pod_two
#define TEST_IPV6_LOCAL		v6_pod_one
#define TEST_IPV6_REMOTE	v6_pod_two
#define TEST_LXC_ID_LOCAL	233

static volatile const __u8 *ep_mac = mac_one;
static volatile const __u8 *node_mac = mac_two;

#if defined(IS_BPF_WIREGUARD)
# undef IS_BPF_WIREGUARD
# include "bpf_wireguard.c"
# include "lib/endpoint.h"
#elif defined(IS_BPF_HOST)
# undef IS_BPF_HOST

/* We wanted to tail call handle_policy from bpf_lxc, but at present it's
 * impossible to #include both bpf_host.c and bpf_lxc.c at the same time.
 * Therefore, we created a stud, mock_hanle_policy, to simply check if the
 * our skb reaches there.
 */
__section_entry
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

# define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

# include "bpf_host.c"
# include "lib/endpoint.h"
#else
# error "this file supports inclusion only from files with IS_BPF_HOST or IS_BPF_WIREGUARD defined"
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
#if defined(IS_BPF_WIREGUARD)
		[0] = &cil_from_wireguard,
		[1] = &cil_to_wireguard,
#else
		[0] = &cil_from_netdev,
		[1] = &cil_to_netdev,
#endif
	},
};

static __always_inline int
l3_to_l2_fast_redirect_pktgen(struct __ctx_buff *ctx, bool is_ingress, bool is_ipv4)
{
	struct pktgen builder;
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

	if (is_ingress)
		if (is_ipv4)
			l4 = pktgen__push_ipv4_tcp_packet(&builder,
							  (__u8 *)node_mac, (__u8 *)ep_mac,
							  TEST_IP_REMOTE, TEST_IP_LOCAL,
							  tcp_src_one, tcp_svc_one);
		else
			l4 = pktgen__push_ipv6_tcp_packet(&builder,
							  (__u8 *)node_mac, (__u8 *)ep_mac,
							  (__u8 *)TEST_IPV6_REMOTE,
							  (__u8 *)TEST_IPV6_LOCAL,
							  tcp_src_one, tcp_svc_one);
	else
		if (is_ipv4)
			l4 = pktgen__push_ipv4_tcp_packet(&builder,
							  (__u8 *)ep_mac, (__u8 *)node_mac,
							  TEST_IP_LOCAL, TEST_IP_REMOTE,
							  tcp_svc_one, tcp_src_one);
		else
			l4 = pktgen__push_ipv6_tcp_packet(&builder,
							  (__u8 *)ep_mac, (__u8 *)node_mac,
							  (__u8 *)TEST_IPV6_LOCAL,
							  (__u8 *)TEST_IPV6_REMOTE,
							  tcp_svc_one, tcp_src_one);

	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

static __always_inline int
l3_to_l2_fast_redirect_setup(struct __ctx_buff *ctx, bool is_ingress, bool is_ipv4)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;
	struct metrics_key key = {
#if defined(IS_BPF_HOST)
		.reason = is_ingress ? REASON_PLAINTEXT : REASON_FORWARDED,
#elif defined(IS_BPF_WIREGUARD)
		.reason = is_ingress ? REASON_DECRYPTING : REASON_ENCRYPTING,
#endif
		.dir = is_ingress ? METRIC_INGRESS : METRIC_EGRESS,
	};

	map_delete_elem(&cilium_metrics, &key);

	if (is_ipv4)
		endpoint_v4_add_entry(TEST_IP_LOCAL, 0, TEST_LXC_ID_LOCAL, 0, 0,
				      0, (__u8 *)ep_mac, (__u8 *)node_mac);
	else
		endpoint_v6_add_entry((union v6addr *)TEST_IPV6_LOCAL, 0, TEST_LXC_ID_LOCAL, 0, 0,
				      (__u8 *)ep_mac, (__u8 *)node_mac);

	/* As commented in PKTGEN, now we strip the L2 header. Bpf helper
	 * skb_adjust_room will use L2 header to overwrite L3 header, so we play
	 * a trick to memcpy(ethhdr, iphdr, ETH_HLEN) ahead of skb_adjust_room
	 * so as to guarantee L3 header keeps intact.
	 */
	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);

	tail_call_static(ctx, entry_call_map, is_ingress ? 0 : 1);
	return TEST_ERROR;
}

static __always_inline int
ingress_l3_to_l2_fast_redirect_check(__maybe_unused const struct __ctx_buff *ctx, bool is_ipv4)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct tcphdr *l4;
	__u8 *payload;

	struct metrics_value *entry = NULL;
	struct metrics_key key = {
#if defined(IS_BPF_HOST)
		.reason = REASON_PLAINTEXT,
#elif defined(IS_BPF_WIREGUARD)
		.reason = REASON_DECRYPTING,
#endif
		.dir = METRIC_INGRESS,
	};

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

#if defined(IS_BPF_HOST)
	assert(*status_code == TC_ACT_REDIRECT);
#elif defined(IS_BPF_WIREGUARD)
	assert(*status_code == TC_ACT_SHOT);
#endif

	l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (is_ipv4 && l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 proto hasn't been set to ETH_P_IP")

	if (!is_ipv4 && l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IPV6")

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to router's mac");

	if (memcmp(l2->h_dest, (__u8 *)ep_mac, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to ep's mac");

	if (is_ipv4) {
		struct iphdr *l3;

		l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

		if ((void *)l3 + sizeof(struct iphdr) > data_end)
			test_fatal("l3 out of bounds");

		if (l3->saddr != TEST_IP_REMOTE)
			test_fatal("src IP was changed");

		if (l3->daddr != TEST_IP_LOCAL)
			test_fatal("dest IP was changed");

		if (l3->check != bpf_htons(0xfa68))
			test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

		l4 = (void *)l3 + sizeof(struct iphdr);
	} else {
		struct ipv6hdr *l3;

		l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

		if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
			test_fatal("l3 out of bounds");

		if (memcmp((__u8 *)&l3->saddr, (__u8 *)TEST_IPV6_REMOTE, 16) != 0)
			test_fatal("src IP was changed");

		if (memcmp((__u8 *)&l3->daddr, (__u8 *)TEST_IPV6_LOCAL, 16) != 0)
			test_fatal("dest IP was changed");

		l4 = (void *)l3 + sizeof(struct ipv6hdr);
	}

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_src_one)
		test_fatal("src TCP port was changed");

	if (l4->dest != tcp_svc_one)
		test_fatal("dst TCP port was changed");

	if (is_ipv4 && l4->check != bpf_htons(0x589c))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	if (!is_ipv4 && l4->check != bpf_htons(0xdfe3))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	payload = (void *)l4 + sizeof(struct tcphdr);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("paylaod out of bounds\n");

	if (memcmp(payload, default_data, sizeof(default_data)) != 0)
		test_fatal("tcp payload was changed");

	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found")

	__u64 count = 1;

	assert_metrics_count(key, count);

	test_finish();
}

static __always_inline int
egress_l3_to_l2_fast_redirect_check(__maybe_unused const struct __ctx_buff *ctx, bool is_ipv4)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	__u8 *payload;

	struct metrics_value *entry = NULL;
	struct metrics_key key = {
#if defined(IS_BPF_HOST)
		.reason = REASON_FORWARDED,
#elif defined(IS_BPF_WIREGUARD)
		.reason = REASON_ENCRYPTING,
#endif
		.dir = METRIC_EGRESS,
	};

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_OK);

	if (is_ipv4) {
		struct iphdr *l3;

		l3 = data + sizeof(*status_code);

		if ((void *)l3 + sizeof(struct iphdr) > data_end)
			test_fatal("l3 out of bounds");

		if (l3->saddr != TEST_IP_LOCAL)
			test_fatal("src IP was not snatted");

		if (l3->daddr != TEST_IP_REMOTE)
			test_fatal("dest IP was changed");

		l4 = (void *)l3 + sizeof(struct iphdr);
	} else {
		struct ipv6hdr *l3;

		l3 = data + sizeof(*status_code);

		if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
			test_fatal("l3 out of bounds");

		if (memcmp((__u8 *)&l3->saddr, (__u8 *)TEST_IPV6_LOCAL, 16) != 0)
			test_fatal("src IP was changed");

		if (memcmp((__u8 *)&l3->daddr, (__u8 *)TEST_IPV6_REMOTE, 16) != 0)
			test_fatal("dest IP was changed");

		l4 = (void *)l3 + sizeof(struct ipv6hdr);
	}

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_svc_one)
		test_fatal("l4 src port was changed");

	if (l4->dest != tcp_src_one)
		test_fatal("l4 dst port was changed");

	payload = (void *)l4 + sizeof(struct tcphdr);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("payload out of bounds");

	if (memcmp(payload, default_data, sizeof(default_data)) != 0)
		test_fatal("tcp payload was changed")

	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found")

	__u64 count = 1;

	assert_metrics_count(key, count);

	test_finish();
}

PKTGEN("tc", "ingress_ipv4_l3_to_l2_fast_redirect")
int ingress_ipv4_l3_to_l2_fast_redirect_pktgen(struct __ctx_buff *ctx)
{
	return l3_to_l2_fast_redirect_pktgen(ctx, true, true);
}

SETUP("tc", "ingress_ipv4_l3_to_l2_fast_redirect")
int ingress_ipv4_l3_to_l2_fast_redirect_setup(struct __ctx_buff *ctx)
{
	return l3_to_l2_fast_redirect_setup(ctx, true, true);
}

CHECK("tc", "ingress_ipv4_l3_to_l2_fast_redirect")
int ingress_ipv4_l3_to_l2_fast_redirect_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return ingress_l3_to_l2_fast_redirect_check(ctx, true);
}

PKTGEN("tc", "ingress_ipv6_l3_to_l2_fast_redirect")
int ingress_ipv6_l3_to_l2_fast_redirect_pktgen(struct __ctx_buff *ctx)
{
	return l3_to_l2_fast_redirect_pktgen(ctx, true, false);
}

SETUP("tc", "ingress_ipv6_l3_to_l2_fast_redirect")
int ingress_ipv6_l3_to_l2_fast_redirect_setup(struct __ctx_buff *ctx)
{
	return l3_to_l2_fast_redirect_setup(ctx, true, false);
}

CHECK("tc", "ingress_ipv6_l3_to_l2_fast_redirect")
int ingress_ipv6_l3_to_l2_fast_redirect_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return ingress_l3_to_l2_fast_redirect_check(ctx, false);
}

PKTGEN("tc", "egress_ipv4_l3_to_l2_fast_redirect")
int egress_ipv4_l3_to_l2_fast_redirect_pktgen(struct __ctx_buff *ctx)
{
	return l3_to_l2_fast_redirect_pktgen(ctx, false, true);
}

SETUP("tc", "egress_ipv4_l3_to_l2_fast_redirect")
int egress_ipv4_l3_to_l2_fast_redirect_setup(struct __ctx_buff *ctx)
{
	return l3_to_l2_fast_redirect_setup(ctx, false, true);
}

CHECK("tc", "egress_ipv4_l3_to_l2_fast_redirect")
int egress_ipv4_l3_to_l2_fast_redirect_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return egress_l3_to_l2_fast_redirect_check(ctx, true);
}

PKTGEN("tc", "egress_ipv6_l3_to_l2_fast_redirect")
int egress_ipv6_l3_to_l2_fast_redirect_pktgen(struct __ctx_buff *ctx)
{
	return l3_to_l2_fast_redirect_pktgen(ctx, false, false);
}

SETUP("tc", "egress_ipv6_l3_to_l2_fast_redirect")
int egress_ipv6_l3_to_l2_fast_redirect_setup(struct __ctx_buff *ctx)
{
	return l3_to_l2_fast_redirect_setup(ctx, false, false);
}

CHECK("tc", "egress_ipv6_l3_to_l2_fast_redirect")
int egress_ipv6_l3_to_l2_fast_redirect_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return egress_l3_to_l2_fast_redirect_check(ctx, false);
}
