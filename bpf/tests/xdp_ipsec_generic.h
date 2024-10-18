/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
#define ENABLE_IPV4
#define ENABLE_IPSEC
#define ENABLE_IPSEC_RPS
#define ENABLE_CPU_MAP

#include <bpf/ctx/xdp.h>
#include "common.h"
#include "node_config.h"
#include "lib/maps.h"

#include "lib/ipsecrps.h"
#include "pktgen.h"

#define ctx_redirect_map mock_ctx_redirect_map

int mock_ctx_redirect_map(const void *map __maybe_unused, __u32 key __maybe_unused,
			  __u32 flags __maybe_unused)
{
	return CTX_ACT_REDIRECT;
}

#include "bpf_xdp.c"

#define FROM_NETDEV 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_xdp_entry,
	},
};

#define ENCRYPT_KEY	 3
#define PKT_HASH 0xdeadbeef
#define ESP_SEQUENCE 69865

/* Test that an ESP packet sent from a pod on one node
 * to a pod on another node, using native routing, can
 * be successfully handled by the IPSec RPS logic in the
 * XDP ingress program:
 *   1. The SPI is restored to the correct value.
 *   2. A CPU redirect occurs.
 */

PKTGEN("xdp", "ipv4_ipsec_from_net_xdp")
int ipv4_ipsec_from_net_xdp_pktgen(struct __ctx_buff *ctx)
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
	l4->spi = (bpf_htonl(ENCRYPT_KEY) & IPSEC_RPS_SPI_MASK) | (PKT_HASH & IPSEC_RPS_HASH_MASK);
	l4->seq_no = ESP_SEQUENCE;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("xdp", "ipv4_ipsec_from_net_xdp")
int ipv4_ipsec_from_net_xdp_setup(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* If we don't jump, then fail */
	return TEST_ERROR;
}

CHECK("xdp", "ipv4_ipsec_from_net_xdp")
int ipv4_ipsec_from_net_xdp_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct ip_esp_hdr *l4;
	__u8 *payload;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx_data_end(ctx);

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("invalid status code: %d", *status_code);

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

	if (l3->check != bpf_htons(0xf948))
		test_fatal("L3 checksum is invalid: %d", bpf_htons(l3->check));

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct ip_esp_hdr) > data_end)
		test_fatal("l4 out of bounds");

	if (bpf_ntohl(l4->spi) != ENCRYPT_KEY)
		test_fatal("ESP spi was incorrectly set: %lx != %lx\n", l4->spi, ENCRYPT_KEY);

	if (l4->seq_no != ESP_SEQUENCE)
		test_fatal("ESP seq was changed");

	payload = (void *)l4 + sizeof(struct ip_esp_hdr);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("paylaod out of bounds\n");

	if (memcmp(payload, default_data, sizeof(default_data)) != 0)
		test_fatal("tcp payload was changed");

	test_finish();
}
