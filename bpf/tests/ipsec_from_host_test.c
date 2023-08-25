// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"
#define ROUTER_IP
#include "config_replacement.h"
#undef ROUTER_IP

#define NODE_ID 2333
#define ENCRYPT_KEY 3
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_IPSEC
#define TUNNEL_MODE
#define HAVE_ENCAP
#define ENCAP_IFINDEX 4
#define SECCTX_FROM_IPCACHE 1

#define skb_set_tunnel_key mock_skb_set_tunnel_key
#define ctx_redirect mock_ctx_redirect

int mock_skb_set_tunnel_key(__maybe_unused struct __sk_buff *skb,
			    const struct bpf_tunnel_key *from,
			    __maybe_unused __u32 size,
			    __maybe_unused __u32 flags)
{
	/* 0xfffff is the default SECLABEL */
	if (from->tunnel_id != 0xfffff)
		return -1;
	if (from->local_ipv4 != 0)
		return -2;
	if (from->remote_ipv4 != bpf_htonl(v4_node_two))
		return -3;
	return 0;
}

int mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused, int ifindex, __u32 flags)
{
	if (ifindex != ENCAP_IFINDEX)
		return -1;
	if (flags != 0)
		return -2;
	return CTX_ACT_REDIRECT;
}

#include "bpf_host.c"

#include "lib/ipcache.h"

#define FROM_HOST 0
#define ESP_SEQUENCE 69865

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_HOST] = &cil_from_host,
	},
};

PKTGEN("tc", "ipv4_ipsec_from_host")
int ipv4_ipsec_from_host_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "ipv4_ipsec_from_host")
int ipv4_ipsec_from_host_setup(struct __ctx_buff *ctx)
{
	/* This is the ipcache entry for the CiliumInternalIP of the remote node.
	 * It allows us to lookup the tunnel endpoint from the outer destination IP
	 * address of the ESP packet. The CiliumInternalIPs are used for that outer
	 * header.
	 */
	ipcache_v4_add_entry(v4_pod_two, 0, 233, v4_node_two, 0);

	set_encrypt_key_mark(ctx, ENCRYPT_KEY, NODE_ID);
	set_identity_meta(ctx, SECLABEL_IPV4);
	tail_call_static(ctx, &entry_call_map, FROM_HOST);
	return TEST_ERROR;
}

CHECK("tc", "ipv4_ipsec_from_host")
int ipv4_ipsec_from_host_check(__maybe_unused const struct __ctx_buff *ctx)
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
	assert(*status_code == CTX_ACT_REDIRECT);

	assert(ctx->mark == 0);
	assert(ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY) == 0);

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

PKTGEN("tc", "ipv6_ipsec_from_host")
int ipv6_ipsec_from_host_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "ipv6_ipsec_from_host")
int ipv6_ipsec_from_host_setup(struct __ctx_buff *ctx)
{
	/* See comment for IPv4 counterpart. */
	ipcache_v6_add_entry((union v6addr *)v6_pod_two, 0, 233, v4_node_two, 0);

	set_encrypt_key_mark(ctx, ENCRYPT_KEY, NODE_ID);
	set_identity_meta(ctx, SECLABEL_IPV6);
	tail_call_static(ctx, &entry_call_map, FROM_HOST);
	return TEST_ERROR;
}

CHECK("tc", "ipv6_ipsec_from_host")
int ipv6_ipsec_from_host_check(__maybe_unused const struct __ctx_buff *ctx)
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
	assert(*status_code == CTX_ACT_REDIRECT);

	assert(ctx->mark == 0);
	assert(ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY) == 0);

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
