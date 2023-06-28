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

#include "bpf_lxc.c"

#define FROM_CONTAINER 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_CONTAINER] = &cil_from_container,
	},
};

PKTGEN("tc", "ipv4_ipsec_from_lxc")
int ipv4_ipsec_from_lxc_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;
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

SETUP("tc", "ipv4_ipsec_from_lxc")
int ipv4_ipsec_from_lxc_setup(struct __ctx_buff *ctx)
{
	struct policy_key policy_key = { .egress = 1 };
	struct policy_entry policy_value = {};

	map_update_elem(&POLICY_MAP, &policy_key, &policy_value, BPF_ANY);

	struct ipcache_key cache_key = {};
	struct remote_endpoint_info cache_value = {};

	cache_key.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32);
	cache_key.family = ENDPOINT_KEY_IPV4;
	cache_key.ip4 = v4_pod_two;
	cache_value.sec_identity = 233;
	cache_value.tunnel_endpoint = v4_node_two;
	cache_value.node_id = NODE_ID;
	cache_value.key = ENCRYPT_KEY;
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	__u32 encrypt_key = 0;
	struct encrypt_config encrypt_value = { .encrypt_key = 3 };

	map_update_elem(&ENCRYPT_MAP, &encrypt_key, &encrypt_value, BPF_ANY);

	tail_call_static(ctx, &entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

CHECK("tc", "ipv4_ipsec_from_lxc")
int ipv4_ipsec_from_lxc_check(__maybe_unused const struct __ctx_buff *ctx)
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
	assert(*status_code == CTX_ACT_OK);
	assert(ctx->mark == (NODE_ID << 16 | ENCRYPT_KEY << 12 | MARK_MAGIC_ENCRYPT));
	assert(ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY) == SECLABEL);

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

PKTGEN("tc", "ipv6_ipsec_from_lxc")
int ipv6_ipsec_from_lxc_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
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

SETUP("tc", "ipv6_ipsec_from_lxc")
int ipv6_ipsec_from_lxc_setup(struct __ctx_buff *ctx)
{
	struct policy_key policy_key = { .egress = 1 };
	struct policy_entry policy_value = {};

	map_update_elem(&POLICY_MAP, &policy_key, &policy_value, BPF_ANY);

	struct ipcache_key cache_key = {};
	struct remote_endpoint_info cache_value = {};

	cache_key.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(128);
	cache_key.family = ENDPOINT_KEY_IPV6;
	memcpy(&cache_key.ip6, (__u8 *)v6_pod_two, 16);
	cache_value.sec_identity = 233;
	cache_value.tunnel_endpoint = v4_node_two;
	cache_value.node_id = NODE_ID;
	cache_value.key = ENCRYPT_KEY;
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	__u32 encrypt_key = 0;
	struct encrypt_config encrypt_value = { .encrypt_key = 3 };

	map_update_elem(&ENCRYPT_MAP, &encrypt_key, &encrypt_value, BPF_ANY);

	tail_call_static(ctx, &entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

CHECK("tc", "ipv6_ipsec_from_lxc")
int ipv6_ipsec_from_lxc_check(__maybe_unused const struct __ctx_buff *ctx)
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
	assert(*status_code == CTX_ACT_OK);
	assert(ctx->mark == (NODE_ID << 16 | ENCRYPT_KEY << 12 | MARK_MAGIC_ENCRYPT));
	assert(ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY) == SECLABEL);

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IPV6");

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
