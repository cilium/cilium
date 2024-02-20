// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"
#define ROUTER_IP
#define HOST_IP
#include "config_replacement.h"
#undef ROUTER_IP
#undef HOST_IP

#define ENABLE_IPV4
#define ENABLE_IPV6
#define SECCTX_FROM_IPCACHE 1

#include "bpf_host.c"

#include "lib/ipcache.h"
#include "lib/endpoint.h"

#define FROM_NETDEV 0

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

PKTGEN("tc", "01_ipv6_from_netdev_ns_for_pod")
int ipv6_from_netdev_ns_for_pod_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_icmp6_packet(&builder,
					    (__u8 *)mac_one, (__u8 *)mac_two,
					    (__u8 *)v6_pod_one, (__u8 *)v6_pod_two,
					    ICMP6_NS_MSG_TYPE);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, (__u8 *)v6_pod_three, 16);
	if (!data)
		return TEST_ERROR;

	__u8 options[] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};

	data = pktgen__push_data(&builder, (__u8 *)options, 8);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "01_ipv6_from_netdev_ns_for_pod")
int ipv6_from_netdev_ns_for_pod_setup(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)v6_pod_three, 0, 0, 0,
			      (__u8 *)mac_three, (__u8 *)mac_two);
	tail_call_static(ctx, &entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "01_ipv6_from_netdev_ns_for_pod")
int ipv6_from_netdev_ns_for_pod_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct icmp6hdr *l4;
	void *payload;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	printk("status_code: %d\n", *status_code);
	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IP");

	union macaddr node_mac = NODE_MAC;

	if (memcmp(l2->h_source, (__u8 *)&node_mac.addr, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to node mac");

	if (memcmp(l2->h_dest, (__u8 *)mac_one, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to source mac");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	union v6addr router_ip;

	BPF_V6(router_ip, ROUTER_IP);
	if (memcmp((__u8 *)&l3->saddr, (__u8 *)&router_ip, 16) != 0)
		test_fatal("src IP hasn't been set to router IP");

	if (memcmp((__u8 *)&l3->daddr, (__u8 *)v6_pod_one, 16) != 0)
		test_fatal("dest IP hasn't been set to source IP");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);

	if ((void *)l4 + sizeof(struct icmp6hdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->icmp6_type != ICMP6_NA_MSG_TYPE)
		test_fatal("icmp6 type hasn't been set to ICMP6_NA_MSG_TYPE");

	payload = (void *)l4 + sizeof(struct icmp6hdr);
	if ((void *)payload + 24 > data_end)
		test_fatal("payload out of bounds");

	void *target = payload;

	if (memcmp(target, (__u8 *)v6_pod_three, 16) != 0)
		test_fatal("icmp6 payload target hasn't been set properly");

	void *target_lladdr = payload + 16 + 2;

	if (memcmp(target_lladdr, (__u8 *)&node_mac.addr, ETH_ALEN) != 0)
		test_fatal("icmp6 payload target_lladdr hasn't been set properly");

	test_finish();
}

PKTGEN("tc", "02_ipv6_from_netdev_ns_for_node_ip")
int ipv6_from_netdev_ns_for_node_ip_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_icmp6_packet(&builder,
					    (__u8 *)mac_one, (__u8 *)mac_two,
					    (__u8 *)v6_pod_one, (__u8 *)v6_pod_two,
					    ICMP6_NS_MSG_TYPE);
	if (!l4)
		return TEST_ERROR;

	union v6addr node_ip;

	BPF_V6(node_ip, HOST_IP);
	data = pktgen__push_data(&builder, (__u8 *)&node_ip, 16);
	if (!data)
		return TEST_ERROR;

	__u8 options[] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};

	data = pktgen__push_data(&builder, (__u8 *)options, 8);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "02_ipv6_from_netdev_ns_for_node_ip")
int ipv6_from_netdev_ns_for_node_ip_setup(struct __ctx_buff *ctx)
{
	union v6addr node_ip;

	BPF_V6(node_ip, HOST_IP);
	endpoint_v6_add_entry((union v6addr *)&node_ip, 0, 0, ENDPOINT_F_HOST,
			      (__u8 *)mac_three, (__u8 *)mac_two);
	tail_call_static(ctx, &entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "02_ipv6_from_netdev_ns_for_node_ip")
int ipv6_from_netdev_ns_for_node_ip_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct icmp6hdr *l4;
	void *payload;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	printk("status_code: %d\n", *status_code);
	assert(*status_code == CTX_ACT_OK);

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

	if ((void *)l4 + sizeof(struct icmp6hdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->icmp6_type != ICMP6_NS_MSG_TYPE)
		test_fatal("icmp6 type was changed");

	payload = (void *)l4 + sizeof(struct icmp6hdr);
	if ((void *)payload + 24 > data_end)
		test_fatal("payload out of bounds");

	union v6addr node_ip;

	BPF_V6(node_ip, HOST_IP);
	if (memcmp(payload, (__u8 *)&node_ip, 16) != 0)
		test_fatal("icmp6 payload target was changed");

	test_finish();
}
