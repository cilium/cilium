// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_IPV6

#include "bpf_host.c"

ASSIGN_CONFIG(__u32, host_secctx_from_ipcache, 1)

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

/*
 * These tests make sure that ND packets directed to a Pod IP are answered
 * directly from BPF.
 */

/* "Targeted" NS */
PKTGEN("tc", "011_ipv6_from_netdev_ns_for_pod")
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

SETUP("tc", "011_ipv6_from_netdev_ns_for_pod")
int ipv6_from_netdev_ns_for_pod_setup(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)v6_pod_three, 0, 0, 0, 0,
			      (__u8 *)mac_three, (__u8 *)mac_two);
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "011_ipv6_from_netdev_ns_for_pod")
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
	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IP");

	union macaddr node_mac = THIS_INTERFACE_MAC;

	if (memcmp(l2->h_source, (__u8 *)&node_mac.addr, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to node mac");

	if (memcmp(l2->h_dest, (__u8 *)mac_one, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to source mac");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (memcmp((__u8 *)&l3->saddr, (__u8 *)v6_pod_three, 16) != 0)
		test_fatal("src IP hasn't been set to target IP");

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

/* Bcast NS */
PKTGEN("tc", "012_ipv6_from_netdev_ns_for_pod_mcast")
int ipv6_from_netdev_ns_for_pod_pktgen_mcast(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *l4;
	void *data;
	union v6addr dst_ip;

	__u8 mac_v6mcast[ETH_ALEN];

	/* IPv6 mcast mac addr is 33:33 followed by 32 LSBs from target IP */
	__bpf_memcpy_builtin(mac_v6mcast, (void *)mac_v6mcast_base, 2);
	__bpf_memcpy_builtin((__u8 *)mac_v6mcast + 2,
			     (__u8 *)v6_pod_three + 12, 4);

	/* IPv6 mcast addr has the 24 LSBs from the target IP */
	__bpf_memcpy_builtin(&dst_ip, (void *)v6_mcast_base, sizeof(dst_ip));
	__bpf_memcpy_builtin((__u8 *)&dst_ip + 13, (void *)v6_pod_three, 3);

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_icmp6_packet(&builder,
					    (__u8 *)mac_one,
					    (__u8 *)mac_v6mcast,
					    (__u8 *)v6_pod_one,
					    (__u8 *)dst_ip.addr,
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

SETUP("tc", "012_ipv6_from_netdev_ns_for_pod_mcast")
int ipv6_from_netdev_ns_for_pod_setup_mcast(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)v6_pod_three, 0, 0, 0, 0,
			      (__u8 *)mac_three, (__u8 *)mac_two);
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "012_ipv6_from_netdev_ns_for_pod_mcast")
int ipv6_from_netdev_ns_for_pod_check_mcast(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct icmp6hdr *l4;
	void *payload;
	union v6addr dst_ip;

	__u8 mac_v6mcast[ETH_ALEN];

	/* IPv6 mcast mac addr is 33:33 followed by 32 LSBs from target IP */
	__bpf_memcpy_builtin(mac_v6mcast, (void *)mac_v6mcast_base, 2);
	__bpf_memcpy_builtin(mac_v6mcast, (__u8 *)v6_pod_three + 12, 4);

	/* IPv6 mcast addr has the 24 LSBs from the target IP */
	__bpf_memcpy_builtin(&dst_ip, (void *)v6_mcast_base, sizeof(dst_ip));
	__bpf_memcpy_builtin((__u8 *)&dst_ip + 13, (void *)v6_pod_three, 3);

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IP");

	union macaddr node_mac = THIS_INTERFACE_MAC;

	if (memcmp(l2->h_source, (__u8 *)&node_mac.addr, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to node mac");

	if (memcmp(l2->h_dest, (__u8 *)mac_one, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to source mac");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (memcmp((__u8 *)&l3->saddr, (__u8 *)v6_pod_three, 16) != 0)
		test_fatal("src IP hasn't been set to target IP");

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

/*
 * These tests make sure that ND packets directed to the node IP make it
 * to the stack unmodified
 */

/* "Targeted" NS */
PKTGEN("tc", "021_ipv6_from_netdev_ns_for_node_ip")
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

	data = pktgen__push_data(&builder, (__u8 *)v6_node_one, 16);
	if (!data)
		return TEST_ERROR;

	__u8 options[] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};

	data = pktgen__push_data(&builder, (__u8 *)options, 8);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "021_ipv6_from_netdev_ns_for_node_ip")
int ipv6_from_netdev_ns_for_node_ip_setup(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)v6_node_one, 0, 0, ENDPOINT_F_HOST, 0,
			      (__u8 *)mac_three, (__u8 *)mac_two);
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "021_ipv6_from_netdev_ns_for_node_ip")
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
	assert(*status_code == CTX_ACT_OK);

	l2 = data + sizeof(*status_code);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto is incorrect");

	if (memcmp(l2->h_source, (__u8 *)mac_one, ETH_ALEN) != 0)
		test_fatal("src mac has been modified");

	if (memcmp(l2->h_dest, (__u8 *)mac_two, ETH_ALEN) != 0)
		test_fatal("dest mac has been modified");

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

	if (memcmp(payload, (__u8 *)v6_node_one, 16) != 0)
		test_fatal("icmp6 payload target was changed");

	test_finish();
}

/* Bcast NS */
PKTGEN("tc", "022_ipv6_from_netdev_ns_for_node_ip_mcast")
int ipv6_from_netdev_ns_for_node_ip_pktgen_mcast(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *l4;
	void *data;
	union v6addr dst_ip;
	__u8 mac_v6mcast[ETH_ALEN];

	/* IPv6 mcast mac addr is 33:33 followed by 32 LSBs from target IP */
	__bpf_memcpy_builtin(mac_v6mcast, (void *)mac_v6mcast_base, 2);
	__bpf_memcpy_builtin((__u8 *)mac_v6mcast + 2,
			     (__u8 *)v6_node_one + 12, 4);

	/* IPv6 mcast addr has the 24 LSBs from the target IP */
	__bpf_memcpy_builtin(&dst_ip, (void *)v6_mcast_base, sizeof(dst_ip));
	dst_ip.addr[13] = v6_node_one[13];
	dst_ip.addr[14] = v6_node_one[14];
	dst_ip.addr[15] = v6_node_one[15];

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_icmp6_packet(&builder,
					    (__u8 *)mac_one,
					    (__u8 *)mac_v6mcast,
					    (__u8 *)v6_pod_one,
					    (__u8 *)dst_ip.addr,
					    ICMP6_NS_MSG_TYPE);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, (__u8 *)&v6_node_one, 16);
	if (!data)
		return TEST_ERROR;

	__u8 options[] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};

	data = pktgen__push_data(&builder, (__u8 *)options, 8);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "022_ipv6_from_netdev_ns_for_node_ip_mcast")
int ipv6_from_netdev_ns_for_node_ip_setup_mcast(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)&v6_node_one, 0, 0, ENDPOINT_F_HOST, 0,
			      (__u8 *)mac_three, (__u8 *)mac_two);
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "022_ipv6_from_netdev_ns_for_node_ip_mcast")
int ipv6_from_netdev_ns_for_node_ip_check_mcast(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct icmp6hdr *l4;
	void *payload;
	union v6addr dst_ip;
	__u8 mac_v6mcast[ETH_ALEN];

	/* IPv6 mcast mac addr is 33:33 followed by 32 LSBs from target IP */
	__bpf_memcpy_builtin(mac_v6mcast, (void *)mac_v6mcast_base, 2);
	__bpf_memcpy_builtin((__u8 *)mac_v6mcast + 2,
			     (__u8 *)v6_node_one + 12, 4);

	/* IPv6 mcast addr has the 24 LSBs from the target IP */
	__bpf_memcpy_builtin(&dst_ip, (void *)v6_mcast_base, sizeof(dst_ip));
	dst_ip.addr[13] = v6_node_one[13];
	dst_ip.addr[14] = v6_node_one[14];
	dst_ip.addr[15] = v6_node_one[15];

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l2 = data + sizeof(*status_code);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto is incorrect");

	if (memcmp(l2->h_source, (__u8 *)mac_one, ETH_ALEN) != 0)
		test_fatal("src mac has been modified");

	if (memcmp(l2->h_dest, (__u8 *)mac_v6mcast, ETH_ALEN) != 0)
		test_fatal("dest mac has been modified");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (memcmp((__u8 *)&l3->saddr, (__u8 *)v6_pod_one, 16) != 0)
		test_fatal("src IP was changed");

	if (memcmp((__u8 *)&l3->daddr, (__u8 *)dst_ip.addr, 16) != 0)
		test_fatal("dest IP was changed");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);

	if ((void *)l4 + sizeof(struct icmp6hdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->icmp6_type != ICMP6_NS_MSG_TYPE)
		test_fatal("icmp6 type was changed");

	payload = (void *)l4 + sizeof(struct icmp6hdr);
	if ((void *)payload + 24 > data_end)
		test_fatal("payload out of bounds");

	if (memcmp(payload, (__u8 *)&v6_node_one, 16) != 0)
		test_fatal("icmp6 payload target was changed");

	test_finish();
}
