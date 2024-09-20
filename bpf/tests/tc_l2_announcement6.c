// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

/* Enable debug output */
#define DEBUG

#define SECCTX_FROM_IPCACHE 1

/* Set the LXC source address to be the address of pod one */
#define LXC_IPV4 (__be32)v6_pod_one

/* Enable CT debug output */
#undef QUIET_CT

#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_L2_ANNOUNCEMENTS

#include <bpf_host.c>

#define V6_ALEN 16

ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr})

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

struct icmp6_opthdr {
	__u8 type;
	__u8 length;
	__u8 llsrc_mac[ETH_ALEN];
};

/* Setup for this test:
 * +-------------------------+   +--------------------------------------+    +--------------------------+
 * |L2:mac_one, L3:v6_ext_node_one|---|  ND Request broadcast for v6_svc_one |--->|L2:mac_two, L3:v6_node_one|
 * +-------------------------+   +--------------------------------------+    +--------------------------+
 *             ^   +-------------------------------------------------------------------+    |
 *             \---| ND Reply, SHR:mac_two, SIP:v6_svc_one, DHR:mac_one, DIP:v6_ext_node_one|---/
 *                 +-------------------------------------------------------------------+
 */

static __always_inline int build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	union macaddr dst;
	struct icmp6hdr *l4;
	void *data;
	struct icmp6_opthdr llsrc_opt;
	__u8 ll_mac[] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1};

	pktgen__init(&builder, ctx);

	ipv6_sol_mc_mac_set((union v6addr *)v6_svc_one, &dst);

	l4 = pktgen__push_ipv6_icmp6_packet(&builder, (__u8 *)src,
					    (__u8 *)&dst,
					    (__u8 *)v6_ext_node_one,
					    (__u8 *)v6_svc_one,
					    ICMP6_NS_MSG_TYPE);
	if (!l4)
		return TEST_ERROR;

	l4->icmp6_router = 0;
	l4->icmp6_solicited = 1;
	l4->icmp6_override = 0;
	l4->icmp6_ndiscreserved = 0;

	data = pktgen__push_data(&builder, (__u8 *)v6_svc_one, V6_ALEN);
	if (!data)
		return TEST_ERROR;

	/* LLSRC opt */
	llsrc_opt.type = 0x1;
	llsrc_opt.length = 0x1;
	memcpy((__u8 *)&llsrc_opt.llsrc_mac, (__u8 *)ll_mac, ETH_ALEN);
	data = pktgen__push_data(&builder, (__u8 *)&llsrc_opt,
				 sizeof(llsrc_opt));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

PKTGEN("tc", "0_no_entry")
int l2_announcement_nd_no_entry_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "0_no_entry")
int l2_announcement_nd_no_entry_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "0_no_entry")
int l2_announcement_nd_no_entry_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	union macaddr dst;
	struct ipv6hdr *l3;
	struct icmp6hdr *icmp;
	void *target_addr, *opt;
	struct icmp6_opthdr llsrc_opt;
	__u8 ll_mac[] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1};

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* The program should pass unknown ND messages to the stack */
	assert(*status_code == TC_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	ipv6_sol_mc_mac_set((union v6addr *)v6_svc_one, &dst);
	assert(memcmp(l2->h_source, (__u8 *)mac_one, ETH_ALEN) == 0);
	assert(memcmp(l2->h_dest, (__u8 *)&dst, ETH_ALEN) == 0);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	assert(memcmp(&l3->saddr, (void *)v6_ext_node_one, V6_ALEN) == 0);
	assert(memcmp(&l3->daddr, (void *)v6_svc_one, V6_ALEN) == 0);
	assert(l3->nexthdr == NEXTHDR_ICMP);

	icmp = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)icmp + sizeof(struct icmp6hdr) > data_end)
		test_fatal("icmp out of bounds");

	assert(icmp->icmp6_type == ICMP6_NS_MSG_TYPE);
	assert(icmp->icmp6_code == 0);

	assert(icmp->icmp6_router == 0);
	assert(icmp->icmp6_solicited == 1);
	assert(icmp->icmp6_override == 0);
	assert(icmp->icmp6_ndiscreserved == 0);

	target_addr = (void *)icmp + sizeof(struct icmp6hdr);
	if (target_addr + V6_ALEN > data_end)
		test_fatal("Target addr out of bounds");

	assert(memcmp(target_addr, (__u8 *)v6_svc_one, V6_ALEN) == 0);

	/* Link layer address option */
	opt = target_addr + V6_ALEN;
	if (opt + sizeof(llsrc_opt) > data_end)
		test_fatal("llsrc_opt addr out of bounds");

	llsrc_opt.type = 0x1;
	llsrc_opt.length = 0x1;
	memcpy((__u8 *)&llsrc_opt.llsrc_mac, (__u8 *)ll_mac, ETH_ALEN);
	assert(memcmp(opt, (__u8 *)&llsrc_opt, sizeof(llsrc_opt)) == 0);

	test_finish();
}

PKTGEN("tc", "1_happy_path")
int l2_announcement_nd_happy_path_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "1_happy_path")
int l2_announcement_nd_happy_path_setup(struct __ctx_buff *ctx)
{
	struct l2_responder_v6_key key;
	struct l2_responder_stats value = {0};

	key.ifindex = 0;
	key.pad = 0;
	memcpy(&key.ip6, (void *)v6_svc_one, V6_ALEN);
	map_update_elem(&cilium_l2_responder_v6, &key, &value, BPF_ANY);

	config_set(RUNTIME_CONFIG_AGENT_LIVENESS, ktime_get_ns());

	tail_call_static(ctx, entry_call_map, 0);

	return TEST_ERROR;
}

CHECK("tc", "1_happy_path")
int l2_announcement_nd_happy_path_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct icmp6hdr *icmp;
	void *target_addr;
	struct icmp6_opthdr *opt;
	struct icmp6_opthdr llsrc_opt;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == TC_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	assert(memcmp(l2->h_source, (__u8 *)mac_two, ETH_ALEN) == 0);
	assert(memcmp(l2->h_dest, (__u8 *)mac_one, ETH_ALEN) == 0);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	assert(memcmp(&l3->saddr, (void *)&v6_svc_one, V6_ALEN) == 0);
	assert(memcmp(&l3->daddr, (void *)&v6_ext_node_one, V6_ALEN) == 0);
	assert(l3->nexthdr == NEXTHDR_ICMP);

	icmp = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)icmp + sizeof(struct icmp6hdr) > data_end)
		test_fatal("icmp out of bounds");

	assert(icmp->icmp6_type == ICMP6_NA_MSG_TYPE);
	assert(icmp->icmp6_code == 0);

	assert(icmp->icmp6_router == 0);
	assert(icmp->icmp6_solicited == 1);
	assert(icmp->icmp6_override == 1);
	assert(icmp->icmp6_ndiscreserved == 0);

	target_addr = (void *)icmp + sizeof(struct icmp6hdr);
	if (target_addr + V6_ALEN > data_end)
		test_fatal("Target addr out of bounds");

	assert(memcmp(target_addr, (__u8 *)v6_svc_one, V6_ALEN) == 0);

	/* Link layer address option */
	opt = (struct icmp6_opthdr *)(target_addr + V6_ALEN);
	if ((void *)opt + sizeof(llsrc_opt) > data_end)
		test_fatal("llsrc_opt addr out of bounds");

	assert(opt->type == 0x2);
	assert(opt->length == 0x1);
	assert(memcmp((void *)mac_two, (void *)opt->llsrc_mac, ETH_ALEN) == 0);

	test_finish();
}
