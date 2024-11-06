// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

/* Enable debug output */
#define DEBUG

/* Set THIS_INTERFACE_MAC equal to mac_two */
#define THIS_INTERFACE_MAC { .addr = {0x13, 0x37, 0x13, 0x37, 0x13, 0x37} }

#define SECCTX_FROM_IPCACHE 1

/* Set the LXC source address to be the address of pod one */
#define LXC_IPV4 (__be32)v6_pod_one

/* Enable CT debug output */
#undef QUIET_CT

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_L2_ANNOUNCEMENTS

#include <bpf_host.c>

#define NS_MSG_SIZE (4 /* ICMP6: TYPE+CODE+CSUM */)
#define NA_MSG_SIZE (4 /* ICMP6: TYPE+CODE+CSUM */ + 8 /* LL Address opt */)

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

/* Setup for this test:
 * +-------------------------+   +--------------------------------------+    +--------------------------+
 * |L2:mac_one, L3:v6_ext_one|---|  ND Request broadcast for v6_svc_one |--->|L2:mac_two, L3:v6_node_one|
 * +-------------------------+   +--------------------------------------+    +--------------------------+
 *             ^   +-------------------------------------------------------------------+    |
 *             \---| ND Reply, SHR:mac_two, SIP:v6_svc_one, DHR:mac_one, DIP:v6_ext_one|---/
 *                 +-------------------------------------------------------------------+
 */

static volatile const __u8 mac_bcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static __always_inline int build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_bcast;
	struct icmp6hdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_icmp6_packet(&builder,
				    (__u8 *)src, (__u8 *)dst,
				    (__u8 *)v6_ext_one, (__u8 *)v6_svc_one,
				    ICMP6_NS_MSG_TYPE);
	if (!l4)
		return TEST_ERROR;

	/* Set ND sol data */
	l4->icmp6_type = ICMP6_NS_MSG_TYPE;
	l4->icmp6_code = 0;

	l4->icmp6_router = 0;
	l4->icmp6_solicited = 0;
	l4->icmp6_override = 0;
	l4->icmp6_ndiscreserved = 0;

	__u8 options[] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};
	data = pktgen__push_data(&builder, (__u8 *)options, 8);
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

/* Test that sending a ND broadcast request without entries in the map.
 */
SETUP("tc", "0_no_entry")
int l2_announcement_nd_no_entry_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "0_no_entry")
int l2_announcement_nd_no_entry_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void* data;
	void* data_end;
	__u32 *status_code;
	struct ethhdr* l2;
	struct ipv6hdr* l3;
	struct icmp6hdr* icmp;
	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* The program should pass unknown ND messages to the stack */
	assert(*status_code == TC_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void*)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	icmp = (void*)l3 + sizeof(struct ipv6hdr);
	if ((void*)l3 + sizeof(struct ipv6hdr) + NS_MSG_SIZE > data_end)
		test_fatal("l3 out of bounds");

	/* L2 */
	assert(memcmp(l2->h_source, (__u8 *)mac_one, ETH_ALEN) == 0);
	assert(memcmp(l2->h_dest, (__u8 *)mac_bcast, ETH_ALEN) == 0);

	/* IPv6 */
	assert(memcmp(&l3->saddr, (void*)&v6_ext_one, sizeof(v6_ext_one)) == 0);
	assert(memcmp(&l3->daddr, (void*)&v6_svc_one, sizeof(v6_svc_one)) == 0);
	assert(l3->nexthdr == NEXTHDR_ICMP);

	/* ICMPv6 + ND sol */
	assert(icmp->icmp6_type == ICMP6_NS_MSG_TYPE);
	assert(icmp->icmp6_code == 0);

	assert(icmp->icmp6_router == 0);
	assert(icmp->icmp6_solicited == 0);
	assert(icmp->icmp6_override == 0);
	assert(icmp->icmp6_ndiscreserved == 0);

	test_finish();
}

PKTGEN("tc", "1_happy_path")
int l2_announcement_nd_happy_path_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

/* Test that sending a ND broadcast request matching an entry in the
 * L2_RESPONDER_MAP6 results in a valid ND reply.
 */
SETUP("tc", "1_happy_path")
int l2_announcement_nd_happy_path_setup(struct __ctx_buff *ctx)
{
	struct l2_responder_v6_key key;
	struct l2_responder_stats value = {0};
	__u32 index;
	__u64 time;

	key.ifindex = 0;
	memcpy(&key.ip6, (void*)&v6_svc_one, sizeof(v6_svc_one));
	map_update_elem(&L2_RESPONDER_MAP6, &key, &value, BPF_ANY);

	index = RUNTIME_CONFIG_AGENT_LIVENESS;
	time = ktime_get_ns();
	map_update_elem(&CONFIG_MAP, &index, &time, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "1_happy_path")
int l2_announcement_nd_happy_path_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void* data;
	void* data_end;
	__u32 *status_code;
	struct ethhdr* l2;
	struct ipv6hdr* l3;
	struct icmp6hdr* icmp;
	__u8* lla_opt;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* The program should pass unknown ND messages to the stack */
	assert(*status_code == TC_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void*)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	icmp = (void*)l3 + sizeof(struct ipv6hdr);
	lla_opt = (void*)icmp + sizeof(struct icmp6hdr) + 2 /* Type + Length */;

	if ((void*)l3 + sizeof(struct ipv6hdr) + NA_MSG_SIZE > data_end)
		test_fatal("l3 out of bounds");

	/* L2 */
	assert(memcmp(l2->h_source, (__u8 *)mac_two, ETH_ALEN) == 0);
	assert(memcmp(l2->h_dest, (__u8 *)mac_one, ETH_ALEN) == 0);

	/* IPv6 */
	assert(memcmp(&l3->saddr, (void*)&v6_svc_one, sizeof(v6_svc_one)) == 0);
	assert(memcmp(&l3->daddr, (void*)&v6_ext_one, sizeof(v6_ext_one)) == 0);
	assert(l3->nexthdr == NEXTHDR_ICMP);

	/* ICMPv6 + NA sol */
	assert(icmp->icmp6_type == ICMP6_NA_MSG_TYPE);
	assert(icmp->icmp6_code == 0);

	assert(icmp->icmp6_router == 0);
	assert(icmp->icmp6_solicited == 1);
	assert(icmp->icmp6_override == 1); /* Must override */
	assert(icmp->icmp6_ndiscreserved == 0);

	/* check Link layer address */
	assert(memcmp(&lla_opt, (void*)&mac_two, sizeof(mac_two)));

	test_finish();
}
