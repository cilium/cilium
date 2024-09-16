// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

/* Enable debug output */
#define DEBUG

/* Set THIS_INTERFACE_MAC equal to mac_two */
#define THIS_INTERFACE_MAC { .addr = {0x13, 0x37, 0x13, 0x37, 0x13, 0x37} }

#define SECCTX_FROM_IPCACHE 1

/* Set the LXC source address to be the address of pod one */
#define LXC_IPV4 (__be32)v4_pod_one

/* Enable CT debug output */
#undef QUIET_CT

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_L2_ANNOUNCEMENTS

#include <bpf_host.c>

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
 * |L2:mac_one, L3:v4_ext_one|---| ARP Request broadcast for v4_svc_one |--->|L2:mac_two, L3:v4_node_one|
 * +-------------------------+   +--------------------------------------+    +--------------------------+
 *             ^   +-------------------------------------------------------------------+    |
 *             \---|ARP Reply, SHR:mac_two, SIP:v4_svc_one, DHR:mac_one, DIP:v4_ext_one|---/
 *                 +-------------------------------------------------------------------+
 */

static volatile const __u8 mac_bcast[] =   {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static __always_inline int build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_bcast;
	struct ethhdr *l2;
	struct arphdreth *l3;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)src, (__u8 *)dst);

	/* Push ARP header */
	l3 = pktgen__push_default_arphdr_ethernet(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->ar_op = bpf_htons(ARPOP_REQUEST);
	memcpy(l3->ar_sha, (__u8 *)mac_one, ETH_ALEN);
	l3->ar_sip = v4_ext_one;
	memcpy(l3->ar_tha, (__u8 *)mac_bcast, ETH_ALEN);
	l3->ar_tip = v4_svc_one;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

PKTGEN("tc", "0_no_entry")
int l2_announcement_arp_no_entry_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

/* Test that sending a ARP broadcast request without entries in the map.
 */
SETUP("tc", "0_no_entry")
int l2_announcement_arp_no_entry_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "0_no_entry")
int l2_announcement_arp_no_entry_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct arphdreth *l3;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* The program should pass unknown ARP messages to the stack */
	assert(*status_code == TC_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct arphdreth) > data_end)
		test_fatal("l3 out of bounds");

	assert(memcmp(l2->h_source, (__u8 *)mac_one, ETH_ALEN) == 0);
	assert(memcmp(l2->h_dest, (__u8 *)mac_bcast, ETH_ALEN) == 0);
	assert(l3->ar_op == bpf_htons(ARPOP_REQUEST));
	assert(l3->ar_sip == v4_ext_one);
	assert(l3->ar_tip == v4_svc_one);
	assert(memcmp(l3->ar_sha, (__u8 *)mac_one, ETH_ALEN) == 0);
	assert(memcmp(l3->ar_tha, (__u8 *)mac_bcast, ETH_ALEN) == 0);

	test_finish();
}

PKTGEN("tc", "1_happy_path")
int l2_announcement_arp_happy_path_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

/* Test that sending a ARP broadcast request matching an entry in the
 * L2_RESPONDER_MAP4 results in a valid ARP reply.
 */
SETUP("tc", "1_happy_path")
int l2_announcement_arp_happy_path_setup(struct __ctx_buff *ctx)
{
	struct l2_responder_v4_key key;
	struct l2_responder_v4_stats value = {0};
	__u32 index;
	__u64 time;

	key.ifindex = 0;
	key.ip4 = v4_svc_one;
	map_update_elem(&L2_RESPONDER_MAP4, &key, &value, BPF_ANY);

	index = RUNTIME_CONFIG_AGENT_LIVENESS;
	time = ktime_get_ns();
	map_update_elem(&CONFIG_MAP, &index, &time, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "1_happy_path")
int l2_announcement_arp_happy_path_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct arphdreth *l3;

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

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct arphdreth) > data_end)
		test_fatal("l3 out of bounds");

	assert(memcmp(l2->h_source, (__u8 *)mac_two, ETH_ALEN) == 0);
	assert(memcmp(l2->h_dest, (__u8 *)mac_one, ETH_ALEN) == 0);
	assert(l3->ar_op == bpf_htons(ARPOP_REPLY));
	assert(l3->ar_sip == v4_svc_one);
	assert(l3->ar_tip == v4_ext_one);
	assert(memcmp(l3->ar_sha, (__u8 *)mac_two, ETH_ALEN) == 0);
	assert(memcmp(l3->ar_tha, (__u8 *)mac_one, ETH_ALEN) == 0);

	test_finish();
}
