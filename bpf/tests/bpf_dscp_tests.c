// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_BANDWIDTH_MANAGER
#define ENABLE_DSCP_MARKING

#include "common.h"
#include "pktgen.h"

#include <bpf/config/global.h>
#include <bpf/config/node.h>

#include <lib/edt.h>

#define ENCODE_DSCP(d) ((d) + 1)

static __always_inline __be16 ipv4_csum(const struct iphdr *ip4)
{
	struct iphdr tmp = *ip4;

	tmp.check = 0;
	return csum_fold(csum_diff(NULL, 0, &tmp, sizeof(tmp), 0));
}

PKTGEN("tc", "edt_set_dscp_mark_ipv4")
int dscp_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct udphdr *l4;

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
	/* DSCP=0, ECN=01 (ECT(1)). The ECN bits must be preserved when
	 * we rewrite the DSCP.
	 */
	l3->tos = 0x01;

	l4 = pktgen__push_default_udphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = bpf_htons(1234);
	l4->dest = bpf_htons(53);

	pktgen__finish(&builder);
	return 0;
}

CHECK("tc", "edt_set_dscp_mark_ipv4")
int dscp_ipv4_check(struct __ctx_buff *ctx)
{
	test_init();

	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	struct iphdr *ip4 = data + sizeof(struct ethhdr);

	if ((void *)(ip4 + 1) > data_end)
		test_fatal("ip4 out of bounds");

	__u8 orig_tos = ip4->tos;
	__u8 orig_ecn = orig_tos & 0x3;
	__be16 orig_check = ip4->check;

	TEST("rewrites_tos_preserving_ecn", {
		int ret = edt_set_dscp_mark(ctx, bpf_htons(ETH_P_IP),
					    ENCODE_DSCP(46));
		assert(ret == CTX_ACT_OK);

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		ip4 = data + sizeof(struct ethhdr);
		if ((void *)(ip4 + 1) > data_end)
			test_fatal("ip4 out of bounds after rewrite");

		__u8 expected = (__u8)((46 << 2) | orig_ecn);
		if (ip4->tos != expected)
			test_fatal("TOS not rewritten: got 0x%x, want 0x%x",
				   ip4->tos, expected);

		if (ip4->check == orig_check)
			test_fatal("IPv4 checksum unchanged after TOS rewrite");

		__be16 csum = ipv4_csum(ip4);
		if (csum != ip4->check)
			test_fatal("IPv4 checksum invalid: got 0x%x want 0x%x",
				   ip4->check, csum);
	});

	TEST("same_dscp_does_not_rewrite", {
		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		ip4 = data + sizeof(struct ethhdr);
		if ((void *)(ip4 + 1) > data_end)
			test_fatal("ip4 out of bounds");

		__u8 before = ip4->tos;
		__be16 before_check = ip4->check;

		int ret = edt_set_dscp_mark(ctx, bpf_htons(ETH_P_IP),
					    ENCODE_DSCP(46));
		assert(ret == CTX_ACT_OK);

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		ip4 = data + sizeof(struct ethhdr);
		if ((void *)(ip4 + 1) > data_end)
			test_fatal("ip4 out of bounds");

		if (ip4->tos != before)
			test_fatal("TOS changed on same-dscp call");
		if (ip4->check != before_check)
			test_fatal("checksum changed on same-dscp call");
	});

	TEST("dscp_zero_is_noop", {
		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		ip4 = data + sizeof(struct ethhdr);
		if ((void *)(ip4 + 1) > data_end)
			test_fatal("ip4 out of bounds");

		__u8 before = ip4->tos;
		__be16 before_check = ip4->check;

		int ret = edt_set_dscp_mark(ctx, bpf_htons(ETH_P_IP), 0);
		assert(ret == CTX_ACT_OK);

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		ip4 = data + sizeof(struct ethhdr);
		if ((void *)(ip4 + 1) > data_end)
			test_fatal("ip4 out of bounds");

		if (ip4->tos != before)
			test_fatal("TOS modified by dscp=0: got 0x%x want 0x%x",
				   ip4->tos, before);
		if (ip4->check != before_check)
			test_fatal("checksum modified by dscp=0");
	});

	TEST("encoded_value_out_of_range_is_noop", {
		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		ip4 = data + sizeof(struct ethhdr);
		if ((void *)(ip4 + 1) > data_end)
			test_fatal("ip4 out of bounds");

		__u8 before = ip4->tos;
		__be16 before_check = ip4->check;

		int ret = edt_set_dscp_mark(ctx, bpf_htons(ETH_P_IP), 65);
		assert(ret == CTX_ACT_OK);

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		ip4 = data + sizeof(struct ethhdr);
		if ((void *)(ip4 + 1) > data_end)
			test_fatal("ip4 out of bounds");

		if (ip4->tos != before)
			test_fatal("TOS modified by encoded>64: got 0x%x want 0x%x",
				   ip4->tos, before);
		if (ip4->check != before_check)
			test_fatal("checksum modified by encoded>64");
	});

	TEST("max_dscp_63_rewrites_tos", {
		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		ip4 = data + sizeof(struct ethhdr);
		if ((void *)(ip4 + 1) > data_end)
			test_fatal("ip4 out of bounds");

		__u8 orig_ecn_local = ip4->tos & 0x3;

		int ret = edt_set_dscp_mark(ctx, bpf_htons(ETH_P_IP),
					    ENCODE_DSCP(63));
		assert(ret == CTX_ACT_OK);

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		ip4 = data + sizeof(struct ethhdr);
		if ((void *)(ip4 + 1) > data_end)
			test_fatal("ip4 out of bounds");

		__u8 expected = (__u8)((63 << 2) | orig_ecn_local);
		if (ip4->tos != expected)
			test_fatal("TOS not set to DSCP=63: got 0x%x, want 0x%x",
				   ip4->tos, expected);

		__be16 csum = ipv4_csum(ip4);
		if (csum != ip4->check)
			test_fatal("IPv4 checksum invalid after DSCP=63: got 0x%x "
				   "want 0x%x",
				   ip4->check, csum);
	});

	test_finish();
}

PKTGEN("tc", "edt_set_dscp_mark_ipv6")
int dscp_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)mac_one, (__u8 *)mac_two);

	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;
	/* Encode initial Traffic Class and a non-trivial Flow Label.
	 * Layout (network byte order):
	 *   byte 0: version(4) | TC_hi(4)
	 *   byte 1: TC_lo(4)   | FL_hi(4)
	 *   byte 2..3: FL_lo(16)
	 *
	 * Set TC = 0x01 (DSCP=0, ECN=01) and Flow Label = 0xABCDE.
	 */
	__u8 *hdr = (__u8 *)l3;
	__u8 tc = 0x01;
	__u32 fl = 0xABCDE;
	hdr[0] = (__u8)((6 << 4) | (tc >> 4));
	hdr[1] = (__u8)((tc << 4) | ((fl >> 16) & 0x0f));
	hdr[2] = (__u8)((fl >> 8) & 0xff);
	hdr[3] = (__u8)(fl & 0xff);

	l4 = pktgen__push_default_udphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = bpf_htons(1234);
	l4->dest = bpf_htons(53);

	pktgen__finish(&builder);
	return 0;
}

CHECK("tc", "edt_set_dscp_mark_ipv6")
int dscp_ipv6_check(struct __ctx_buff *ctx)
{
	test_init();

	TEST("rewrites_traffic_class_preserving_ecn_and_flow_label", {
		void *data = ctx_data(ctx);
		void *data_end = ctx_data_end(ctx);
		__u8 *hdr = data + sizeof(struct ethhdr);

		if ((void *)(hdr + 4) > data_end)
			test_fatal("ipv6 hdr out of bounds");

		__u8 orig_tc = (__u8)(((hdr[0] & 0x0f) << 4) | (hdr[1] >> 4));
		__u8 orig_ecn = orig_tc & 0x3;
		__u32 orig_fl = ((__u32)(hdr[1] & 0x0f) << 16) |
				((__u32)hdr[2] << 8) | hdr[3];
		__u8 orig_ver = (__u8)(hdr[0] >> 4);

		int ret = edt_set_dscp_mark(ctx, bpf_htons(ETH_P_IPV6),
					    ENCODE_DSCP(34));
		assert(ret == CTX_ACT_OK);

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		hdr = data + sizeof(struct ethhdr);
		if ((void *)(hdr + 4) > data_end)
			test_fatal("ipv6 hdr out of bounds after rewrite");

		__u8 new_tc = (__u8)(((hdr[0] & 0x0f) << 4) | (hdr[1] >> 4));
		__u8 expected_tc = (__u8)((34 << 2) | orig_ecn);
		if (new_tc != expected_tc)
			test_fatal("TC not rewritten: got 0x%x, want 0x%x",
				   new_tc, expected_tc);

		__u32 new_fl = ((__u32)(hdr[1] & 0x0f) << 16) |
			       ((__u32)hdr[2] << 8) | hdr[3];
		if (new_fl != orig_fl)
			test_fatal("Flow Label changed: got 0x%x, want 0x%x",
				   new_fl, orig_fl);

		__u8 new_ver = (__u8)(hdr[0] >> 4);
		if (new_ver != orig_ver)
			test_fatal("IP version changed: got %d, want %d",
				   new_ver, orig_ver);
	});

	TEST("dscp_zero_is_noop", {
		void *data = ctx_data(ctx);
		void *data_end = ctx_data_end(ctx);
		__u8 *hdr = data + sizeof(struct ethhdr);
		if ((void *)(hdr + 4) > data_end)
			test_fatal("ipv6 hdr out of bounds");

		__u8 b0 = hdr[0];
		__u8 b1 = hdr[1];
		__u8 b2 = hdr[2];
		__u8 b3 = hdr[3];

		int ret = edt_set_dscp_mark(ctx, bpf_htons(ETH_P_IPV6), 0);
		assert(ret == CTX_ACT_OK);

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		hdr = data + sizeof(struct ethhdr);
		if ((void *)(hdr + 4) > data_end)
			test_fatal("ipv6 hdr out of bounds");

		if (hdr[0] != b0 || hdr[1] != b1 || hdr[2] != b2 || hdr[3] != b3)
			test_fatal("ipv6 first 4 bytes modified by dscp=0");
	});

	TEST("encoded_value_out_of_range_is_noop", {
		void *data = ctx_data(ctx);
		void *data_end = ctx_data_end(ctx);
		__u8 *hdr = data + sizeof(struct ethhdr);
		if ((void *)(hdr + 4) > data_end)
			test_fatal("ipv6 hdr out of bounds");

		__u8 b0 = hdr[0];
		__u8 b1 = hdr[1];
		__u8 b2 = hdr[2];
		__u8 b3 = hdr[3];

		int ret = edt_set_dscp_mark(ctx, bpf_htons(ETH_P_IPV6), 200);
		assert(ret == CTX_ACT_OK);

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		hdr = data + sizeof(struct ethhdr);
		if ((void *)(hdr + 4) > data_end)
			test_fatal("ipv6 hdr out of bounds");

		if (hdr[0] != b0 || hdr[1] != b1 || hdr[2] != b2 || hdr[3] != b3)
			test_fatal("ipv6 first 4 bytes modified by encoded>64");
	});

	TEST("max_dscp_63_rewrites_traffic_class", {
		void *data = ctx_data(ctx);
		void *data_end = ctx_data_end(ctx);
		__u8 *hdr = data + sizeof(struct ethhdr);
		if ((void *)(hdr + 4) > data_end)
			test_fatal("ipv6 hdr out of bounds");

		__u8 orig_ecn_local = (__u8)((hdr[1] >> 4) & 0x3);
		__u32 orig_fl_local = ((__u32)(hdr[1] & 0x0f) << 16) |
				      ((__u32)hdr[2] << 8) | hdr[3];
		__u8 orig_ver_local = (__u8)(hdr[0] >> 4);

		int ret = edt_set_dscp_mark(ctx, bpf_htons(ETH_P_IPV6),
					    ENCODE_DSCP(63));
		assert(ret == CTX_ACT_OK);

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		hdr = data + sizeof(struct ethhdr);
		if ((void *)(hdr + 4) > data_end)
			test_fatal("ipv6 hdr out of bounds after rewrite");

		__u8 new_tc = (__u8)(((hdr[0] & 0x0f) << 4) | (hdr[1] >> 4));
		__u8 expected_tc = (__u8)((63 << 2) | orig_ecn_local);
		if (new_tc != expected_tc)
			test_fatal("TC not set to DSCP=63: got 0x%x, want 0x%x",
				   new_tc, expected_tc);

		__u32 new_fl = ((__u32)(hdr[1] & 0x0f) << 16) |
			       ((__u32)hdr[2] << 8) | hdr[3];
		if (new_fl != orig_fl_local)
			test_fatal("Flow Label changed at DSCP=63: got 0x%x, want 0x%x",
				   new_fl, orig_fl_local);

		__u8 new_ver = (__u8)(hdr[0] >> 4);
		if (new_ver != orig_ver_local)
			test_fatal("IP version changed at DSCP=63: got %d, want %d",
				   new_ver, orig_ver_local);
	});

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
