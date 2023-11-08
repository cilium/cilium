// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "bpf/ctx/skb.h"
#include "node_config.h"
#include "common.h"
#include "lib/endian.h"
#include "lib/common.h"
#include "lib/eth.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_MULTICAST 1
#define ENCAP_IFINDEX 1

#include <linux/igmp.h>
#include <linux/in.h>
#include "../lib/mcast.h"

static __always_inline int default_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *eh;
	struct iphdr *iph;

	pktgen__init(&builder, ctx);

	eh = pktgen__push_ethhdr(&builder);
	if (!eh)
		return TEST_ERROR;

	iph = pktgen__push_default_iphdr(&builder);
	if (!iph)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

static __always_inline int igmpv3_join_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *eh;
	struct iphdr *iph;
	struct igmpv3_report *rep;

	pktgen__init(&builder, ctx);

	eh = pktgen__push_ethhdr(&builder);
	if (!eh)
		return TEST_ERROR;

	iph = pktgen__push_default_iphdr(&builder);
	if (!iph)
		return TEST_ERROR;
	iph->saddr = 0x1010101;/* 1.1.1.1 */
	iph->daddr = 0x160000e0;/* 224.0.0.22 */
	iph->protocol = IPPROTO_IGMP;

	rep = pktgen__push_rawhdr(&builder, sizeof(struct igmpv3_report),
				  PKT_LAYER_DATA);
	if (!rep)
		return TEST_ERROR;

	rep->type = IGMPV3_HOST_MEMBERSHIP_REPORT;

	pktgen__finish(&builder);

	return 0;
}

CHECK("tc", "mcast_tests")
int test1_check(struct __ctx_buff *ctx)
{
	test_init();

	/* test we correctly identify igmp packets */
	TEST("is_igmp", {
		int ret;
		struct iphdr *ip4;

		ret = igmpv3_join_packet(ctx);
		if (ret)
			return ret;

		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if ((data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end)
			test_fatal("ctx not big enough");

		ip4 = data + sizeof(struct ethhdr);

		if (mcast_ipv4_is_igmp(ip4) != 1)
			test_fatal("expected true for ipv4 protocol %x", ip4->protocol);
	});

	/* test we do not incorrectly identify non igmp packets */
	TEST("is_not_igmp", {
		int ret;
		struct iphdr *ip4;

		ret = default_packet(ctx);
		if (ret)
			return ret;

		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if ((data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end)
			test_fatal("ctx not big enough");

		ip4 = data + sizeof(struct ethhdr);

		if (mcast_ipv4_is_igmp(ip4) == 1)
			test_fatal("expected false for ipv4 protocol %x", ip4->protocol);
	});

	/* test we extract the correct IGMP type */
	TEST("igmp_type", {
		int ret;
		struct iphdr *ip4;
		__s32 type = 0;

		ret = igmpv3_join_packet(ctx);
		if (ret)
			return ret;

		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if ((data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end)
			test_fatal("ctx not big enough");

		ip4 = data + sizeof(struct ethhdr);

		type = mcast_ipv4_igmp_type(ip4, data, data_end);
		if (type != IGMPV3_HOST_MEMBERSHIP_REPORT)
			test_fatal("expected 0x22, got %x", type);
	});

	test_finish();
}
