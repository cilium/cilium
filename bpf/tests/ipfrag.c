// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include <node_config.h>

#include <lib/ipfrag.h>
#include <lib/ipv6.h>

PKTGEN("tc", "ipfrag_helpers_ipv4")
int test_ipfrag_helpers_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_node_one, v4_node_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

CHECK("tc", "ipfrag_helpers_ipv4")
int test_ipfrag_helpers_ipv4_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *l2;
	struct iphdr *l3;
	fraginfo_t fraginfo;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	l2 = data;
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	assert(l3->frag_off == 0);

	/* Non-fragmented packet */
	fraginfo = ipfrag_encode_ipv4(l3);
	assert(!ipfrag_is_fragment(fraginfo));
	assert(ipfrag_has_l4_header(fraginfo));

	/* First fragment */
	l3->id = bpf_htons(0x1234);
	l3->frag_off = bpf_htons(1 << 13); /* MF flag */
	fraginfo = ipfrag_encode_ipv4(l3);
	assert(ipfrag_is_fragment(fraginfo));
	assert(ipfrag_has_l4_header(fraginfo));
	assert(ipfrag_get_protocol(fraginfo) == IPPROTO_UDP);
	assert((__be16)ipfrag_get_id(fraginfo) == bpf_htons(0x1234));

	/* Non-first fragment */
	l3->frag_off = bpf_htons((1 << 13) | 0x100);
	fraginfo = ipfrag_encode_ipv4(l3);
	assert(ipfrag_is_fragment(fraginfo));
	assert(!ipfrag_has_l4_header(fraginfo));
	assert(ipfrag_get_protocol(fraginfo) == IPPROTO_UDP);
	assert((__be16)ipfrag_get_id(fraginfo) == bpf_htons(0x1234));

	/* Last fragment */
	l3->frag_off = bpf_htons(0x200);
	fraginfo = ipfrag_encode_ipv4(l3);
	assert(ipfrag_is_fragment(fraginfo));
	assert(!ipfrag_has_l4_header(fraginfo));
	assert(ipfrag_get_protocol(fraginfo) == IPPROTO_UDP);
	assert((__be16)ipfrag_get_id(fraginfo) == bpf_htons(0x1234));

	test_finish();
}

PKTGEN("tc", "ipfrag_helpers_ipv6_nofrag")
int test_ipfrag_helpers_ipv6_nofrag_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)v6_node_one, (__u8 *)v6_node_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

CHECK("tc", "ipfrag_helpers_ipv6_nofrag")
int test_ipfrag_helpers_ipv6_nofrag_check(struct __ctx_buff *ctx __maybe_unused)
{
	void *data, *data_end;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	fraginfo_t fraginfo, fraginfo2;
	__u8 nexthdr;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		test_fatal("l3 out of bounds");

	/* Non-fragmented packet */
	fraginfo = ipv6_get_fraginfo(ctx, l3);
	if (fraginfo < 0)
		test_fatal("ipv6_get_fraginfo failed");
	assert(!ipfrag_is_fragment(fraginfo));
	assert(ipfrag_has_l4_header(fraginfo));

	/* ipv6_hdrlen_with_fraginfo should return the same fraginfo. */
	nexthdr = l3->nexthdr;
	if (ipv6_hdrlen_with_fraginfo(ctx, &nexthdr, &fraginfo2) < 0)
		test_fatal("ipv6_hdrlen_with_fraginfo failed");
	assert(fraginfo == fraginfo2);

	test_finish();
}

PKTGEN("tc", "ipfrag_helpers_ipv6")
int test_ipfrag_helpers_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct ipv6_frag_hdr *fraghdr;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)mac_one, (__u8 *)mac_two);

	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;

	ipv6hdr__set_addrs(l3, (__u8 *)v6_node_one, (__u8 *)v6_node_two);

	fraghdr = (struct ipv6_frag_hdr *)
		pktgen__append_ipv6_extension_header(&builder, NEXTHDR_FRAGMENT, 0);
	if (!fraghdr)
		return TEST_ERROR;
	if ((void *)(fraghdr + 1) > ctx_data_end(ctx))
		return TEST_ERROR;

	fraghdr->id = (__be32)(0x12345678);
	fraghdr->frag_off = bpf_htons(1); /* MF flag */

	l4 = pktgen__push_default_udphdr(&builder);
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

CHECK("tc", "ipfrag_helpers_ipv6")
int test_ipfrag_helpers_ipv6_check(struct __ctx_buff *ctx __maybe_unused)
{
	void *data, *data_end;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct ipv6_frag_hdr *fraghdr;
	fraginfo_t fraginfo, fraginfo2;
	__u8 nexthdr;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		test_fatal("l3 out of bounds");

	fraghdr = (void *)(l3 + 1);
	if ((void *)(fraghdr + 1) > data_end)
		test_fatal("fraghdr out of bounds");

	/* First fragment */
	fraginfo = ipv6_get_fraginfo(ctx, l3);
	if (fraginfo < 0)
		test_fatal("ipv6_get_fraginfo failed");
	assert(ipfrag_is_fragment(fraginfo));
	assert(ipfrag_has_l4_header(fraginfo));
	assert(ipfrag_get_protocol(fraginfo) == IPPROTO_UDP);
	assert(ipfrag_get_id(fraginfo) == (__be32)(0x12345678));

	/* ipv6_hdrlen_with_fraginfo should return the same fraginfo. */
	nexthdr = l3->nexthdr;
	if (ipv6_hdrlen_with_fraginfo(ctx, &nexthdr, &fraginfo2) < 0)
		test_fatal("ipv6_hdrlen_with_fraginfo failed");
	assert(fraginfo == fraginfo2);

	/* Non-first fragment */
	fraghdr->frag_off = bpf_htons((0x100 << 3) | 1);
	fraginfo = ipv6_get_fraginfo(ctx, l3);
	if (fraginfo < 0)
		test_fatal("ipv6_get_fraginfo failed");
	assert(ipfrag_is_fragment(fraginfo));
	assert(!ipfrag_has_l4_header(fraginfo));
	assert(ipfrag_get_protocol(fraginfo) == IPPROTO_UDP);
	assert(ipfrag_get_id(fraginfo) == (__be32)(0x12345678));

	/* ipv6_hdrlen_with_fraginfo should return the same fraginfo. */
	nexthdr = l3->nexthdr;
	if (ipv6_hdrlen_with_fraginfo(ctx, &nexthdr, &fraginfo2) < 0)
		test_fatal("ipv6_hdrlen_with_fraginfo failed");
	assert(fraginfo == fraginfo2);

	/* Last fragment */
	fraghdr->frag_off = bpf_htons(0x200 << 3);
	fraginfo = ipv6_get_fraginfo(ctx, l3);
	if (fraginfo < 0)
		test_fatal("ipv6_get_fraginfo failed");
	assert(ipfrag_is_fragment(fraginfo));
	assert(!ipfrag_has_l4_header(fraginfo));
	assert(ipfrag_get_protocol(fraginfo) == IPPROTO_UDP);
	assert(ipfrag_get_id(fraginfo) == (__be32)(0x12345678));

	/* ipv6_hdrlen_with_fraginfo should return the same fraginfo. */
	nexthdr = l3->nexthdr;
	if (ipv6_hdrlen_with_fraginfo(ctx, &nexthdr, &fraginfo2) < 0)
		test_fatal("ipv6_hdrlen_with_fraginfo failed");
	assert(fraginfo == fraginfo2);

	test_finish();
}
