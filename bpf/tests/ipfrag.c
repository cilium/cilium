// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"
#include <node_config.h>

#include <lib/ipfrag.h>

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

CHECK("tc", "ipfrag_helpers_ipv6")
int test_ipfrag_helpers_ipv6_check(struct __ctx_buff *ctx __maybe_unused)
{
	fraginfo_t fraginfo;

	test_init();

	/* Stub fraginfo until parsing IPv6 extension headers is implemented. */

	/* Non-fragmented packet */
	fraginfo = 0x0000001100000000;
	assert(!ipfrag_is_fragment(fraginfo));
	assert(ipfrag_has_l4_header(fraginfo));

	/* First fragment */
	fraginfo = 0x0000011112345678;
	assert(ipfrag_is_fragment(fraginfo));
	assert(ipfrag_has_l4_header(fraginfo));
	assert(ipfrag_get_protocol(fraginfo) == IPPROTO_UDP);
	assert(ipfrag_get_id(fraginfo) == (__be32)(0x12345678));

	/* Non-first fragment */
	fraginfo = 0x0000031112345678;
	assert(ipfrag_is_fragment(fraginfo));
	assert(!ipfrag_has_l4_header(fraginfo));
	assert(ipfrag_get_protocol(fraginfo) == IPPROTO_UDP);
	assert(ipfrag_get_id(fraginfo) == (__be32)(0x12345678));

	test_finish();
}
