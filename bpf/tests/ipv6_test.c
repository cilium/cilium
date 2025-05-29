// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include "common.h"
#include "pktgen.h"
#include <bpf/config/node.h>

#include "lib/common.h"
#include "lib/ipv6.h"

PKTGEN("xdp", "ipv6_without_extension_header")
int ipv6_without_extension_header_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)v6_node_one, (__u8 *)v6_node_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("xdp", "ipv6_without_extension_header")
int ipv6_without_extension_header_setup(__maybe_unused struct __ctx_buff *ctx)
{
	return 123;
}

CHECK("xdp", "ipv6_without_extension_header")
int ipv6_without_extension_header_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	__u32 *status_code;
	__u8 nexthdr;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == 123);

	xdp_adjust_head(ctx, 4);

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		test_fatal("l2 out of bounds");

	assert(l2->h_proto == __bpf_htons(ETH_P_IPV6));

	l3 = (void *)l2 + ETH_HLEN;
	if ((void *)(l3 + 1) > data_end)
		test_fatal("l3 out of bounds");

	nexthdr = l3->nexthdr;
	assert(ipv6_hdrlen(ctx, &nexthdr) > 0);
	assert(nexthdr == IPPROTO_TCP);

	test_finish();
}

struct ipv6_authhdr {
	struct ipv6_opt_hdr opt;
	__u16 reserved;
	int spi;
	int seq;
	char icv[];
};

PKTGEN("xdp", "ipv6_with_auth_hop_tcp")
int ipv6_with_hop_auth_tcp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct ipv6_authhdr *authhdr;
	struct ipv6_opt_hdr *l3_next;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)mac_one, (__u8 *)mac_two);

	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;

	memcpy(&l3->saddr, (__u8 *)v6_node_one, sizeof(l3->saddr));
	memcpy(&l3->daddr, (__u8 *)v6_node_two, sizeof(l3->daddr));

	l3_next = pktgen__append_ipv6_extension_header(&builder, NEXTHDR_AUTH, 0);
	if (!l3_next)
		return TEST_ERROR;

	authhdr = (struct ipv6_authhdr *)l3_next;
	if ((void *) authhdr + sizeof(struct ipv6_authhdr) > ctx_data_end(ctx))
		return TEST_ERROR;

	authhdr->spi = 0x222;
	authhdr->seq = 1;

	l3_next = pktgen__append_ipv6_extension_header(&builder, NEXTHDR_HOP, 0);
	if (!l3_next)
		return TEST_ERROR;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

	pktgen__finish(&builder);

	return 0;
}

SETUP("xdp", "ipv6_with_auth_hop_tcp")
int ipv6_with_hop_auth_tcp_setup(__maybe_unused struct __ctx_buff *ctx)
{
	return 1234;
}

CHECK("xdp", "ipv6_with_auth_hop_tcp")
int ipv6_with_hop_auth_tcp_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	__u32 *status_code;
	__u8 nexthdr;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == 1234);

	xdp_adjust_head(ctx, 4);

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		test_fatal("l2 out of bounds");

	assert(l2->h_proto == __bpf_htons(ETH_P_IPV6));

	l3 = (void *)l2 + ETH_HLEN;
	if ((void *)(l3 + 1) > data_end)
		test_fatal("l3 out of bounds");

	nexthdr = l3->nexthdr;
	assert(ipv6_hdrlen(ctx, &nexthdr) > 0);
	assert(nexthdr == IPPROTO_TCP);

	test_finish();
}

CHECK("xdp", "ipv6")
int bpf_test(__maybe_unused struct xdp_md *ctx)
{
	test_init();

	union v6addr v6;

	TEST("test_ipv6_addr_clear_suffix", {
		memset(&v6, 0xff, sizeof(v6));
		ipv6_addr_clear_suffix(&v6, 128);
		assert(bpf_ntohl(v6.p1) == 0xffffffff);
		assert(bpf_ntohl(v6.p2) == 0xffffffff);
		assert(bpf_ntohl(v6.p3) == 0xffffffff);
		assert(bpf_ntohl(v6.p4) == 0xffffffff);

		memset(&v6, 0xff, sizeof(v6));
		ipv6_addr_clear_suffix(&v6, 127);
		assert(bpf_ntohl(v6.p1) == 0xffffffff);
		assert(bpf_ntohl(v6.p2) == 0xffffffff);
		assert(bpf_ntohl(v6.p3) == 0xffffffff);
		assert(bpf_ntohl(v6.p4) == 0xfffffffe);

		memset(&v6, 0xff, sizeof(v6));
		ipv6_addr_clear_suffix(&v6, 95);
		assert(bpf_ntohl(v6.p1) == 0xffffffff);
		assert(bpf_ntohl(v6.p2) == 0xffffffff);
		assert(bpf_ntohl(v6.p3) == 0xfffffffe);
		assert(bpf_ntohl(v6.p4) == 0x00000000);

		memset(&v6, 0xff, sizeof(v6));
		ipv6_addr_clear_suffix(&v6, 1);
		assert(bpf_ntohl(v6.p1) == 0x80000000);
		assert(bpf_ntohl(v6.p2) == 0x00000000);
		assert(bpf_ntohl(v6.p3) == 0x00000000);
		assert(bpf_ntohl(v6.p4) == 0x00000000);

		memset(&v6, 0xff, sizeof(v6));
		ipv6_addr_clear_suffix(&v6, -1);
		assert(bpf_ntohl(v6.p1) == 0x00000000);
		assert(bpf_ntohl(v6.p2) == 0x00000000);
		assert(bpf_ntohl(v6.p3) == 0x00000000);
		assert(bpf_ntohl(v6.p4) == 0x00000000);
	});

	test_finish();
}

CHECK("tc", "test_ipv6_mc_helpers")
int test_ipv6_mc_helpers(__maybe_unused struct __ctx_buff *ctx)
{
	union macaddr mac = {{0}};
	union v6addr addr = {{0}};

	test_init();

	/* IPv6 mcast mac addr is 33:33 followed by 32 LSBs from target IP */
	ipv6_mc_mac_set((union v6addr *)&v6_pod_one, &mac);
	assert(mac.addr[0] == 0x33);
	assert(mac.addr[1] == 0x33);
	assert(mac.addr[2] == v6_pod_one[12]);
	assert(mac.addr[3] == v6_pod_one[13]);
	assert(mac.addr[4] == v6_pod_one[14]);
	assert(mac.addr[5] == v6_pod_one[15]);
	assert(ipv6_is_mc_mac((union v6addr *)&v6_pod_one, &mac));
	mac.addr[5] += 0x1;
	assert(!ipv6_is_mc_mac((union v6addr *)&v6_pod_one, &mac));

	/*
	 * IPv6 mcast addr is ff02::1:ffXX:XXXX where XX:XXXX are 24 LSBs from
	 * the target IP
	 */
	ipv6_mc_addr_set((union v6addr *)&v6_pod_one, &addr);
	assert(addr.addr[0] == 0xFF);
	assert(addr.addr[1] == 0x02);
	assert(addr.addr[2] == 0x00);
	assert(addr.addr[3] == 0x00);
	assert(addr.addr[4] == 0x00);
	assert(addr.addr[5] == 0x00);
	assert(addr.addr[6] == 0x00);
	assert(addr.addr[7] == 0x00);
	assert(addr.addr[8] == 0x00);
	assert(addr.addr[9] == 0x00);
	assert(addr.addr[10] == 0x00);
	assert(addr.addr[11] == 0x01);
	assert(addr.addr[12] == 0xFF);
	assert(addr.addr[13] == v6_pod_one[13]);
	assert(addr.addr[14] == v6_pod_one[14]);
	assert(addr.addr[15] == v6_pod_one[15]);

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
