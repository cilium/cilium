// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#define ENABLE_SCTP
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#include <node_config.h>

#undef EVENTS_MAP
#define EVENTS_MAP test_events_map
#define DEBUG

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

#define IP_ENDPOINT 1
#define IP_HOST     2
#define IP_ROUTER   3
#define IP_WORLD    4

static char pkt[100];

__always_inline int mk_icmp4_error_pkt(void *dst, __u8 error_hdr, bool egress)
{
	void *orig = dst;

	struct ethhdr l2 = {
		.h_source = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		.h_dest = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67},
		.h_proto = bpf_htons(ETH_P_IP)
	};
	memcpy(dst, &l2, sizeof(struct ethhdr));
	dst += sizeof(struct ethhdr);

	/* Building an IP/ICMP Error Unreach need to fragment sent by
	 * a networking equipment IP_ROUTER in response to a packet
	 * that is exceeding the MTU.
	 */
	unsigned int saddr = egress ? IP_ENDPOINT : IP_ROUTER;
	unsigned int daddr = egress ? IP_WORLD : IP_HOST;
	struct iphdr l3 = {
		.version = 4,
		.ihl = 5,
		.protocol = IPPROTO_ICMP,
		.saddr = bpf_htonl(saddr),
		.daddr = bpf_htonl(daddr),
	};
	memcpy(dst, &l3, sizeof(struct iphdr));
	dst += sizeof(struct iphdr);

	struct icmphdr icmphdr __align_stack_8 = {
		.type           = ICMP_DEST_UNREACH,
		.code           = ICMP_FRAG_NEEDED,
		.un = {
			.frag = {
				.mtu = bpf_htons(THIS_MTU),
			},
		},
	};
	memcpy(dst, &icmphdr, sizeof(struct icmphdr));
	dst += sizeof(struct icmphdr);

	/* Embedded packet is referring the original packet that triggers the
	 * ICMP.
	 */
	struct iphdr inner_l3 = {
		.version = 4,
		.ihl = 5,
		.protocol = error_hdr,
		.saddr = bpf_htonl(IP_HOST),
		.daddr = bpf_htonl(IP_WORLD),
	};
	if (egress) {
		inner_l3.saddr = bpf_htonl(IP_WORLD);
		inner_l3.daddr = bpf_htonl(IP_ENDPOINT);
	}

	memcpy(dst, &inner_l3, sizeof(struct iphdr));
	dst += sizeof(struct iphdr);

	__u16 sport = 32768, dport = 80;

	if (egress) {
		sport = 79;
		dport = error_hdr == IPPROTO_SCTP ? 32767 : 3030;
	}

	switch (error_hdr) {
	case IPPROTO_TCP: {
		struct tcphdr inner_l4 = {
			.source = bpf_htons(sport),
			.dest = bpf_htons(dport),
		};
		memcpy(dst, &inner_l4, sizeof(struct tcphdr));
		dst += sizeof(struct tcphdr);
	}
		break;
	case IPPROTO_UDP: {
		struct udphdr inner_l4 = {
			.source = bpf_htons(sport),
			.dest = bpf_htons(dport),
		};
		memcpy(dst, &inner_l4, sizeof(struct udphdr));
		dst += sizeof(struct udphdr);
	}
		break;
	case IPPROTO_SCTP: {
		struct {
			__be16 sport;
			__be16 dport;
		} inner_l4;

		inner_l4.sport = bpf_htons(sport),
		inner_l4.dport = bpf_htons(dport),

		memcpy(dst, &inner_l4, sizeof(inner_l4));
		dst += sizeof(inner_l4);
	}
		break;
	case IPPROTO_ICMP: {
		struct icmphdr inner_l4 __align_stack_8 = {
			.type = egress ? ICMP_ECHOREPLY : ICMP_ECHO,
			.un = {
				.echo = {
					.id = bpf_htons(egress ? dport : sport)
				},
			},
		};
		memcpy(dst, &inner_l4, sizeof(struct icmphdr));
		dst += sizeof(struct icmphdr);
	}
		break;
	}
	return dst - orig;
}

CHECK("tc", "nat4_icmp_error_tcp")
int test_nat4_icmp_error_tcp(__maybe_unused struct __ctx_buff *ctx)
{
	int pkt_size = mk_icmp4_error_pkt(pkt, IPPROTO_TCP, false);
	{
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if (data + pkt_size > data_end)
			return TEST_ERROR;

		memcpy(data, pkt, pkt_size);
	}

	test_init();
	/* The test is validating that the function snat_v4_rev_nat()
	 * will rev-nat the ICMP Unreach error need to fragment to the
	 * correct endpoint.  Also, to be valid, the embedded packet
	 * should be NATed as-well, meaning that the source addr of
	 * the original packet will be switched from IP_HOST to
	 * IP_ENDPOINT, Also for TCP/UDP the dest port and ICMP the
	 * identifier.
	 *
	 * This test is validating the TCP case.
	 */

	int ret;

	/* As a pre-requist we intruct the NAT table
	 * to simulate an ingress packet sent by
	 * endpoint to the world.
	 */
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.saddr = bpf_htonl(IP_ENDPOINT),
		.daddr = bpf_htonl(IP_WORLD),
		.sport = bpf_htons(3030),
		.dport = bpf_htons(80),
		.flags = 0,
	};
	struct ipv4_nat_target target = {
		.addr = bpf_htonl(IP_HOST),
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MIN_NAT + 1,
	};
	struct ipv4_nat_entry state;

	ret = snat_v4_new_mapping(ctx, &tuple, &state, &target,
				  snat_v4_needs_ct(&tuple, &target));
	assert(ret == 0);

	/* This is the entry-point of the test, calling
	 * snat_v4_rev_nat().
	 */
	ret = snat_v4_rev_nat(ctx, &target, NULL);
	assert(ret == 0);

	__u16 proto;
	void *data;
	void *data_end;

	int l3_off;
	int l4_off;
	struct iphdr *ip4;
	struct icmphdr icmphdr __align_stack_8;

	assert(validate_ethertype(ctx, &proto));
	assert(revalidate_data(ctx, &data, &data_end, &ip4));
	if (data + pkt_size > data_end)
		test_fatal("packet shrank");

	/* Validating outer headers */
	assert(ip4->protocol == IPPROTO_ICMP);
	assert(ip4->saddr == bpf_htonl(IP_ROUTER));
	assert(ip4->daddr == bpf_htonl(IP_ENDPOINT));

	l3_off = ETH_HLEN;
	l4_off = l3_off + ipv4_hdrlen(ip4);
	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		test_fatal("can't load icmp headers");
	assert(icmphdr.type == ICMP_DEST_UNREACH);
	assert(icmphdr.code == ICMP_FRAG_NEEDED);

	/* Validating inner headers */
	int in_l3_off;
	int in_l4_off;
	struct iphdr in_ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} in_l4hdr;

	in_l3_off = l4_off + sizeof(icmphdr);
	if (ctx_load_bytes(ctx, in_l3_off, &in_ip4,
			   sizeof(in_ip4)) < 0)
		test_fatal("can't load embedded ip headers");
	assert(in_ip4.protocol == IPPROTO_TCP);
	assert(in_ip4.saddr == bpf_htonl(IP_ENDPOINT));
	assert(in_ip4.daddr == bpf_htonl(IP_WORLD));

	in_l4_off = in_l3_off + ipv4_hdrlen(&in_ip4);
	if (ctx_load_bytes(ctx, in_l4_off, &in_l4hdr, sizeof(in_l4hdr)) < 0)
		test_fatal("can't load embedded l4 headers");
	assert(in_l4hdr.sport == bpf_htons(3030));
	assert(in_l4hdr.dport == bpf_htons(80));

	test_finish();
}

CHECK("tc", "nat4_icmp_error_udp")
int test_nat4_icmp_error_udp(__maybe_unused struct __ctx_buff *ctx)
{
	int pkt_size = mk_icmp4_error_pkt(pkt, IPPROTO_UDP, false);
	{
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if (data + pkt_size > data_end)
			return TEST_ERROR;

		memcpy(data, pkt, pkt_size);
	}

	test_init();
	/* The test is validating that the function snat_v4_rev_nat()
	 * will rev-nat the ICMP Unreach error need to fragment to the
	 * correct endpoint.  Also, to be valid, the embedded packet
	 * should be NATed as-well, meaning that the source addr of
	 * the original packet will be switched from IP_HOST to
	 * IP_ENDPOINT, Also for TCP/UDP the dest port and ICMP the
	 * identifier.
	 *
	 * This test is validating the UDP case.
	 */

	int ret;

	/* As a pre-requist we intruct the NAT table
	 * to simulate an ingress packet sent by
	 * endpoint to the world.
	 */
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_UDP,
		.saddr = bpf_htonl(IP_ENDPOINT),
		.daddr = bpf_htonl(IP_WORLD),
		.sport = bpf_htons(9999),
		.dport = bpf_htons(80),
		.flags = 0,
	};
	struct ipv4_nat_target target = {
		.addr = bpf_htonl(IP_HOST),
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MIN_NAT + 1,
	};
	struct ipv4_nat_entry state;

	ret = snat_v4_new_mapping(ctx, &tuple, &state, &target,
				  snat_v4_needs_ct(&tuple, &target));
	assert(ret == 0);

	/* This is the entry-point of the test, calling
	 * snat_v4_rev_nat().
	 */
	ret = snat_v4_rev_nat(ctx, &target, NULL);
	assert(ret == 0);

	__u16 proto;
	void *data;
	void *data_end;

	int l3_off;
	int l4_off;
	struct iphdr *ip4;
	struct icmphdr icmphdr __align_stack_8;

	assert(validate_ethertype(ctx, &proto));
	assert(revalidate_data(ctx, &data, &data_end, &ip4));
	if (data + pkt_size > data_end)
		test_fatal("packet shrank");

	/* Validating outer headers */
	assert(ip4->protocol == IPPROTO_ICMP);
	assert(ip4->saddr == bpf_htonl(IP_ROUTER));
	assert(ip4->daddr == bpf_htonl(IP_ENDPOINT));

	l3_off = ETH_HLEN;
	l4_off = l3_off + ipv4_hdrlen(ip4);
	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		test_fatal("can't load icmp headers");
	assert(icmphdr.type == ICMP_DEST_UNREACH);
	assert(icmphdr.code == ICMP_FRAG_NEEDED);

	/* Validating inner headers */
	int in_l3_off;
	int in_l4_off;
	struct iphdr in_ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} in_l4hdr;

	in_l3_off = l4_off + sizeof(icmphdr);
	if (ctx_load_bytes(ctx, in_l3_off, &in_ip4,
			   sizeof(in_ip4)) < 0)
		test_fatal("can't load embedded ip headers");
	assert(in_ip4.protocol == IPPROTO_UDP);
	assert(in_ip4.saddr == bpf_htonl(IP_ENDPOINT));
	assert(in_ip4.daddr == bpf_htonl(IP_WORLD));

	in_l4_off = in_l3_off + ipv4_hdrlen(&in_ip4);
	if (ctx_load_bytes(ctx, in_l4_off, &in_l4hdr, sizeof(in_l4hdr)) < 0)
		test_fatal("can't load embedded l4 headers");
	assert(in_l4hdr.sport == bpf_htons(9999));
	assert(in_l4hdr.dport == bpf_htons(80));

	test_finish();
}

CHECK("tc", "nat4_icmp_error_icmp")
int test_nat4_icmp_error_icmp(__maybe_unused struct __ctx_buff *ctx)
{
	int pkt_size = mk_icmp4_error_pkt(pkt, IPPROTO_ICMP, false);
	{
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if (data + pkt_size > data_end)
			return TEST_ERROR;

		memcpy(data, pkt, pkt_size);
	}

	test_init();
	/* The test is validating that the function snat_v4_rev_nat()
	 * will rev-nat the ICMP Unreach error need to fragment to the
	 * correct endpoint.  Also, to be valid, the embedded packet
	 * should be NATed as-well, meaning that the source addr of
	 * the original packet will be switched from IP_HOST to
	 * IP_ENDPOINT, Also for TCP/UDP the dest port and ICMP the
	 * identifier.
	 *
	 * This test is validating the ICMP case.
	 */

	int ret;

	/* As a pre-requist we intruct the NAT table
	 * to simulate an ingress packet sent by
	 * endpoint to the world.
	 */
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_ICMP,
		.saddr = bpf_htonl(IP_ENDPOINT),
		.daddr = bpf_htonl(IP_WORLD),
		.sport = bpf_htons(123),
		.flags = 0,
	};
	struct ipv4_nat_target target = {
		.addr = bpf_htonl(IP_HOST),
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MIN_NAT + 1,
	};
	struct ipv4_nat_entry state;

	ret = snat_v4_new_mapping(ctx, &tuple, &state, &target,
				  snat_v4_needs_ct(&tuple, &target));
	assert(ret == 0);

	/* This is the entry-point of the test, calling
	 * snat_v4_rev_nat().
	 */
	ret = snat_v4_rev_nat(ctx, &target, NULL);
	assert(ret == 0);

	__u16 proto;
	void *data;
	void *data_end;

	int l3_off;
	int l4_off;
	struct iphdr *ip4;
	struct icmphdr icmphdr __align_stack_8;

	assert(validate_ethertype(ctx, &proto));
	assert(revalidate_data(ctx, &data, &data_end, &ip4));
	if (data + pkt_size > data_end)
		test_fatal("packet shrank");

	/* Validating outer headers */
	assert(ip4->protocol == IPPROTO_ICMP);
	assert(ip4->saddr == bpf_htonl(IP_ROUTER));
	assert(ip4->daddr == bpf_htonl(IP_ENDPOINT));

	l3_off = ETH_HLEN;
	l4_off = l3_off + ipv4_hdrlen(ip4);
	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		test_fatal("can't load icmp headers");
	assert(icmphdr.type == ICMP_DEST_UNREACH);
	assert(icmphdr.code == ICMP_FRAG_NEEDED);

	/* Validating inner headers */
	int in_l3_off;
	int in_l4_off;
	struct iphdr in_ip4;
	struct icmphdr in_l4hdr __align_stack_8;

	in_l3_off = l4_off + sizeof(icmphdr);
	if (ctx_load_bytes(ctx, in_l3_off, &in_ip4,
			   sizeof(in_ip4)) < 0)
		test_fatal("can't load embedded ip headers");
	assert(in_ip4.protocol == IPPROTO_ICMP);
	assert(in_ip4.saddr == bpf_htonl(IP_ENDPOINT));
	assert(in_ip4.daddr == bpf_htonl(IP_WORLD));

	in_l4_off = in_l3_off + ipv4_hdrlen(&in_ip4);
	if (ctx_load_bytes(ctx, in_l4_off, &in_l4hdr, sizeof(in_l4hdr)) < 0)
		test_fatal("can't load embedded l4 headers");
	assert(in_l4hdr.un.echo.id == bpf_htons(123));

	test_finish();
}

CHECK("tc", "nat4_icmp_error_sctp")
int test_nat4_icmp_error_sctp(__maybe_unused struct __ctx_buff *ctx)
{
	int pkt_size = mk_icmp4_error_pkt(pkt, IPPROTO_SCTP, false);
	{
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if (data + pkt_size > data_end)
			return TEST_ERROR;

		memcpy(data, pkt, pkt_size);
	}

	test_init();
	/* This test is validating the SCTP case.
	 */

	int ret;

	/* As a pre-requist we intruct the NAT table
	 * to simulate an ingress packet sent by
	 * endpoint to the world.
	 */
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_SCTP,
		.saddr = bpf_htonl(IP_ENDPOINT),
		.daddr = bpf_htonl(IP_WORLD),
		.sport = bpf_htons(9999),
		.dport = bpf_htons(80),
		.flags = 0,
	};
	struct ipv4_nat_target target = {
		.addr = bpf_htonl(IP_HOST),
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MIN_NAT + 1,
	};
	struct ipv4_nat_entry state;

	ret = snat_v4_new_mapping(ctx, &tuple, &state, &target,
				  snat_v4_needs_ct(&tuple, &target));
	assert(ret == 0);

	/* This is the entry-point of the test, calling
	 * snat_v4_rev_nat().
	 */
	ret = snat_v4_rev_nat(ctx, &target, NULL);
	assert(ret == DROP_CSUM_L4);

	/* nothing really change with udp/tcp */
	test_finish();
}

CHECK("tc", "nat4_icmp_error_tcp_egress")
int test_nat4_icmp_error_tcp_egress(__maybe_unused struct __ctx_buff *ctx)
{
	int pkt_size = mk_icmp4_error_pkt(pkt, IPPROTO_TCP, true);
	{
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if (data + pkt_size > data_end)
			return TEST_ERROR;

		memcpy(data, pkt, pkt_size);
	}

	test_init();
	/* The test is validating that the function snat_v4_nat()
	 * will nat the ICMP Unreach error need to fragment to the
	 * correct source.  Also, to be valid, the embedded packet
	 * should be NATed as-well, meaning that the dest addr of
	 * the original packet will be switched from IP_ENDPOINT to
	 * IP_HOST, Also for TCP/UDP the dest port and ICMP the
	 * identifier.
	 *
	 * This test is validating the TCP case.
	 */

	int ret;

	/* As a pre-requist we intruct the NAT table
	 * to simulate an egress packet sent by
	 * endpoint to the world.
	 */
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.saddr = bpf_htonl(IP_ENDPOINT),
		.daddr = bpf_htonl(IP_WORLD),
		.sport = bpf_htons(3030),
		.dport = bpf_htons(79),
		.flags = 0,
	};
	struct ipv4_nat_target target = {
		.addr = bpf_htonl(IP_HOST),
		.min_port = NODEPORT_PORT_MIN_NAT - 1,
		.max_port = NODEPORT_PORT_MIN_NAT,
	};
	struct ipv4_nat_entry state;

	ret = snat_v4_new_mapping(ctx, &tuple, &state, &target,
				  snat_v4_needs_ct(&tuple, &target));
	assert(ret == 0);

	/* This is the entry-point of the test, calling
	 * snat_v4_nat().
	 */
	ret = snat_v4_nat(ctx, &target, NULL);
	assert(ret == 0);

	__u16 proto;
	void *data;
	void *data_end;

	int l3_off;
	int l4_off;
	struct iphdr *ip4;
	struct icmphdr icmphdr __align_stack_8;

	assert(validate_ethertype(ctx, &proto));
	assert(revalidate_data(ctx, &data, &data_end, &ip4));
	if (data + pkt_size > data_end)
		test_fatal("packet shrank");

	/* Validating outer headers */
	assert(ip4->protocol == IPPROTO_ICMP);
	assert(ip4->saddr == bpf_htonl(IP_HOST));
	assert(ip4->daddr == bpf_htonl(IP_WORLD));

	l3_off = ETH_HLEN;
	l4_off = l3_off + ipv4_hdrlen(ip4);
	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		test_fatal("can't load icmp headers");
	assert(icmphdr.type == ICMP_DEST_UNREACH);
	assert(icmphdr.code == ICMP_FRAG_NEEDED);

	/* Validating inner headers */
	int in_l3_off;
	int in_l4_off;
	struct iphdr in_ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} in_l4hdr;

	in_l3_off = l4_off + sizeof(icmphdr);
	if (ctx_load_bytes(ctx, in_l3_off, &in_ip4,
			   sizeof(in_ip4)) < 0)
		test_fatal("can't load embedded ip headers");
	assert(in_ip4.protocol == IPPROTO_TCP);
	assert(in_ip4.saddr == bpf_htonl(IP_WORLD));
	assert(in_ip4.daddr == bpf_htonl(IP_HOST));

	in_l4_off = in_l3_off + ipv4_hdrlen(&in_ip4);
	if (ctx_load_bytes(ctx, in_l4_off, &in_l4hdr, sizeof(in_l4hdr)) < 0)
		test_fatal("can't load embedded l4 headers");
	assert(in_l4hdr.sport == bpf_htons(79));
	assert(in_l4hdr.dport == bpf_htons(32767));

	test_finish();
}

CHECK("tc", "nat4_icmp_error_udp_egress")
int test_nat4_icmp_error_udp_egress(__maybe_unused struct __ctx_buff *ctx)
{
	int pkt_size = mk_icmp4_error_pkt(pkt, IPPROTO_UDP, true);
	{
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if (data + pkt_size > data_end)
			return TEST_ERROR;

		memcpy(data, pkt, pkt_size);
	}

	test_init();
	/* The test is validating that the function snat_v4_nat()
	 * will nat the ICMP Unreach error need to fragment to the
	 * correct source.  Also, to be valid, the embedded packet
	 * should be NATed as-well, meaning that the dest addr of
	 * the original packet will be switched from IP_ENDPOINT to
	 * IP_HOST, Also for TCP/UDP the dest port and ICMP the
	 * identifier.
	 *
	 * This test is validating the UDP case.
	 */

	int ret;

	/* As a pre-requist we intruct the NAT table
	 * to simulate an egress packet sent by
	 * endpoint to the world.
	 */
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_UDP,
		.saddr = bpf_htonl(IP_ENDPOINT),
		.daddr = bpf_htonl(IP_WORLD),
		.sport = bpf_htons(3030),
		.dport = bpf_htons(79),
		.flags = 0,
	};
	struct ipv4_nat_target target = {
	    .addr = bpf_htonl(IP_HOST),
	    .min_port = NODEPORT_PORT_MIN_NAT - 1,
	    .max_port = NODEPORT_PORT_MIN_NAT,
	};
	struct ipv4_nat_entry state;

	ret = snat_v4_new_mapping(ctx, &tuple, &state, &target,
				  snat_v4_needs_ct(&tuple, &target));
	assert(ret == 0);

	/* This is the entry-point of the test, calling
	 * snat_v4_nat().
	 */
	ret = snat_v4_nat(ctx, &target, NULL);
	assert(ret == 0);

	__u16 proto;
	void *data;
	void *data_end;

	int l3_off;
	int l4_off;
	struct iphdr *ip4;
	struct icmphdr icmphdr __align_stack_8;

	assert(validate_ethertype(ctx, &proto));
	assert(revalidate_data(ctx, &data, &data_end, &ip4));
	if (data + pkt_size > data_end)
		test_fatal("packet shrank");

	/* Validating outer headers */
	assert(ip4->protocol == IPPROTO_ICMP);
	assert(ip4->saddr == bpf_htonl(IP_HOST));
	assert(ip4->daddr == bpf_htonl(IP_WORLD));

	l3_off = ETH_HLEN;
	l4_off = l3_off + ipv4_hdrlen(ip4);
	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		test_fatal("can't load icmp headers");
	assert(icmphdr.type == ICMP_DEST_UNREACH);
	assert(icmphdr.code == ICMP_FRAG_NEEDED);

	/* Validating inner headers */
	int in_l3_off;
	int in_l4_off;
	struct iphdr in_ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} in_l4hdr;

	in_l3_off = l4_off + sizeof(icmphdr);
	if (ctx_load_bytes(ctx, in_l3_off, &in_ip4,
			   sizeof(in_ip4)) < 0)
		test_fatal("can't load embedded ip headers");
	assert(in_ip4.protocol == IPPROTO_UDP);
	assert(in_ip4.saddr == bpf_htonl(IP_WORLD));
	assert(in_ip4.daddr == bpf_htonl(IP_HOST));

	in_l4_off = in_l3_off + ipv4_hdrlen(&in_ip4);
	if (ctx_load_bytes(ctx, in_l4_off, &in_l4hdr, sizeof(in_l4hdr)) < 0)
		test_fatal("can't load embedded l4 headers");
	assert(in_l4hdr.sport == bpf_htons(79));
	assert(in_l4hdr.dport == bpf_htons(32767));

	test_finish();
}

CHECK("tc", "nat4_icmp_error_icmp_egress")
int test_nat4_icmp_error_icmp_egress(__maybe_unused struct __ctx_buff *ctx)
{
	int pkt_size = mk_icmp4_error_pkt(pkt, IPPROTO_ICMP, true);
	{
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if (data + pkt_size > data_end)
			return TEST_ERROR;

		memcpy(data, pkt, pkt_size);
	}

	test_init();
	/* The test is validating that the function snat_v4_nat()
	 * will nat the ICMP Unreach error need to fragment to the
	 * correct source.  Also, to be valid, the embedded packet
	 * should be NATed as-well, meaning that the dest addr of
	 * the original packet will be switched from IP_ENDPOINT to
	 * IP_HOST, Also for TCP/UDP the dest port and ICMP the
	 * identifier.
	 *
	 * This test is validating the ICMP case.
	 */

	int ret;

	/* As a pre-requist we intruct the NAT table
	 * to simulate an egress packet sent by
	 * endpoint to the world.
	 */
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_ICMP,
		.saddr = bpf_htonl(IP_ENDPOINT),
		.daddr = bpf_htonl(IP_WORLD),
		.sport = bpf_htons(3030),
		.flags = 0,
	};
	struct ipv4_nat_target target = {
	    .addr = bpf_htonl(IP_HOST),
	    .min_port = NODEPORT_PORT_MIN_NAT - 1,
	    .max_port = NODEPORT_PORT_MIN_NAT,
	};
	struct ipv4_nat_entry state;

	ret = snat_v4_new_mapping(ctx, &tuple, &state, &target,
				  snat_v4_needs_ct(&tuple, &target));
	assert(ret == 0);

	/* This is the entry-point of the test, calling
	 * snat_v4_nat().
	 */
	ret = snat_v4_nat(ctx, &target, NULL);
	assert(ret == 0);

	__u16 proto;
	void *data;
	void *data_end;

	int l3_off;
	int l4_off;
	struct iphdr *ip4;
	struct icmphdr icmphdr __align_stack_8;

	assert(validate_ethertype(ctx, &proto));
	assert(revalidate_data(ctx, &data, &data_end, &ip4));
	if (data + pkt_size > data_end)
		test_fatal("packet shrank");

	/* Validating outer headers */
	assert(ip4->protocol == IPPROTO_ICMP);
	assert(ip4->saddr == bpf_htonl(IP_HOST));
	assert(ip4->daddr == bpf_htonl(IP_WORLD));

	l3_off = ETH_HLEN;
	l4_off = l3_off + ipv4_hdrlen(ip4);
	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		test_fatal("can't load icmp headers");
	assert(icmphdr.type == ICMP_DEST_UNREACH);
	assert(icmphdr.code == ICMP_FRAG_NEEDED);

	/* Validating inner headers */
	int in_l3_off;
	int in_l4_off;
	struct iphdr in_ip4;
	struct icmphdr in_l4hdr __align_stack_8;

	in_l3_off = l4_off + sizeof(icmphdr);
	if (ctx_load_bytes(ctx, in_l3_off, &in_ip4,
			   sizeof(in_ip4)) < 0)
		test_fatal("can't load embedded ip headers");
	assert(in_ip4.protocol == IPPROTO_ICMP);
	assert(in_ip4.saddr == bpf_htonl(IP_WORLD));
	assert(in_ip4.daddr == bpf_htonl(IP_HOST));

	in_l4_off = in_l3_off + ipv4_hdrlen(&in_ip4);
	if (ctx_load_bytes(ctx, in_l4_off, &in_l4hdr, sizeof(in_l4hdr)) < 0)
		test_fatal("can't load embedded l4 headers");
	assert(in_l4hdr.un.echo.id == bpf_htons(32767));

	test_finish();
}

CHECK("tc", "nat4_icmp_error_sctp_egress")
int test_nat4_icmp_error_sctp_egress(__maybe_unused struct __ctx_buff *ctx)
{
	int pkt_size = mk_icmp4_error_pkt(pkt, IPPROTO_SCTP, true);
	{
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if (data + pkt_size > data_end)
			return TEST_ERROR;

		memcpy(data, pkt, pkt_size);
	}

	test_init();
	/* This test is validating the SCTP case.
	 */

	int ret;

	/* As a pre-requist we intruct the NAT table
	 * to simulate an egress packet sent by
	 * endpoint to the world.
	 */
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_SCTP,
		.saddr = bpf_htonl(IP_ENDPOINT),
		.daddr = bpf_htonl(IP_WORLD),
		.sport = bpf_htons(32767),  /* STCP requires ports are the same after NAT */
		.dport = bpf_htons(79),
		.flags = 0,
	};
	struct ipv4_nat_target target = {
	    .addr = bpf_htonl(IP_HOST),
	    .min_port = NODEPORT_PORT_MIN_NAT - 1,
	    .max_port = NODEPORT_PORT_MIN_NAT,
	};
	struct ipv4_nat_entry state;

	ret = snat_v4_new_mapping(ctx, &tuple, &state, &target,
				  snat_v4_needs_ct(&tuple, &target));
	assert(ret == 0);

	/* This is the entry-point of the test, calling
	 * snat_v4_nat().
	 */
	ret = snat_v4_nat(ctx, &target, NULL);
	assert(ret == 0);

	__u16 proto;
	void *data;
	void *data_end;

	int l3_off;
	int l4_off;
	struct iphdr *ip4;
	struct icmphdr icmphdr __align_stack_8;

	assert(validate_ethertype(ctx, &proto));
	assert(revalidate_data(ctx, &data, &data_end, &ip4));
	if (data + pkt_size > data_end)
		test_fatal("packet shrank");

	/* Validating outer headers */
	assert(ip4->protocol == IPPROTO_ICMP);
	assert(ip4->saddr == bpf_htonl(IP_HOST));
	assert(ip4->daddr == bpf_htonl(IP_WORLD));

	l3_off = ETH_HLEN;
	l4_off = l3_off + ipv4_hdrlen(ip4);
	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		test_fatal("can't load icmp headers");
	assert(icmphdr.type == ICMP_DEST_UNREACH);
	assert(icmphdr.code == ICMP_FRAG_NEEDED);

	/* Validating inner headers */
	int in_l3_off;
	int in_l4_off;
	struct iphdr in_ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} in_l4hdr;

	in_l3_off = l4_off + sizeof(icmphdr);
	if (ctx_load_bytes(ctx, in_l3_off, &in_ip4,
			   sizeof(in_ip4)) < 0)
		test_fatal("can't load embedded ip headers");
	assert(in_ip4.protocol == IPPROTO_SCTP);
	assert(in_ip4.saddr == bpf_htonl(IP_WORLD));
	assert(in_ip4.daddr == bpf_htonl(IP_HOST));

	in_l4_off = in_l3_off + ipv4_hdrlen(&in_ip4);
	if (ctx_load_bytes(ctx, in_l4_off, &in_l4hdr, sizeof(in_l4hdr)) < 0)
		test_fatal("can't load embedded l4 headers");
	assert(in_l4hdr.sport == bpf_htons(79));
	assert(in_l4hdr.dport == bpf_htons(32767));

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
