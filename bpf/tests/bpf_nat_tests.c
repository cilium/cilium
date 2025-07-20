// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_SCTP
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#include <bpf/config/node.h>

#define DEBUG

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

#include "bpf_nat_tuples.h"

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
				.mtu = bpf_htons(MTU),
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
	return (int)(dst - orig);
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
		.max_port = NODEPORT_PORT_MIN_NAT,
	};
	struct ipv4_nat_entry state;
	struct trace_ctx trace;
	void *map;

	map = get_cluster_snat_map_v4(target.cluster_id);
	assert(map);

	ret = snat_v4_new_mapping(ctx, map, &tuple, &state, &target,
				  false, NULL);
	assert(ret == 0);

	/* This is the entry-point of the test, calling
	 * snat_v4_rev_nat().
	 */
	ret = snat_v4_rev_nat(ctx, &target, &trace, NULL);
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
		.max_port = NODEPORT_PORT_MIN_NAT,
	};
	struct ipv4_nat_entry state;
	struct trace_ctx trace;
	void *map;

	map = get_cluster_snat_map_v4(target.cluster_id);
	assert(map);

	ret = snat_v4_new_mapping(ctx, map, &tuple, &state, &target,
				  false, NULL);
	assert(ret == 0);

	/* This is the entry-point of the test, calling
	 * snat_v4_rev_nat().
	 */
	ret = snat_v4_rev_nat(ctx, &target, &trace, NULL);
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
		.max_port = NODEPORT_PORT_MIN_NAT,
	};
	struct ipv4_nat_entry state;
	struct trace_ctx trace;
	void *map;

	map = get_cluster_snat_map_v4(target.cluster_id);
	assert(map);

	ret = snat_v4_new_mapping(ctx, map, &tuple, &state, &target,
				  false, NULL);
	assert(ret == 0);

	/* This is the entry-point of the test, calling
	 * snat_v4_rev_nat().
	 */
	ret = snat_v4_rev_nat(ctx, &target, &trace, NULL);
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
		.max_port = NODEPORT_PORT_MIN_NAT,
	};
	struct ipv4_nat_entry state;
	struct trace_ctx trace;
	void *map;

	map = get_cluster_snat_map_v4(target.cluster_id);
	assert(map);

	ret = snat_v4_new_mapping(ctx, map, &tuple, &state, &target,
				  false, NULL);
	assert(ret == 0);

	/* This is the entry-point of the test, calling
	 * snat_v4_rev_nat().
	 */
	ret = snat_v4_rev_nat(ctx, &target, &trace, NULL);
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
		.max_port = NODEPORT_PORT_MIN_NAT - 1,
	};
	struct ipv4_nat_entry state;
	void *map;

	map = get_cluster_snat_map_v4(target.cluster_id);
	assert(map);

	ret = snat_v4_new_mapping(ctx, map, &tuple, &state, &target,
				  false, NULL);
	assert(ret == 0);

	struct ipv4_ct_tuple icmp_tuple = {};
	struct trace_ctx trace;
	void *data, *data_end;
	struct iphdr *ip4;
	int l4_off;

	assert(revalidate_data(ctx, &data, &data_end, &ip4));
	snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &icmp_tuple);
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	/* This is the entry-point of the test, calling
	 * snat_v4_nat().
	 */
	ret = snat_v4_nat(ctx, &icmp_tuple, ip4, ipfrag_encode_ipv4(ip4),
			  l4_off, &target, &trace, NULL);
	assert(ret == 0);

	__u16 proto;
	int l3_off;
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
	    .max_port = NODEPORT_PORT_MIN_NAT - 1,
	};
	struct ipv4_nat_entry state;
	void *map;

	map = get_cluster_snat_map_v4(target.cluster_id);
	assert(map);

	ret = snat_v4_new_mapping(ctx, map, &tuple, &state, &target,
				  false, NULL);
	assert(ret == 0);

	struct ipv4_ct_tuple icmp_tuple = {};
	struct trace_ctx trace;
	void *data, *data_end;
	struct iphdr *ip4;
	int l4_off;

	assert(revalidate_data(ctx, &data, &data_end, &ip4));
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &icmp_tuple);

	/* This is the entry-point of the test, calling
	 * snat_v4_nat().
	 */
	ret = snat_v4_nat(ctx, &icmp_tuple, ip4, ipfrag_encode_ipv4(ip4),
			  l4_off, &target, &trace, NULL);
	assert(ret == 0);

	__u16 proto;
	int l3_off;
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
	    .max_port = NODEPORT_PORT_MIN_NAT - 1,
	};
	struct ipv4_nat_entry state;
	void *map;

	map = get_cluster_snat_map_v4(target.cluster_id);
	assert(map);

	ret = snat_v4_new_mapping(ctx, map, &tuple, &state, &target,
				  false, NULL);
	assert(ret == 0);

	struct ipv4_ct_tuple icmp_tuple = {};
	struct trace_ctx trace;
	void *data, *data_end;
	struct iphdr *ip4;
	int l4_off;

	assert(revalidate_data(ctx, &data, &data_end, &ip4));
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &icmp_tuple);

	/* This is the entry-point of the test, calling
	 * snat_v4_nat().
	 */
	ret = snat_v4_nat(ctx, &icmp_tuple, ip4, ipfrag_encode_ipv4(ip4),
			  l4_off, &target, &trace, NULL);
	assert(ret == 0);

	__u16 proto;
	int l3_off;
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
	void *map;

	map = get_cluster_snat_map_v4(target.cluster_id);
	assert(map);

	ret = snat_v4_new_mapping(ctx, map, &tuple, &state, &target,
				  false, NULL);
	assert(ret == 0);

	struct ipv4_ct_tuple icmp_tuple = {};
	struct trace_ctx trace;
	void *data, *data_end;
	struct iphdr *ip4;
	int l4_off;

	assert(revalidate_data(ctx, &data, &data_end, &ip4));
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &icmp_tuple);

	/* This is the entry-point of the test, calling
	 * snat_v4_nat().
	 */
	ret = snat_v4_nat(ctx, &icmp_tuple, ip4, ipfrag_encode_ipv4(ip4),
			  l4_off, &target, &trace, NULL);
	assert(ret == 0);

	__u16 proto;
	int l3_off;
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

__u32 daddrs[] = {
	0x01010101, 0x02020202, 0x03030303, 0x04040404,
	0x05050505, 0x06060606, 0x07070707, 0x08080808,
};

/* 16 sets of port samples. */
#define SNAT_TEST_CLIENTS 16
#define SNAT_TEST_ITERATIONS \
	SIMPLE_MIN(ARRAY_SIZE(tcp_ports0) * SNAT_TEST_CLIENTS, \
		   ARRAY_SIZE(daddrs) * (NODEPORT_PORT_MAX_NAT - NODEPORT_PORT_MIN_NAT + 1))

static __u32 retries_before[SNAT_COLLISION_RETRIES + 1];
static __u32 retries_10percent[SNAT_COLLISION_RETRIES + 1];
static __u32 retries_50percent[SNAT_COLLISION_RETRIES + 1];
static __u32 retries_75percent[SNAT_COLLISION_RETRIES + 1];
static __u32 retries_100percent[SNAT_COLLISION_RETRIES + 1];

static __always_inline bool store_retries(__u32 *buf, bool dump)
{
	for (__u32 i = 0; i <= SNAT_COLLISION_RETRIES; i++) {
		__u32 *v = map_lookup_elem(&cilium_snat_v4_alloc_retries, &(__u32){i});

		if (!v)
			return false;
		buf[i] = *v - retries_before[i];
	}

	if (dump)
		for (__u32 i = 0; i <= SNAT_COLLISION_RETRIES; i++)
			printk("retries[%u] = %u\n", i, buf[i]);

	return true;
}

struct snat_callback_ctx {
	struct __ctx_buff *ctx;
	int err;
	__u32 fails;
	__u32 fail_thres;
};

static long snat_callback_tcp(__u32 i, struct snat_callback_ctx *ctx)
{
	struct ipv4_ct_tuple otuple = {
		.saddr = bpf_htonl(0x0A000101),
		.dport = bpf_htons(80),
		.nexthdr = IPPROTO_TCP,
		.flags = NAT_DIR_EGRESS,
	};
	struct ipv4_nat_entry ostate;
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.needs_ct = true,
		.egress_gateway = true,
		.addr = bpf_htonl(0x0AA40001),
	};
	__s8 ext_err = 0;
	void *map;
	__u16 *ports;

	/* Keep in sync with SNAT_TEST_CLIENTS. */
	__u32 client = i & 15;
	__u32 port_idx = i >> 4;

	otuple.saddr += 0x100 * client;
	otuple.daddr = bpf_htonl(daddrs[get_prandom_u32() % ARRAY_SIZE(daddrs)]);

	if (port_idx >= ARRAY_SIZE(tcp_ports0))
		return 1;

	/* Keep in sync with SNAT_TEST_CLIENTS. */
	switch (client) {
	case 0: ports = tcp_ports0; break;
	case 1: ports = tcp_ports1; break;
	case 2: ports = tcp_ports2; break;
	case 3: ports = tcp_ports3; break;
	case 4: ports = tcp_ports4; break;
	case 5: ports = tcp_ports5; break;
	case 6: ports = tcp_ports6; break;
	case 7: ports = tcp_ports7; break;
	case 8: ports = tcp_ports8; break;
	case 9: ports = tcp_ports9; break;
	case 10: ports = tcp_ports10; break;
	case 11: ports = tcp_ports11; break;
	case 12: ports = tcp_ports12; break;
	case 13: ports = tcp_ports13; break;
	case 14: ports = tcp_ports14; break;
	case 15: ports = tcp_ports15; break;
	}
	otuple.sport = bpf_htons(ports[port_idx]);
	map = get_cluster_snat_map_v4(0);
	ctx->err = snat_v4_new_mapping(ctx->ctx, map, &otuple, &ostate, &target, true, &ext_err);

	if (ctx->err == DROP_NAT_NO_MAPPING && !ext_err) {
		ctx->err = 0;
		++ctx->fails;
		/* Store the number of iterations when we start having 5% of failures. */
		if (!ctx->fail_thres && ctx->fails >= (i + 1) / 20)
			ctx->fail_thres = i;
	}

	if (ctx->err)
		printk("error %d at iteration %u\n", ctx->err, i);

	switch (i) {
	case SNAT_TEST_ITERATIONS / 10:
		printk("TCP port allocation retries at 10%% of test:\n");
		if (!store_retries(retries_10percent, true))
			ctx->err = -ENOMEM;
		break;
	case SNAT_TEST_ITERATIONS / 2:
		printk("TCP port allocation retries at 50%% of test:\n");
		if (!store_retries(retries_50percent, true))
			ctx->err = -ENOMEM;
		break;
	case SNAT_TEST_ITERATIONS * 3 / 4:
		printk("TCP port allocation retries at 75%% of test:\n");
		if (!store_retries(retries_75percent, true))
			ctx->err = -ENOMEM;
		break;
	}

	return ctx->err != 0;
}

CHECK("tc", "nat4_port_allocation")
int test_nat4_port_allocation_tcp_check(struct __ctx_buff *ctx)
{
	struct snat_callback_ctx cb_ctx = {
		.ctx = ctx,
	};
	long iters;

	test_init();
	/* This test checks the effectiveness of port allocation algorithm in SNAT.
	 */

	assert(store_retries(retries_before, false));
	iters = loop(SNAT_TEST_ITERATIONS, snat_callback_tcp, &cb_ctx, 0);
	assert(iters == SNAT_TEST_ITERATIONS);
	assert(cb_ctx.err == 0);
	printk("TCP port allocation retries at 100%% of test:\n");
	assert(store_retries(retries_100percent, true));

	printk("5%% failures happened at iteration %u\n", cb_ctx.fail_thres);

	/* Non-negligible amount of failures happens after 70% of the test. */
	assert(cb_ctx.fail_thres >= SNAT_TEST_ITERATIONS * 0.7);

	/* Only occasional failures at 50% of the test. */
	assert(retries_50percent[SNAT_COLLISION_RETRIES] < 15);

	/* Less than 7% of failures at 75% of the test. */
	assert(retries_75percent[SNAT_COLLISION_RETRIES] < SNAT_TEST_ITERATIONS * 0.75 * 0.07);

	/* Less than 16% of failures at 100% of the test. */
	assert(retries_100percent[SNAT_COLLISION_RETRIES] < SNAT_TEST_ITERATIONS * 0.16);

	/* Negligible amount of ports allocated after 10+ retries. */
	for (__u32 i = 10; i < SNAT_COLLISION_RETRIES; i++)
		assert(retries_100percent[i] < 100);

	/* More ports could be allocated after fewer retries. */
	for (__u32 i = 1; i <= 5; i++)
		assert(retries_100percent[i] <= retries_100percent[i - 1]);
	for (__u32 i = 6; i < SNAT_COLLISION_RETRIES; i++)
		assert(retries_100percent[i] <= retries_100percent[5]);

	test_finish();
}

static long snat_callback_udp(__u32 i, struct snat_callback_ctx *ctx)
{
	struct ipv4_ct_tuple otuple = {
		.saddr = bpf_htonl(0x0A000101),
		.dport = bpf_htons(80),
		.nexthdr = IPPROTO_UDP,
		.flags = NAT_DIR_EGRESS,
	};
	struct ipv4_nat_entry ostate;
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.needs_ct = true,
		.egress_gateway = true,
		.addr = bpf_htonl(0x0AA40001),
	};
	__s8 ext_err = 0;
	void *map;
	__u16 *ports;

	/* Keep in sync with SNAT_TEST_CLIENTS. */
	__u32 client = i & 15;
	__u32 port_idx = i >> 4;

	otuple.saddr += 0x100 * client;
	otuple.daddr = bpf_htonl(daddrs[get_prandom_u32() % ARRAY_SIZE(daddrs)]);

	if (port_idx >= ARRAY_SIZE(udp_ports0))
		return 1;

	/* Keep in sync with SNAT_TEST_CLIENTS. */
	switch (client) {
	case 0: ports = udp_ports0; break;
	case 1: ports = udp_ports1; break;
	case 2: ports = udp_ports2; break;
	case 3: ports = udp_ports3; break;
	case 4: ports = udp_ports4; break;
	case 5: ports = udp_ports5; break;
	case 6: ports = udp_ports6; break;
	case 7: ports = udp_ports7; break;
	case 8: ports = udp_ports8; break;
	case 9: ports = udp_ports9; break;
	case 10: ports = udp_ports10; break;
	case 11: ports = udp_ports11; break;
	case 12: ports = udp_ports12; break;
	case 13: ports = udp_ports13; break;
	case 14: ports = udp_ports14; break;
	case 15: ports = udp_ports15; break;
	}
	otuple.sport = bpf_htons(ports[port_idx]);
	map = get_cluster_snat_map_v4(0);
	ctx->err = snat_v4_new_mapping(ctx->ctx, map, &otuple, &ostate, &target, true, &ext_err);

	if (ctx->err == DROP_NAT_NO_MAPPING && !ext_err) {
		ctx->err = 0;
		++ctx->fails;
		/* Store the number of iterations when we start having 5% of failures. */
		if (!ctx->fail_thres && ctx->fails >= (i + 1) / 20)
			ctx->fail_thres = i;
	}

	if (ctx->err)
		printk("error %d at iteration %u\n", ctx->err, i);

	switch (i) {
	case SNAT_TEST_ITERATIONS / 10:
		printk("UDP port allocation retries at 10%% of test:\n");
		if (!store_retries(retries_10percent, true))
			ctx->err = -ENOMEM;
		break;
	case SNAT_TEST_ITERATIONS / 2:
		printk("UDP port allocation retries at 50%% of test:\n");
		if (!store_retries(retries_50percent, true))
			ctx->err = -ENOMEM;
		break;
	case SNAT_TEST_ITERATIONS * 3 / 4:
		printk("UDP port allocation retries at 75%% of test:\n");
		if (!store_retries(retries_75percent, true))
			ctx->err = -ENOMEM;
		break;
	}

	return ctx->err != 0;
}

CHECK("tc", "nat4_port_allocation")
int test_nat4_port_allocation_udp_check(struct __ctx_buff *ctx)
{
	struct snat_callback_ctx cb_ctx = {
		.ctx = ctx,
	};
	long iters;

	test_init();
	/* This test checks the effectiveness of port allocation algorithm in SNAT.
	 */

	assert(store_retries(retries_before, false));
	iters = loop(SNAT_TEST_ITERATIONS, snat_callback_udp, &cb_ctx, 0);
	assert(iters == SNAT_TEST_ITERATIONS);
	assert(cb_ctx.err == 0);
	printk("UDP port allocation retries at 100%% of test:\n");
	assert(store_retries(retries_100percent, true));

	printk("5%% failures happened at iteration %u\n", cb_ctx.fail_thres);

	/* Non-negligible amount of failures happens after 70% of the test. */
	assert(cb_ctx.fail_thres >= SNAT_TEST_ITERATIONS * 0.7);

	/* Only occasional failures at 50% of the test. */
	assert(retries_50percent[SNAT_COLLISION_RETRIES] < 15);

	/* Less than 7% of failures at 75% of the test. */
	assert(retries_75percent[SNAT_COLLISION_RETRIES] < SNAT_TEST_ITERATIONS * 0.75 * 0.07);

	/* Less than 16% of failures at 100% of the test. */
	assert(retries_100percent[SNAT_COLLISION_RETRIES] < SNAT_TEST_ITERATIONS * 0.16);

	/* Negligible amount of ports allocated after 11+ retries. */
	for (__u32 i = 11; i < SNAT_COLLISION_RETRIES; i++)
		assert(retries_100percent[i] < 100);

	/* More ports could be allocated after fewer retries. */
	for (__u32 i = 1; i <= 5; i++)
		assert(retries_100percent[i] <= retries_100percent[i - 1]);
	for (__u32 i = 6; i < SNAT_COLLISION_RETRIES; i++)
		assert(retries_100percent[i] <= retries_100percent[5]);

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
