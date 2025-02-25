/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#define IP_ENDPOINT	1
#define IP_HOST 2
#define IP_ROUTER 3
#define IP_WORLD 4

#define TEST_MTU 1500

struct icmp4_frag_test_info {
	__u8 packet_type;
	__u16 icmp4_payload_len;
	__u8 egress;
	__u16 ip4_id;
	__u8 ip4_more_fragments;
	__u16 ip4_fragment_offset;
	__u16 ip4_next_fragment_offset;
	__u8 icmp4_type;
	__u8 icmp4_code;
	__u16 icmp4_id;
	__u16 pkt_size;
};

#define TO_NETDEV	0
#define FROM_NETDEV	1

static __always_inline int mk_icmp4_frag_pkt(struct __ctx_buff *ctx,
					     struct icmp4_frag_test_info *test_info)
{
	struct iphdr *l3_ptr = NULL;
	__u16 len;

	char *orig = (char *)(long)ctx->data;
	char *data_end = (char *)(long)ctx->data_end;
	char *data = orig;

	/* L2 */
	struct ethhdr l2_egress = {
		.h_proto = bpf_htons(ETH_P_IP),
		.h_source = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		.h_dest = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67}
	};
	struct ethhdr l2_ingress = {
		.h_proto = bpf_htons(ETH_P_IP),
		.h_source = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67},
		.h_dest = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	};
	struct ethhdr *l2;

	if (test_info->egress)
		l2 = &l2_egress;
	else
		l2 = &l2_ingress;

	len = sizeof(struct ethhdr);
	if (data + len > data_end)
		return TEST_FAIL;
	memcpy(data, l2, len);
	data += len;

	/* L3 */
	__u32 saddr, daddr;

	if (test_info->egress) {
		saddr = IP_ENDPOINT;
		daddr = IP_WORLD;
	} else {
		saddr = IP_WORLD;
		daddr = IP_HOST;
	}

	struct iphdr l3 = {
		.version = 4,
		.ihl = 5,
		.protocol = IPPROTO_ICMP,
		.saddr = bpf_htonl(saddr),
		.daddr = bpf_htonl(daddr),
		.id = bpf_htons(test_info->ip4_id)
	};
	l3_ptr = (struct iphdr *)data;
	len = sizeof(struct iphdr);
	if (data + len > data_end)
		return TEST_FAIL;
	memcpy(data, &l3, len);
	data += len;

	/* L4 */
	if (!test_info->ip4_next_fragment_offset) {
		struct icmphdr l4 __align_stack_8 = {
			.type = test_info->icmp4_type,
			.un = {
				.echo = {
					.id = bpf_htons(test_info->icmp4_id)
				},
			},
		};
		len = sizeof(struct icmphdr);
		if (data + len > data_end)
			return TEST_FAIL;
		memcpy(data, &l4, len);
		data += len;
	}

	__u16 avail_len = TEST_MTU - (__u16)(data - orig);
	__u16 remain_len = test_info->icmp4_payload_len
		- test_info->ip4_next_fragment_offset;

	if (avail_len == 0)
		return TEST_FAIL;

	/* set current fragment offset (before it can be changed) */
	test_info->ip4_fragment_offset = test_info->ip4_next_fragment_offset;

	if (remain_len > 0) {
		__u16 ip4_payload_len = 0;

		if (avail_len < remain_len)
			ip4_payload_len = avail_len;
		else
			ip4_payload_len = remain_len;
		data += ip4_payload_len;
		test_info->ip4_next_fragment_offset += ip4_payload_len;
	}

	test_info->ip4_more_fragments = false;
	if (test_info->ip4_next_fragment_offset < test_info->icmp4_payload_len)
		/* we have more payload */
		test_info->ip4_more_fragments = true;

	test_info->pkt_size = (__u16)(data - orig);

	/* update l3 header */
	l3.frag_off = bpf_htons((__u16)((test_info->ip4_fragment_offset & 0x1FFF)
		+ (test_info->ip4_more_fragments << 13)
	));
	l3.tot_len = bpf_htons(test_info->pkt_size);
	len	= sizeof(struct iphdr);
	memcpy((void *)l3_ptr, &l3, len);

	return TEST_PASS;
}

