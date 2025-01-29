// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#define ENABLE_IPV4
#define ENABLE_IPV4_FRAGMENTS
#define ENABLE_NODEPORT

#include <node_config.h>

#include "bpf_host.c"
#include "tc_egressgw_snat_icmp_frag.h"

static struct icmp4_frag_test_info s_icmp4_frag_test_info;

CHECK("tc", "snat4_icmp_frag_egress")
int test_snat4_icmp_frag_egress(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	int res;

	/* egress (echo request) */
	do {
		struct icmp4_frag_test_info *test_info = &s_icmp4_frag_test_info;

		memset(test_info, 0x00, sizeof(*test_info));

		test_info->egress = true;
		test_info->icmp4_type = ICMP_ECHO;
		test_info->icmp4_payload_len = 3000;
		test_info->ip4_id = 1234;
		test_info->icmp4_code = 0;
		test_info->icmp4_id = NODEPORT_PORT_MIN_NAT;

		__u16 packet_count = (test_info->icmp4_payload_len / TEST_MTU) + 1;

		for (int i = 0; i < packet_count; i++) {
			/* make packet */
			res = mk_icmp4_frag_pkt(ctx, test_info);
			if (res != TEST_PASS)
				test_fatal("mk_icmp4_frag_pkt() failed\n");

			/* check snat packet */
			struct trace_ctx trace;
			__u16 proto;
			void *data, *data_end;
			struct iphdr *ip4;
			struct icmphdr *icmp4;
			int l4_off;

			struct ipv4_ct_tuple tuple = {
				.nexthdr = IPPROTO_ICMP,
				.flags = 0
			};

			struct ipv4_nat_target target = {
				.addr = bpf_htonl(IP_HOST),
				.min_port = NODEPORT_PORT_MIN_NAT,
				.max_port = NODEPORT_PORT_MIN_NAT,
				.egress_gateway	= true,
				.needs_ct = true
			};

			if (test_info->icmp4_type == ICMP_ECHO) {
				tuple.saddr = bpf_htonl(IP_ENDPOINT);
				tuple.daddr = bpf_htonl(IP_WORLD);
				tuple.sport = bpf_htons(test_info->icmp4_id);
			} else {
				tuple.saddr = bpf_htonl(IP_WORLD);
				tuple.daddr = bpf_htonl(IP_ENDPOINT);
				tuple.sport = bpf_htons(test_info->icmp4_id);
			}

			res = revalidate_data(ctx, &data, &data_end, &ip4);
			if (!res)
				test_fatal("revalidate_data() failed\n");

			if (data + test_info->pkt_size > data_end)
				test_fatal("packet shrank\n");

			l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

			/* snat_v4_nat */
			res = snat_v4_nat(ctx, &tuple, ip4, l4_off, ipv4_has_l4_header(ip4),
					  &target, &trace, NULL);
			if (IS_ERR(res))
				test_fatal("snat_v4_nat() failed with code: %d\n", res);

			/* ethertype */
			res = validate_ethertype(ctx, &proto);
			if (!res)
				test_fatal("validate_ethertype() failed\n");

			/* revalidate_data */
			res = revalidate_data(ctx, &data, &data_end, &ip4);
			if (!res)
				test_fatal("revalidate_data() failed\n");

			if (data + test_info->pkt_size > data_end)
				test_fatal("packet shrank\n");

			/* ip4_id */
			__u16 ip4_id = bpf_ntohs(ip4->id);

			if (test_info->ip4_id != ip4_id)
				test_fatal("wrong ip4_id: %d\n", ip4_id);

			/* ip4 protocol */
			if (ip4->protocol != IPPROTO_ICMP)
				test_fatal("IPPROTO_ICMP(%u) != ip4->protocol(%u)\n",
					   IPPROTO_ICMP, ip4->protocol);

			__u32 ip4_saddr = bpf_ntohl(ip4->saddr);

			if (ip4_saddr != IP_HOST)
				test_fatal("bpf_ntohl(ip4->saddr(0x%lx)) != IP_HOST(0x%lx)\n",
					   ip4_saddr, IP_HOST);

			__u32 ip4_daddr = bpf_ntohl(ip4->daddr);

			if (ip4_daddr != IP_WORLD)
				test_fatal("bpf_ntohl(ip4->daddr(0x%lx)) != IP_WORLD(0x%lx)\n",
					   ip4_daddr, IP_WORLD);

			__u8 ip4_hlen = ip4->ihl * 4;
			__u32 ip4_tot_len = bpf_ntohs(ip4->tot_len);
			__u16 ip4_frag_off = bpf_ntohs(ip4->frag_off) & 0x1FFF;
			bool ip4_more_fragments = (bpf_ntohs(ip4->frag_off) & 0x2FFF) >> 13;

			if (ip4_hlen != 20)
				test_fatal("ip4->ihl * 5 is not 20 (%u)\n",
					   ip4_hlen
				);

			if (i == 0) {
				/* first packet */
				if (ip4_frag_off != 0)
					test_fatal("ip4->frag_off is not 0 (%u)\n", ip4_frag_off);
				/* more fragments */
				if (!ip4_more_fragments)
					test_fatal("ip4 more fragments bit is not set\n");
				/* ip4_tot_len */
				if (ip4_tot_len != TEST_MTU)
					test_fatal("ip4 tot_len is not %u (%u)\n",
						   TEST_MTU, ip4_tot_len);
				/* icmp4 type */
				if ((void *)ip4 + ip4_hlen + sizeof(struct icmphdr) > data_end)
					test_fatal("packet shrank\n");
				icmp4 = (struct icmphdr *)((void *)ip4 + ip4_hlen);
				if (icmp4->type != ICMP_ECHO)
					test_fatal("icmp4->type is not %u (ICMP_ECHO) (%u)\n",
						   ICMP_ECHO, icmp4->type
					);
			} else if (i == 1) {
				/* intermediate packet */
				if (ip4_frag_off == 0)
					test_fatal("ip4->frag_off is 0\n");
				/* more fragments */
				if (!ip4_more_fragments)
					test_fatal("ip4 more fragments bit is not set\n");
				/* ip4_tot_len */
				if (ip4_tot_len != TEST_MTU)
					test_fatal("ip4 tot_len is not %u (%u)\n",
						   TEST_MTU, ip4_tot_len
					);
			} else if (i == 2) {
				/* last packet */
				if (ip4_frag_off == 0)
					test_fatal("ip4->frag_off is 0\n");
				/* more fragments */
				if (ip4_more_fragments)
					test_fatal("ip4 more fragments bit is set\n");
				/* ip4_tot_len */
				if (ip4_tot_len != 110)
					test_fatal("ip4 tot_len is not %u (%u)\n",
						   110, ip4_tot_len);
			} else {
				test_fatal("unsupported packet index: %d\n", i);
			}

			/* all ok */

			if (test_info->ip4_next_fragment_offset >= test_info->icmp4_payload_len)
				/* end of payload */
				break;
		}
	} while (false);

	test_finish();
}

