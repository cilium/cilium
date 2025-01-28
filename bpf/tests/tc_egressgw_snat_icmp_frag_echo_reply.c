// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

// uncomment for debug
// #define TEST_DEBUG

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_IPV4_FRAGMENTS
#define ENABLE_NODEPORT

#include <node_config.h>

#ifdef TEST_DEBUG
static int s_debug_level = 10;
#endif

#include "bpf_host.c"
#include "tc_egressgw_snat_icmp_frag.h"

static icmp4_frag_test_info_t s_icmp4_frag_test_info;

__always_inline int check_revnat_icmp4_frag_pkt(
	struct __ctx_buff		*a_ctx,
	icmp4_frag_test_info_t	*a_test_info __maybe_unused,
	char					**a_test_result_cursor,
	char					**a_suite_result_cursor,
	char					**a_test_result_status,
	int						a_packet_index __attribute__((unused)))
{
	char *test_result_cursor	= *a_test_result_cursor;
	char *suite_result_cursor	= *a_suite_result_cursor;
	char *test_result_status	= *a_test_result_status;

	int res, ret = TEST_ERROR;

	do {
		test_pdebug_args(10, "-- check packet: %u --\n",
			a_packet_index
		);

		__u16					proto;
		void					*data, *data_end;
		struct iphdr			*ip4;
		struct icmphdr			*icmp4;
		struct trace_ctx		trace;

		struct ipv4_nat_target target = {
			.addr = bpf_htonl(IP_HOST),
			.min_port = NODEPORT_PORT_MIN_NAT,
			.max_port = NODEPORT_PORT_MIN_NAT,
		};

		if (0 == a_packet_index) {
			struct ipv4_nat_entry state;

			struct ipv4_ct_tuple tuple = {
				.nexthdr = IPPROTO_ICMP,
				.saddr = bpf_htonl(IP_ENDPOINT),
				.daddr = bpf_htonl(IP_WORLD),
				.sport = bpf_htons(NODEPORT_PORT_MIN_NAT),
				.flags = 0,
			};

			void *map = get_cluster_snat_map_v4(target.cluster_id);
			if (!map) {
				test_fatal("get_cluster_snat_map_v4() failed\n");
			}

			res = snat_v4_new_mapping(a_ctx, map, &tuple, &state, &target,
				false, NULL);
			if (res) {
				test_fatal("snat_v4_new_mapping() failed with code: %d\n",
					res
				);
			}
		}

		// this is the entry-point of the test, calling
		// snat_v4_rev_nat()
		res = snat_v4_rev_nat(a_ctx, &target, &trace, NULL);
		if (res) {
			test_fatal("snat_v4_rev_nat() failed with code: %d\n", res);
		}

		test_pdebug(10, "snat_v4_rev_nat() done (success)\n");

		// ethertype
		res = validate_ethertype(a_ctx, &proto);
		if (!res) {
			test_fatal("validate_ethertype() failed\n");
		}
		test_pdebug(10, "validate_ethertype() done (success)\n");

		// revalidate_data
		res = revalidate_data(a_ctx, &data, &data_end, &ip4);
		if (!res) {
			test_fatal("revalidate_data() failed\n");
		}
		if (data + a_test_info->pkt_size > data_end) {
			test_fatal("packet shrank\n");
		}
		test_pdebug(10, "revalidate_data() done (success)\n");

		// ip4_id
		__u16 ip4_id = bpf_ntohs(ip4->id);
		if (a_test_info->ip4_id != ip4_id) {
			test_fatal("wrong ip4_id: %d\n", ip4_id);
		}
		test_pdebug_args(10, "ip4 id: %d (valid)\n", ip4_id);

		// ip4 protocol
		if (IPPROTO_ICMP != ip4->protocol) {
			test_fatal("IPPROTO_ICMP(%u) != ip4->protocol(%u)\n",
				IPPROTO_ICMP,
				ip4->protocol
			);
		}
		test_pdebug_args(10, "ip4 protocol: %d (IPPROTO_ICMP) (valid)\n",
			ip4->protocol
		);

		__u32 ip4_saddr = bpf_ntohl(ip4->saddr);
		if (ip4_saddr != IP_WORLD) {
			test_fatal("bpf_ntohl(ip4->saddr(0x%lx)) != IP_WORLD(0x%lx)\n",
				ip4_saddr,
				IP_HOST
			);
		}
		test_pdebug_args(10, "ip4 saddr: %lx (IP_WORLD)\n",
			ip4_saddr
		);

		__u32 ip4_daddr = bpf_ntohl(ip4->daddr);
		if (ip4_daddr != IP_ENDPOINT) {
			test_fatal("bpf_ntohl(ip4->daddr(0x%lx)) != IP_ENDPOINT(0x%lx)\n",
				ip4_daddr,
				IP_ENDPOINT
			);
		}
		test_pdebug_args(10, "ip4 daddr: %lx (IP_ENDPOINT) (rev nat is valid)\n",
			ip4_daddr
		);

		__u8	ip4_hlen			= ip4->ihl * 4;
		__u32	ip4_tot_len			= bpf_ntohs(ip4->tot_len);
		__u16	ip4_frag_off		= bpf_ntohs(ip4->frag_off)	& 0x1FFF;
		bool	ip4_more_fragments	= (bpf_ntohs(ip4->frag_off)	& 0x2000) >> 13;

		if (20 != ip4_hlen) {
			test_fatal("ip4->ihl * 5 is not 20 (%u)\n",
				ip4_hlen
			);
		}
		test_pdebug(10, "ip4->ihl * 5 is 20 (valid)\n");

		if (0 == a_packet_index) {
			// first packet
			if (0 != ip4_frag_off) {
				test_fatal("ip4->frag_off is not 0 (%u)\n",
					ip4_frag_off
				);
			}
			test_pdebug(10, "ip4->frag_off is 0 (valid)\n");
			// more fragments
			if (!ip4_more_fragments) {
				test_fatal("ip4 more fragments bit is not set\n");
			}
			test_pdebug(10, "ip4 more fragments bit is set (valid)\n");
			// ip4_tot_len
			if (TEST_MTU != ip4_tot_len) {
				test_fatal("ip4 tot_len is not %u (%u)\n",
					TEST_MTU,
					ip4_tot_len
				);
			}
			test_pdebug_args(10, "ip4 tot_len is %u (valid)\n",
				ip4_tot_len
			);
			// icmp4 type
			if ((void *)ip4 + ip4_hlen + sizeof(struct icmphdr) > data_end) {
				test_fatal("packet shrank\n");
			}
			icmp4 = (struct icmphdr *)((void *)ip4 + ip4_hlen);
			if (ICMP_ECHOREPLY != icmp4->type) {
				test_fatal("icmp4->type is not %u (ICMP_ECHOREPLY) (%u)\n",
					ICMP_ECHOREPLY,
					icmp4->type
				);
			}
			test_pdebug_args(10, "icmp4->type is %u (ICMP_ECHOREPLY) (valid)\n",
				icmp4->type
			);
		} else if (1 == a_packet_index) {
			// intermediate packet
			if (0 == ip4_frag_off) {
				test_fatal("ip4->frag_off is 0\n");
			}
			test_pdebug_args(10, "ip4->frag_off is not 0 (%u) (valid)\n",
				ip4_frag_off
			);
			// more fragments
			if (!ip4_more_fragments) {
				test_fatal("ip4 more fragments bit is not set\n");
			}
			test_pdebug(10, "ip4 more fragments bit is set (valid)\n");
			// ip4_tot_len
			if (TEST_MTU != ip4_tot_len) {
				test_fatal("ip4 tot_len is not %u (%u)\n",
					TEST_MTU,
					ip4_tot_len
				);
			}
			test_pdebug_args(10, "ip4 tot_len is %u (valid)\n",
				ip4_tot_len
			);
		} else if (2 == a_packet_index) {
			// last packet
			if (0 == ip4_frag_off) {
				test_fatal("ip4->frag_off is 0\n");
			}
			test_pdebug_args(10, "ip4->frag_off is not 0 (%u) (valid)\n",
				ip4_frag_off
			)
			// more fragments
			if (ip4_more_fragments) {
				test_fatal("ip4 more fragments bit is set\n");
			}
			test_pdebug(10, "ip4 more fragments bit is not set (valid)\n");
			// ip4_tot_len
			if (110 != ip4_tot_len) {
				test_fatal("ip4 tot_len is not %u (%u)\n",
					110,
					ip4_tot_len
				);
			}
			test_pdebug_args(10, "ip4 tot_len is %u (valid)\n",
				ip4_tot_len
			);
		} else {
			test_fatal("unsupported packet index: %d\n", a_packet_index);
		}

		test_pdebug(10, "checks PASSED\n");

		// all ok
		ret = TEST_PASS;
	} while (false);

	// test_pdebug_args(10, "check_snat_icmp4_frag_pkt, ret: %d\n", ret);
	*a_test_result_cursor	= test_result_cursor;
	*a_suite_result_cursor	= suite_result_cursor;
	*a_test_result_status	= test_result_status;
	return ret;
}

CHECK("tc", "snat4_icmp_frag_ingress")
int test_snat4_icmp_frag_ingress(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	int res;

	// ingress (echo REPLY)
	do {
		icmp4_frag_test_info_t *test_info = &s_icmp4_frag_test_info;
		memset(test_info, 0x00, sizeof(*test_info));

		test_info->egress				= false;
		test_info->icmp4_type			= ICMP_ECHOREPLY;
		test_info->icmp4_payload_len	= 3000;
		test_info->ip4_id				= 1235;
		test_info->icmp4_code			= 0;
		test_info->icmp4_id				= NODEPORT_PORT_MIN_NAT;

		__u16 packet_count = (test_info->icmp4_payload_len / TEST_MTU) + 1;

		for (int i = 0; i < packet_count; i++) {
			test_pdebug_args(10, "----- make ingress packet (%d) -----\n", i);
			test_pdebug_args(10, "ip4_next_fragment_offset: %d\n",
				test_info->ip4_next_fragment_offset
			);
			test_pdebug_args(10, "ctx->data: %lx,"
				" ctx->data_end: %lx"
				"\n",
				ctx->data,
				ctx->data_end
			);

			// make packet
			res = mk_icmp4_frag_pkt(
				ctx,
				test_info,
				&test_result_cursor,
				&suite_result_cursor
			);
			if (TEST_PASS != res) {
				test_fatal(
					"mk_icmp4_frag_pkt() failed,"
					" res: %d,"
					" ip4_next_fragment_offset: %u"
					"\n",
					res,
					test_info->ip4_next_fragment_offset
				);
			}

			// check revnat packet
			res = check_revnat_icmp4_frag_pkt(
				ctx,
				test_info,
				&test_result_cursor,
				&suite_result_cursor,
				&test_result_status,
				i
			);
			if (TEST_PASS != res) {
				test_fatal(
					"check_revnat_icmp4_frag_pkt() failed,"
					" res: %d,"
					" ip4_next_fragment_offset: %u"
					"\n",
					res,
					test_info->ip4_next_fragment_offset
				);
			}

			if (test_info->ip4_next_fragment_offset >= test_info->icmp4_payload_len) {
				// end of payload
				break;
			}
		}
	} while (false);

#ifdef TEST_DEBUG
	test_fatal("end of test\n");
#endif

	test_finish();
}

