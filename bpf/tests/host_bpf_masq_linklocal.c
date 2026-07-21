// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* BPF masquerade on a node whose only IPv6 address is a link-local.
 *
 * When no selected device has a global IPv6 address, the best IPv6 fallback
 * node address is the link-local (fallbackAddresses.update() ranks addresses by
 * public-vs-private and scope, and does not exclude link-locals), so that is
 * what bpfMasqAddrs() hands the datapath as nat_ipv6_masquerade. A node like
 * this is what BGP unnumbered peering runs on, and the Router Advertisements it
 * emits are sourced from that same link-local - which makes
 * __snat_v6_needs_masquerade() answer NAT_NEEDED on its very first test, so
 * snat_v6_nat() has to decide what to do with them.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6			1
#define ENABLE_MASQUERADE_IPV6		1
#define ENABLE_NODEPORT			1

#define NODE_IP_V6			v6_node_one_ll

/* Set port ranges to have deterministic source port selection */
#include "nodeport_defaults.h"

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "lib/bpf_host.h"

ASSIGN_CONFIG(union v6addr, nat_ipv6_masquerade, { .addr = v6_node_one_ll_addr})

/* Router Advertisements must reach the wire untranslated. Masquerading one
 * would advertise the masquerade address as the router's link-local, and an
 * ICMPv6 type that snat_v6_nat() does not recognise is dropped outright with
 * DROP_NAT_UNSUPP_PROTO.
 */
PKTGEN(PROG_TYPE, "host_bpf_masq_ll_v6_1_icmp6_ra")
int host_bpf_masq_ll_v6_1_icmp6_ra_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *icmp;

	pktgen__init(&builder, ctx);

	icmp = pktgen__push_ipv6_icmp6_packet(&builder,
					      (__u8 *)node_mac, (__u8 *)server_mac,
					      (__u8 *)NODE_IP_V6,
					      (__u8 *)v6_all_nodes_mcast,
					      ICMP6_RA_MSG_TYPE);
	if (!icmp)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "host_bpf_masq_ll_v6_1_icmp6_ra")
int host_bpf_masq_ll_v6_1_icmp6_ra_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "host_bpf_masq_ll_v6_1_icmp6_ra")
int host_bpf_masq_ll_v6_1_icmp6_ra_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	data += sizeof(__u32);
	if (data + sizeof(struct ethhdr) > data_end)
		test_fatal("ctx doesn't fit ethhdr");
	data += sizeof(struct ethhdr);
	if (data + sizeof(struct ipv6hdr) > data_end)
		test_fatal("ctx doesn't fit ipv6hdr");

	/* the RA must still carry the link-local source it was sent with */
	struct ipv6hdr *ip6 = data;
	{
		const __u8 expected_src[16] = v6_node_one_ll_addr;

		assert(!memcmp(&ip6->saddr, expected_src, 16));
	}

	test_finish();
}

/* Router Solicitations get the same treatment. */
PKTGEN(PROG_TYPE, "host_bpf_masq_ll_v6_2_icmp6_rs")
int host_bpf_masq_ll_v6_2_icmp6_rs_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *icmp;

	pktgen__init(&builder, ctx);

	icmp = pktgen__push_ipv6_icmp6_packet(&builder,
					      (__u8 *)node_mac, (__u8 *)server_mac,
					      (__u8 *)NODE_IP_V6,
					      (__u8 *)v6_all_routers_mcast,
					      ICMP6_RS_MSG_TYPE);
	if (!icmp)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "host_bpf_masq_ll_v6_2_icmp6_rs")
int host_bpf_masq_ll_v6_2_icmp6_rs_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "host_bpf_masq_ll_v6_2_icmp6_rs")
int host_bpf_masq_ll_v6_2_icmp6_rs_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	data += sizeof(__u32);
	if (data + sizeof(struct ethhdr) > data_end)
		test_fatal("ctx doesn't fit ethhdr");
	data += sizeof(struct ethhdr);
	if (data + sizeof(struct ipv6hdr) > data_end)
		test_fatal("ctx doesn't fit ipv6hdr");

	struct ipv6hdr *ip6 = data;
	{
		const __u8 expected_src[16] = v6_node_one_ll_addr;

		assert(!memcmp(&ip6->saddr, expected_src, 16));
	}

	test_finish();
}
