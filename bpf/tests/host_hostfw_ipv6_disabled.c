// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test: host firewall without the IPv6 datapath */
#define ENABLE_IPV4			1
#define ENABLE_HOST_FIREWALL		1

/* Not defined by lib/icmp6.h, which only names the ND types it handles */
#define ICMP6_RA_MSG_TYPE		134

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *remote_mac = mac_two;

#include "lib/bpf_host.h"

/* When the IPv6 datapath is not compiled in, the host firewall cannot
 * enforce policies on IPv6. IPv6 traffic must still reach the kernel
 * stack (as without the host firewall) instead of being dropped as
 * unknown L3: otherwise enabling the host firewall on an IPv4-only
 * Cilium config breaks IPv6 neighbor discovery for the node.
 */

/* ICMPv6 router advertisement from a fabric peer to the node. */
PKTGEN("tc", "hostfw_ipv6_disabled_1_ingress")
int hostfw_ipv6_disabled_ingress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *icmp6;

	pktgen__init(&builder, ctx);

	icmp6 = pktgen__push_ipv6_icmp6_packet(&builder,
					       (__u8 *)remote_mac, (__u8 *)node_mac,
					       (__u8 *)v6_ext_node_one,
					       (__u8 *)v6_node_one,
					       ICMP6_RA_MSG_TYPE);
	if (!icmp6)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hostfw_ipv6_disabled_1_ingress")
int hostfw_ipv6_disabled_ingress_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK("tc", "hostfw_ipv6_disabled_1_ingress")
int hostfw_ipv6_disabled_ingress_check(const struct __ctx_buff *ctx)
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

	test_finish();
}

/* ICMPv6 neighbor solicitation from the node to a fabric peer. */
PKTGEN("tc", "hostfw_ipv6_disabled_2_egress")
int hostfw_ipv6_disabled_egress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *icmp6;

	pktgen__init(&builder, ctx);

	icmp6 = pktgen__push_ipv6_icmp6_packet(&builder,
					       (__u8 *)node_mac, (__u8 *)remote_mac,
					       (__u8 *)v6_node_one,
					       (__u8 *)v6_ext_node_one,
					       ICMP6_NS_MSG_TYPE);
	if (!icmp6)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hostfw_ipv6_disabled_2_egress")
int hostfw_ipv6_disabled_egress_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK("tc", "hostfw_ipv6_disabled_2_egress")
int hostfw_ipv6_disabled_egress_check(const struct __ctx_buff *ctx)
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

	test_finish();
}
