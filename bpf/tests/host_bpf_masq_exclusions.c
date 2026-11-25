// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* NO_SNAT and regular endpoints sending to a destination outside the SNAT
 * exclusion CIDR and not in the ip-masq-agent map, with both of these checks
 * turned on. Neither check skips SNAT for this destination, so only the
 * NO_SNAT flag decides whether the packet is SNATed.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4			1
#define ENABLE_IPV6			1

#define NODE_IP				v4_node_one

#define SERVER_IP			v4_ext_one
#define SERVER_IP_V6			v6_ext_node_one
#define SERVER_PORT			bpf_htons(80)

/* Set port ranges to have deterministic source port selection */
#include "nodeport_defaults.h"

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "lib/bpf_host.h"

ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, { .be32 = NODE_IP})
ASSIGN_CONFIG(union v6addr, nat_ipv6_masquerade, { .addr = v6_node_one_addr})
ASSIGN_CONFIG(bool, enable_masquerade_ipv6, true)

ASSIGN_CONFIG(bool, enable_ipv4, true)
ASSIGN_CONFIG(bool, enable_ipv6, true)
ASSIGN_CONFIG(bool, enable_masquerade_ipv4, true)
ASSIGN_CONFIG(bool, enable_nodeport, true)

ASSIGN_CONFIG(bool, enable_ip_masq_agent_ipv4, true)
ASSIGN_CONFIG(bool, enable_ip_masq_agent_ipv6, true)

ASSIGN_CONFIG(struct ipv4_snat_exclusion_prefix, ipv4_snat_exclusion, {
	.dst_addr = { .be32 = IPV4(192, 168, 0, 0) },
	.bits = 16,
	.enabled = true,
})

ASSIGN_CONFIG(struct ipv6_snat_exclusion_prefix, ipv6_snat_exclusion, {
	.dst_addr = { .addr = { 0xfd, 0x04 } },
	.dst_mask = { .addr = { 0xff, 0xff } },
	.enabled = true,
})

#include "lib/endpoint.h"

static __always_inline int udp_pod_to_server_v4(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   v4_pod_one, SERVER_IP,
					   bpf_htons(12345), SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int udp_pod_to_server_v6(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv6_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   (__u8 *)v6_pod_one, (__u8 *)SERVER_IP_V6,
					   bpf_htons(12345), SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int src_ip_check_v4(const struct __ctx_buff *ctx,
					   __be32 expected)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v4_del_entry(v4_pod_one);

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
	if (data + sizeof(struct iphdr) > data_end)
		test_fatal("ctx doesn't fit iphdr");
	struct iphdr *ip4 = data;

	assert(ip4->saddr == expected);
	test_finish();
}

static __always_inline int src_ip_check_v6(const struct __ctx_buff *ctx,
					   const __u8 *expected)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v6_del_entry((union v6addr *)v6_pod_one);

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

	assert(!memcmp(&ip6->saddr, expected, 16));
	test_finish();
}

/* NO_SNAT endpoints should not be masqueraded */
PKTGEN(PROG_TYPE, "host_bpf_masq_exclusions_v4_1_no_snat_ep")
int host_bpf_masq_exclusions_v4_1_no_snat_ep_pktgen(struct __ctx_buff *ctx)
{
	return udp_pod_to_server_v4(ctx);
}

SETUP(PROG_TYPE, "host_bpf_masq_exclusions_v4_1_no_snat_ep")
int host_bpf_masq_exclusions_v4_1_no_snat_ep_setup(struct __ctx_buff *ctx)
{
	/* mark the source IP as a local endpoint with NO_SNAT flag */
	endpoint_v4_add_entry(v4_pod_one, 0, 0, ENDPOINT_F_NO_SNAT_V4, 0, 0, NULL, NULL);

	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "host_bpf_masq_exclusions_v4_1_no_snat_ep")
int host_bpf_masq_exclusions_v4_1_no_snat_ep_check(const struct __ctx_buff *ctx)
{
	/* source IP should stay the same */
	return src_ip_check_v4(ctx, v4_pod_one);
}

PKTGEN(PROG_TYPE, "host_bpf_masq_exclusions_v6_1_no_snat_ep")
int host_bpf_masq_exclusions_v6_1_no_snat_ep_pktgen(struct __ctx_buff *ctx)
{
	return udp_pod_to_server_v6(ctx);
}

SETUP(PROG_TYPE, "host_bpf_masq_exclusions_v6_1_no_snat_ep")
int host_bpf_masq_exclusions_v6_1_no_snat_ep_setup(struct __ctx_buff *ctx)
{
	/* mark the source IP as a local endpoint with NO_SNAT flag */
	endpoint_v6_add_entry((union v6addr *)v6_pod_one,
			      0,
			      0,
			      ENDPOINT_F_NO_SNAT_V6,
			      0,
			      NULL,
			      NULL);

	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "host_bpf_masq_exclusions_v6_1_no_snat_ep")
int host_bpf_masq_exclusions_v6_1_no_snat_ep_check(const struct __ctx_buff *ctx)
{
	const __u8 expected[16] = v6_pod_one_addr;

	/* source IP should stay the same */
	return src_ip_check_v6(ctx, expected);
}

/* Regular endpoints (without NO_SNAT) should be masqueraded */
PKTGEN(PROG_TYPE, "host_bpf_masq_exclusions_v4_2_snat_ep")
int host_bpf_masq_exclusions_v4_2_snat_ep_pktgen(struct __ctx_buff *ctx)
{
	return udp_pod_to_server_v4(ctx);
}

SETUP(PROG_TYPE, "host_bpf_masq_exclusions_v4_2_snat_ep")
int host_bpf_masq_exclusions_v4_2_snat_ep_setup(struct __ctx_buff *ctx)
{
	/* mark the source IP as a local endpoint without NO_SNAT flag */
	endpoint_v4_add_entry(v4_pod_one, 0, 0, 0, 0, 0, NULL, NULL);

	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "host_bpf_masq_exclusions_v4_2_snat_ep")
int host_bpf_masq_exclusions_v4_2_snat_ep_check(const struct __ctx_buff *ctx)
{
	/* source IP should be masqueraded to NODE_IP */
	return src_ip_check_v4(ctx, NODE_IP);
}

PKTGEN(PROG_TYPE, "host_bpf_masq_exclusions_v6_2_snat_ep")
int host_bpf_masq_exclusions_v6_2_snat_ep_pktgen(struct __ctx_buff *ctx)
{
	return udp_pod_to_server_v6(ctx);
}

SETUP(PROG_TYPE, "host_bpf_masq_exclusions_v6_2_snat_ep")
int host_bpf_masq_exclusions_v6_2_snat_ep_setup(struct __ctx_buff *ctx)
{
	/* mark the source IP as a local endpoint without NO_SNAT flag */
	endpoint_v6_add_entry((union v6addr *)v6_pod_one, 0, 0, 0, 0, NULL, NULL);

	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "host_bpf_masq_exclusions_v6_2_snat_ep")
int host_bpf_masq_exclusions_v6_2_snat_ep_check(const struct __ctx_buff *ctx)
{
	const __u8 expected[16] = v6_node_one_addr;

	/* source IP should be masqueraded to the node IPv6 address */
	return src_ip_check_v6(ctx, expected);
}
