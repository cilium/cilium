/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* mock and record calls to ctx_redirect */
struct ctx_redirect_recorder {
	int ifindex;
	__u32 flags;
} rec;
int mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		      int ifindex, __u32 flags)
{
	rec.flags = flags;
	rec.ifindex = ifindex;
	return CTX_ACT_REDIRECT;
}

#define ctx_redirect mock_ctx_redirect

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_IPSEC

/*
 * Test constants. Make sure to have a valid src/dst identity by
 * using ids < CIDR_IDENTITY_RANGE_START.
 */
#define SOURCE_MAC mac_one
#define DST_MAC mac_two
#define SOURCE_NODE_IP v4_node_one
#define SOURCE_NODE_IP_6 v6_node_one
#define SOURCE_IP v4_pod_one
#define SOURCE_IP_6 v6_pod_one
#define SOURCE_IDENTITY (CIDR_IDENTITY_RANGE_START - 1)
#define DST_IP v4_pod_two
#define DST_IP_6 v6_pod_two
#define DST_NODE_ID 0x08b9
#define DST_NODE_IP v4_node_two
#define DST_NODE_IP_6 v6_node_two
#define DST_IDENTITY (CIDR_IDENTITY_RANGE_START - 2)
#define TARGET_SPI 2
#define BAD_SPI 3
#define GENERAL_PORT bpf_htons(12134)
#define VXLAN_PORT bpf_htons(8472)

static __always_inline
int generate_vxlan_packet(struct __ctx_buff *ctx, bool outer_ip4, bool inner_ip4)
{
	struct pktgen builder;
	struct vxlanhdr *vxlan;
	void *l3;

	pktgen__init(&builder, ctx);

	if (outer_ip4)
		vxlan = pktgen__push_ipv4_vxlan_packet(&builder, (__u8 *)SOURCE_MAC,
						       (__u8 *)DST_MAC, SOURCE_NODE_IP,
						       DST_NODE_IP, GENERAL_PORT,
						       VXLAN_PORT);
	else
		vxlan = pktgen__push_ipv6_vxlan_packet(&builder, (__u8 *)SOURCE_MAC,
						       (__u8 *)DST_MAC, (__u8 *)SOURCE_NODE_IP_6,
						       (__u8 *)DST_NODE_IP_6, GENERAL_PORT,
						       VXLAN_PORT);
	if (!vxlan)
		return TEST_ERROR;

	if (inner_ip4)
		l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)SOURCE_MAC, (__u8 *)DST_MAC,
					      SOURCE_IP, DST_IP);
	else
		l3 = pktgen__push_ipv6_packet(&builder, (__u8 *)SOURCE_MAC, (__u8 *)DST_MAC,
					      (__u8 *)SOURCE_IP_6, (__u8 *)DST_IP_6);

	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

static __always_inline
int generate_native_packet(struct __ctx_buff *ctx, bool ipv4)
{
	struct pktgen builder;
	void *l3 = NULL;

	pktgen__init(&builder, ctx);

	if (ipv4)
		l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)SOURCE_MAC, (__u8 *)DST_MAC,
					      SOURCE_IP, DST_IP);
	else
		l3 = pktgen__push_ipv6_packet(&builder, (__u8 *)SOURCE_MAC, (__u8 *)DST_MAC,
					      (__u8 *)SOURCE_IP_6, (__u8 *)DST_IP_6);

	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}
