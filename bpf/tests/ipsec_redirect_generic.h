/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/skb.h>
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

/* test constants */
#define SOURCE_MAC mac_one
#define DST_MAC mac_two
#define SOURCE_NODE_IP v4_node_one
#define SOURCE_IP v4_pod_one
#define SOURCE_IP_6 v6_pod_one
#define SOURCE_IDENTITY 0xAB0000
#define DST_NODE_IP v4_node_two
#define DST_IP v4_pod_two
#define DST_IP_6 v6_pod_two
#define DST_NODE_ID 0x08b9
#define DST_IDENTITY 0xAC0000
#define TARGET_SPI 2
#define TARGET_MARK 0x08b92e00
#define BAD_SPI 3

int vxlan_ipv6_packet(struct __ctx_buff *ctx) {
	struct pktgen builder;
	struct vxlanhdr *vxlan = NULL;
	// struct udphdr *udp = NULL;
	struct ipv6hdr *l3;
	struct ethhdr *l2;
	pktgen__init(&builder, ctx);

	vxlan = pktgen__push_ipv4_vxlan_packet(&builder, (__u8 *)SOURCE_MAC,
			                       (__u8 *)DST_MAC, SOURCE_NODE_IP,
					       DST_NODE_IP, bpf_htons(0x1234),
					       bpf_htons(0x8472));
	if (!vxlan)
		return TEST_ERROR;

	/*
	 * NOTE: there was an attempt to use the pktgen__push_ipv6_udp_packet
	 * but this blew up the verifier's ins count and broke the tests.
	 */

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)SOURCE_MAC, (__u8 *)DST_MAC);

	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;

	ipv6hdr__set_addrs(l3, (__u8 *)SOURCE_IP_6, (__u8 *)DST_IP_6);

	pktgen__finish(&builder);

	return 0;
}

int vxlan_ipv4_packet(struct __ctx_buff *ctx) {
	struct pktgen builder;
	struct vxlanhdr *vxlan = NULL;
	struct iphdr *ip = NULL;
	pktgen__init(&builder, ctx);

	vxlan = pktgen__push_ipv4_vxlan_packet(&builder, (__u8 *)SOURCE_MAC,
			                       (__u8 *)DST_MAC, SOURCE_NODE_IP,
					       DST_NODE_IP, bpf_htons(0x1234),
					       bpf_htons(0x8472));
	if (!vxlan)
		return TEST_ERROR;

	ip = pktgen__push_ipv4_packet(&builder, (__u8 *)SOURCE_MAC, (__u8 *)DST_MAC,
				 SOURCE_IP, DST_IP);

	if (!ip)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

