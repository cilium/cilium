// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include <bpf/config/global.h>

#define ENABLE_IPV4
#define ENABLE_IPV6
#define TUNNEL_MODE 1
#define ENCAP_IFINDEX 42

#include "lib/common.h"
#include "lib/geneve_encap.h"

/* Explicitly test L3 inner protocol mode (geneve-inner-protocol=ip) */
ASSIGN_CONFIG(__u8, geneve_inner_protocol, GENEVE_INNER_PROTO_IP)

#define SRC_MAC		mac_one
#define DST_MAC		mac_two
#define SRC_IP		v4_pod_one
#define DST_IP		v4_pod_two
#define SRC_IPV6	v6_pod_one
#define DST_IPV6	v6_pod_two
#define TEST_VNI	0x654321

#define INNER_LEN	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))
#define INNER_LEN6	(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

static volatile const union v6addr tunnel_saddr = { .addr = v6_node_one_addr };
static volatile const union v6addr tunnel_daddr = { .addr = v6_node_two_addr };
static struct bpf_tunnel_key ip_mode_v6_key;

PKTGEN("tc", "geneve_encap_v6")
int bpf_geneve_encap_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
					  SRC_IP, DST_IP,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "geneve_encap_v6")
int bpf_geneve_encap_v6_setup(struct __ctx_buff *ctx)
{
	union v6addr saddr = tunnel_saddr;
	union v6addr daddr = tunnel_daddr;

	return bpf_geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
				 bpf_htons(ETH_P_IP), NULL, 0);
}

CHECK("tc", "geneve_encap_v6")
int bpf_geneve_encap_v6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	struct iphdr *inner_ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	__u32 *status_code;
	__u32 vni;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != 0)
		test_fatal("encap6 returned error: %d", *status_code);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("outer eth out of bounds");

	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("unexpected outer proto: 0x%x", bpf_ntohs(eth->h_proto));

	ip6 = (void *)eth + sizeof(*eth);
	if ((void *)ip6 + sizeof(*ip6) > data_end)
		test_fatal("outer ip6 out of bounds");

	if (ip6->version != 6 || ip6->nexthdr != IPPROTO_UDP)
		test_fatal("invalid outer ip6 header");

	udp = (void *)ip6 + sizeof(*ip6);
	if ((void *)udp + sizeof(*udp) > data_end)
		test_fatal("outer udp out of bounds");

	if (udp->dest != bpf_htons(BPF_GENEVE_DEFAULT_PORT))
		test_fatal("unexpected outer UDP dest port: %d", bpf_ntohs(udp->dest));

	geneve = (void *)udp + sizeof(*udp);
	if ((void *)geneve + sizeof(*geneve) > data_end)
		test_fatal("geneve hdr out of bounds");

	if (geneve->ver != BPF_GENEVE_VERSION)
		test_fatal("unexpected geneve version");
	if (geneve->protocol_type != bpf_htons(ETH_P_IP))
		test_fatal("unexpected inner proto: 0x%x", bpf_ntohs(geneve->protocol_type));

	vni = bpf_geneve_hdr_vni(geneve);
	if (vni != TEST_VNI)
		test_fatal("vni mismatch: got 0x%x, expected 0x%x", vni, TEST_VNI);

	/* Verify inner IPv4 header immediately follows Geneve header */
	inner_ip4 = (void *)(geneve + 1);
	if ((void *)(inner_ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	if (inner_ip4->saddr != SRC_IP || inner_ip4->daddr != DST_IP)
		test_fatal("inner IPv4 saddr/daddr mismatch in L3 mode");

	/* Verify packet length in L3 IP mode (no inner Ethernet header) */
	if (data_end - (void *)eth != INNER_LEN + sizeof(struct geneve_encaphdr6))
		test_fatal("unexpected packet length in L3 mode");

	test_finish();
}

PKTGEN("tc", "geneve_encap_v6_inner_ipv6")
int bpf_geneve_encap_v6_inner_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
					  (__u8 *)SRC_IPV6, (__u8 *)DST_IPV6,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "geneve_encap_v6_inner_ipv6")
int bpf_geneve_encap_v6_inner_ipv6_setup(struct __ctx_buff *ctx)
{
	union v6addr saddr = tunnel_saddr;
	union v6addr daddr = tunnel_daddr;

	return bpf_geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
				 bpf_htons(ETH_P_IPV6), NULL, 0);
}

CHECK("tc", "geneve_encap_v6_inner_ipv6")
int bpf_geneve_encap_v6_inner_ipv6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct ipv6hdr *ip6, *inner_ip6;
	struct udphdr *udp;
	struct genevehdr *geneve;
	__u32 *status_code;
	__u32 vni;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != 0)
		test_fatal("encap6 inner ipv6 returned error: %d", *status_code);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("outer eth out of bounds");

	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("unexpected outer proto: 0x%x", bpf_ntohs(eth->h_proto));

	ip6 = (void *)eth + sizeof(*eth);
	if ((void *)ip6 + sizeof(*ip6) > data_end)
		test_fatal("outer ip6 out of bounds");

	udp = (void *)ip6 + sizeof(*ip6);
	if ((void *)udp + sizeof(*udp) > data_end)
		test_fatal("outer udp out of bounds");

	geneve = (void *)udp + sizeof(*udp);
	if ((void *)geneve + sizeof(*geneve) > data_end)
		test_fatal("geneve hdr out of bounds");

	if (geneve->protocol_type != bpf_htons(ETH_P_IPV6))
		test_fatal("unexpected inner proto for IPv6 payload: 0x%x",
			   bpf_ntohs(geneve->protocol_type));

	vni = bpf_geneve_hdr_vni(geneve);
	if (vni != TEST_VNI)
		test_fatal("vni mismatch: got 0x%x, expected 0x%x", vni, TEST_VNI);

	inner_ip6 = (void *)(geneve + 1);
	if ((void *)(inner_ip6 + 1) > data_end)
		test_fatal("inner ip6 out of bounds");
	if (inner_ip6->version != 6)
		test_fatal("invalid inner ip6 version");

	/* Verify packet length in L3 IP mode (no inner Ethernet header) */
	if (data_end - (void *)eth != INNER_LEN6 + sizeof(struct geneve_encaphdr6))
		test_fatal("unexpected packet length in L3 IPv6 mode");

	test_finish();
}

PKTGEN("tc", "geneve_encap_decap_v6_ip_mode")
int bpf_geneve_encap_decap_v6_ip_mode_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_encap_v6_pktgen(ctx);
}

SETUP("tc", "geneve_encap_decap_v6_ip_mode")
int bpf_geneve_encap_decap_v6_ip_mode_setup(struct __ctx_buff *ctx)
{
	union v6addr saddr = tunnel_saddr;
	union v6addr daddr = tunnel_daddr;
	int ret;

	ret = bpf_geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
				bpf_htons(ETH_P_IP), NULL, 0);
	if (ret < 0)
		return ret;

	return bpf_geneve_decap6(ctx, &ip_mode_v6_key);
}

CHECK("tc", "geneve_encap_decap_v6_ip_mode")
int bpf_geneve_encap_decap_v6_ip_mode_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != 0)
		test_fatal("L3 mode roundtrip v6 returned error: %d", *status_code);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("restored packet proto mismatch: 0x%x", bpf_ntohs(eth->h_proto));

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");

	if (ip4->saddr != SRC_IP || ip4->daddr != DST_IP)
		test_fatal("inner IP corrupted after L3 mode decap v6");

	if ((void *)eth + INNER_LEN != data_end)
		test_fatal("inner packet length changed after L3 mode decap v6");

	if (ip_mode_v6_key.tunnel_id != TEST_VNI)
		test_fatal("extracted VNI mismatch: 0x%x", ip_mode_v6_key.tunnel_id);

	test_finish();
}

