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
#define TUNNEL_SRC	v4_node_one
#define TUNNEL_DST	v4_node_two
#define TEST_VNI	0x123456

#define INNER_LEN	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

static struct bpf_tunnel_key ip_mode_v4_key;

PKTGEN("tc", "geneve_encap_v4")
int bpf_geneve_encap_v4_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_encap_v4")
int bpf_geneve_encap_v4_setup(struct __ctx_buff *ctx)
{
	int ret;

	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IP), NULL, 0);
	return ret;
}

CHECK("tc", "geneve_encap_v4")
int bpf_geneve_encap_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4, *inner_ip4;
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
		test_fatal("encap4 returned error: %d", *status_code);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("outer eth out of bounds");

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("unexpected outer proto: 0x%x", bpf_ntohs(eth->h_proto));

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("outer ip4 out of bounds");

	if (ip4->version != 4 || ip4->ihl != 5)
		test_fatal("invalid outer ip4 header");
	if (ip4->protocol != IPPROTO_UDP)
		test_fatal("outer protocol is not UDP");
	if (ip4->saddr != TUNNEL_SRC || ip4->daddr != TUNNEL_DST)
		test_fatal("outer IP mismatch");

	udp = (void *)ip4 + sizeof(*ip4);
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
	if (data_end - (void *)eth != INNER_LEN + sizeof(struct geneve_encaphdr4))
		test_fatal("unexpected packet length in L3 mode");

	test_finish();
}

PKTGEN("tc", "geneve_encap_decap_v4_ip_mode")
int bpf_geneve_encap_decap_v4_ip_mode_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_encap_v4_pktgen(ctx);
}

SETUP("tc", "geneve_encap_decap_v4_ip_mode")
int bpf_geneve_encap_decap_v4_ip_mode_setup(struct __ctx_buff *ctx)
{
	int ret;

	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IP), NULL, 0);
	if (ret < 0)
		return ret;

	return bpf_geneve_decap4(ctx, &ip_mode_v4_key);
}

CHECK("tc", "geneve_encap_decap_v4_ip_mode")
int bpf_geneve_encap_decap_v4_ip_mode_check(const struct __ctx_buff *ctx)
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
		test_fatal("L3 mode roundtrip v4 returned error: %d", *status_code);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("restored packet proto mismatch: 0x%x", bpf_ntohs(eth->h_proto));

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");

	if (ip4->saddr != SRC_IP || ip4->daddr != DST_IP)
		test_fatal("inner IP corrupted after L3 mode decap v4");

	if ((void *)eth + INNER_LEN != data_end)
		test_fatal("inner packet length changed after L3 mode decap v4");

	if (ip_mode_v4_key.tunnel_id != TEST_VNI)
		test_fatal("extracted VNI mismatch: 0x%x", ip_mode_v4_key.tunnel_id);

	test_finish();
}

