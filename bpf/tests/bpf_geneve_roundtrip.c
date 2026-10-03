// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_IPV6
#define TUNNEL_MODE 1
#define ENCAP_IFINDEX 42

#include "lib/common.h"
#include "lib/geneve_encap.h"

#define SRC_MAC		mac_one
#define DST_MAC		mac_two
#define SRC_IP		v4_pod_one
#define DST_IP		v4_pod_two
#define TUNNEL_SRC	v4_node_one
#define TUNNEL_DST	v4_node_two
#define TEST_VNI	0xABCDEF

#define INNER_LEN	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

static struct bpf_tunnel_key roundtrip_key;
static struct bpf_tunnel_key roundtrip_key_v6;

static volatile const union v6addr tunnel_saddr_v6 = { .addr = v6_node_one_addr };
static volatile const union v6addr tunnel_daddr_v6 = { .addr = v6_node_two_addr };

PKTGEN("tc", "geneve_roundtrip_v4")
int bpf_geneve_roundtrip_v4_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_roundtrip_v4")
int bpf_geneve_roundtrip_v4_setup(struct __ctx_buff *ctx)
{
	int ret;

	/* Encapsulate packet */
	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IP), NULL, 0);
	if (ret < 0)
		return ret;

	/* Decapsulate packet back */
	ret = bpf_geneve_decap4(ctx, &roundtrip_key);
	return ret;
}

CHECK("tc", "geneve_roundtrip_v4")
int bpf_geneve_roundtrip_v4_check(const struct __ctx_buff *ctx)
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
		test_fatal("roundtrip v4 returned error: %d", *status_code);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("restored packet proto mismatch: 0x%x", bpf_ntohs(eth->h_proto));

	if (memcmp(eth->h_source, (const void *)SRC_MAC, ETH_ALEN) != 0 ||
	    memcmp(eth->h_dest, (const void *)DST_MAC, ETH_ALEN) != 0)
		test_fatal("restored Ethernet MAC mismatch after roundtrip v4");

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");

	if (ip4->saddr != SRC_IP || ip4->daddr != DST_IP)
		test_fatal("inner IP corrupted after roundtrip v4");

	if ((void *)eth + INNER_LEN != data_end)
		test_fatal("inner packet length changed after roundtrip v4");

	if (roundtrip_key.tunnel_id != TEST_VNI)
		test_fatal("extracted VNI mismatch: 0x%x", roundtrip_key.tunnel_id);

	if (roundtrip_key.local_ipv4 != bpf_ntohl(TUNNEL_DST) ||
	    roundtrip_key.remote_ipv4 != bpf_ntohl(TUNNEL_SRC))
		test_fatal("extracted tunnel IPs mismatch");

	test_finish();
}

PKTGEN("tc", "geneve_roundtrip_v6")
int bpf_geneve_roundtrip_v6_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_roundtrip_v6")
int bpf_geneve_roundtrip_v6_setup(struct __ctx_buff *ctx)
{
	union v6addr saddr = tunnel_saddr_v6;
	union v6addr daddr = tunnel_daddr_v6;
	int ret;

	/* Encapsulate packet with IPv6 underlay */
	ret = bpf_geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
				bpf_htons(ETH_P_IP), NULL, 0);
	if (ret < 0)
		return ret;

	/* Decapsulate packet back */
	ret = bpf_geneve_decap6(ctx, &roundtrip_key_v6);
	return ret;
}

CHECK("tc", "geneve_roundtrip_v6")
int bpf_geneve_roundtrip_v6_check(const struct __ctx_buff *ctx)
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
		test_fatal("roundtrip v6 returned error: %d", *status_code);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("restored packet proto mismatch: 0x%x", bpf_ntohs(eth->h_proto));

	if (memcmp(eth->h_source, (const void *)SRC_MAC, ETH_ALEN) != 0 ||
	    memcmp(eth->h_dest, (const void *)DST_MAC, ETH_ALEN) != 0)
		test_fatal("restored Ethernet MAC mismatch after roundtrip v6");

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");

	if (ip4->saddr != SRC_IP || ip4->daddr != DST_IP)
		test_fatal("inner IP corrupted after roundtrip v6");

	if ((void *)eth + INNER_LEN != data_end)
		test_fatal("inner packet length changed after roundtrip v6");

	if (roundtrip_key_v6.tunnel_id != TEST_VNI)
		test_fatal("extracted VNI mismatch: 0x%x", roundtrip_key_v6.tunnel_id);

	if (roundtrip_key_v6.remote_ipv6[0] != tunnel_saddr_v6.p1 ||
	    roundtrip_key_v6.remote_ipv6[1] != tunnel_saddr_v6.p2 ||
	    roundtrip_key_v6.remote_ipv6[2] != tunnel_saddr_v6.p3 ||
	    roundtrip_key_v6.remote_ipv6[3] != tunnel_saddr_v6.p4)
		test_fatal("extracted tunnel remote IPv6 mismatch");

	test_finish();
}

/* Dedicated test case 1: Default GENEVE_INNER_PROTO_ETH (ETH_P_TEB) mode for IPv4 underlay.
 * Verifies that without overriding geneve_inner_protocol, bpf_geneve_encap4 produces
 * geneve->protocol_type == bpf_htons(ETH_P_TEB), preserves the 14-byte inner Ethernet
 * header after the Geneve header, and bpf_geneve_decap4 cleanly restores the original
 * inner Ethernet frame.
 */
static struct bpf_tunnel_key eth_mode_v4_key;
static __be16 eth_mode_v4_wire_proto;
static __u32 eth_mode_v4_encap_len;
static __be16 eth_mode_v4_inner_eth_proto;
static int eth_mode_v4_inner_eth_mac_ok;

PKTGEN("tc", "bpf_geneve_v4_encap_eth_mode_default")
int bpf_geneve_v4_encap_eth_mode_default_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_roundtrip_v4_pktgen(ctx);
}

SETUP("tc", "bpf_geneve_v4_encap_eth_mode_default")
int bpf_geneve_v4_encap_eth_mode_default_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *outer_eth, *inner_eth;
	struct geneve_encaphdr4 *hdr;
	int ret;

	eth_mode_v4_wire_proto = 0;
	eth_mode_v4_encap_len = 0;
	eth_mode_v4_inner_eth_proto = 0;
	eth_mode_v4_inner_eth_mac_ok = 0;

	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IP), NULL, 0);
	if (ret < 0)
		return ret;

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + sizeof(*hdr) + ETH_HLEN <= data_end) {
		outer_eth = data;
		hdr = (struct geneve_encaphdr4 *)(outer_eth + 1);
		inner_eth = (struct ethhdr *)(hdr + 1);

		eth_mode_v4_wire_proto = hdr->geneve.protocol_type;
		eth_mode_v4_encap_len = (__u32)((void *)data_end - (void *)data);
		eth_mode_v4_inner_eth_proto = inner_eth->h_proto;
		if (memcmp(inner_eth->h_source, (const void *)SRC_MAC, ETH_ALEN) == 0 &&
		    memcmp(inner_eth->h_dest, (const void *)DST_MAC, ETH_ALEN) == 0)
			eth_mode_v4_inner_eth_mac_ok = 1;
	}

	return bpf_geneve_decap4(ctx, &eth_mode_v4_key);
}

CHECK("tc", "bpf_geneve_v4_encap_eth_mode_default")
int bpf_geneve_v4_encap_eth_mode_default_check(const struct __ctx_buff *ctx)
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
		test_fatal("bpf_geneve_v4_encap_eth_mode_default returned error: %d",
			   *status_code);

	if (eth_mode_v4_wire_proto != bpf_htons(ETH_P_TEB))
		test_fatal("expected wire protocol ETH_P_TEB (0x%x), got 0x%x",
			   ETH_P_TEB, bpf_ntohs(eth_mode_v4_wire_proto));

	if (eth_mode_v4_encap_len != INNER_LEN + sizeof(struct geneve_encaphdr4) + ETH_HLEN)
		test_fatal("expected encapsulated len %lu with 14B inner eth, got %u",
			   INNER_LEN + sizeof(struct geneve_encaphdr4) + ETH_HLEN,
			   eth_mode_v4_encap_len);

	if (eth_mode_v4_inner_eth_proto != bpf_htons(ETH_P_IP) ||
	    !eth_mode_v4_inner_eth_mac_ok)
		test_fatal("14-byte inner Ethernet header not preserved after Geneve header");

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("restored eth out of bounds");

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("restored inner eth proto mismatch: 0x%x", bpf_ntohs(eth->h_proto));

	if (memcmp(eth->h_source, (const void *)SRC_MAC, ETH_ALEN) != 0 ||
	    memcmp(eth->h_dest, (const void *)DST_MAC, ETH_ALEN) != 0)
		test_fatal("original inner Ethernet frame MACs not cleanly restored after decap4");

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");

	if (ip4->saddr != SRC_IP || ip4->daddr != DST_IP)
		test_fatal("inner IPv4 addresses corrupted after decap4");

	if ((void *)eth + INNER_LEN != data_end)
		test_fatal("restored inner Ethernet frame length mismatch");

	if (eth_mode_v4_key.tunnel_id != TEST_VNI)
		test_fatal("extracted VNI mismatch: 0x%x", eth_mode_v4_key.tunnel_id);

	test_finish();
}

/* Dedicated test case 2: Default GENEVE_INNER_PROTO_ETH (ETH_P_TEB) mode for IPv6 underlay.
 * Verifies that without overriding geneve_inner_protocol, bpf_geneve_encap6 produces
 * geneve->protocol_type == bpf_htons(ETH_P_TEB), preserves the 14-byte inner Ethernet
 * header after the Geneve header, and bpf_geneve_decap6 cleanly restores the original
 * inner Ethernet frame.
 */
static struct bpf_tunnel_key eth_mode_v6_key;
static __be16 eth_mode_v6_wire_proto;
static __u32 eth_mode_v6_encap_len;
static __be16 eth_mode_v6_inner_eth_proto;
static int eth_mode_v6_inner_eth_mac_ok;

PKTGEN("tc", "bpf_geneve_v6_encap_eth_mode_default")
int bpf_geneve_v6_encap_eth_mode_default_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_roundtrip_v6_pktgen(ctx);
}

SETUP("tc", "bpf_geneve_v6_encap_eth_mode_default")
int bpf_geneve_v6_encap_eth_mode_default_setup(struct __ctx_buff *ctx)
{
	union v6addr saddr = tunnel_saddr_v6;
	union v6addr daddr = tunnel_daddr_v6;
	void *data, *data_end;
	struct ethhdr *outer_eth, *inner_eth;
	struct geneve_encaphdr6 *hdr6;
	int ret;

	eth_mode_v6_wire_proto = 0;
	eth_mode_v6_encap_len = 0;
	eth_mode_v6_inner_eth_proto = 0;
	eth_mode_v6_inner_eth_mac_ok = 0;

	ret = bpf_geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
				bpf_htons(ETH_P_IP), NULL, 0);
	if (ret < 0)
		return ret;

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + sizeof(*hdr6) + ETH_HLEN <= data_end) {
		outer_eth = data;
		hdr6 = (struct geneve_encaphdr6 *)(outer_eth + 1);
		inner_eth = (struct ethhdr *)(hdr6 + 1);

		eth_mode_v6_wire_proto = hdr6->geneve.protocol_type;
		eth_mode_v6_encap_len = (__u32)((void *)data_end - (void *)data);
		eth_mode_v6_inner_eth_proto = inner_eth->h_proto;
		if (memcmp(inner_eth->h_source, (const void *)SRC_MAC, ETH_ALEN) == 0 &&
		    memcmp(inner_eth->h_dest, (const void *)DST_MAC, ETH_ALEN) == 0)
			eth_mode_v6_inner_eth_mac_ok = 1;
	}

	return bpf_geneve_decap6(ctx, &eth_mode_v6_key);
}

CHECK("tc", "bpf_geneve_v6_encap_eth_mode_default")
int bpf_geneve_v6_encap_eth_mode_default_check(const struct __ctx_buff *ctx)
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
		test_fatal("bpf_geneve_v6_encap_eth_mode_default returned error: %d",
			   *status_code);

	if (eth_mode_v6_wire_proto != bpf_htons(ETH_P_TEB))
		test_fatal("expected wire protocol ETH_P_TEB (0x%x), got 0x%x",
			   ETH_P_TEB, bpf_ntohs(eth_mode_v6_wire_proto));

	if (eth_mode_v6_encap_len != INNER_LEN + sizeof(struct geneve_encaphdr6) + ETH_HLEN)
		test_fatal("expected encapsulated len %lu with 14B inner eth, got %u",
			   INNER_LEN + sizeof(struct geneve_encaphdr6) + ETH_HLEN,
			   eth_mode_v6_encap_len);

	if (eth_mode_v6_inner_eth_proto != bpf_htons(ETH_P_IP) ||
	    !eth_mode_v6_inner_eth_mac_ok)
		test_fatal("14-byte inner Ethernet header not preserved after Geneve IPv6 header");

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("restored eth out of bounds");

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("restored inner eth proto mismatch: 0x%x", bpf_ntohs(eth->h_proto));

	if (memcmp(eth->h_source, (const void *)SRC_MAC, ETH_ALEN) != 0 ||
	    memcmp(eth->h_dest, (const void *)DST_MAC, ETH_ALEN) != 0)
		test_fatal("original inner Ethernet frame MACs not cleanly restored after decap6");

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");

	if (ip4->saddr != SRC_IP || ip4->daddr != DST_IP)
		test_fatal("inner IPv4 addresses corrupted after decap6");

	if ((void *)eth + INNER_LEN != data_end)
		test_fatal("restored inner Ethernet frame length mismatch");

	if (eth_mode_v6_key.tunnel_id != TEST_VNI)
		test_fatal("extracted VNI mismatch: 0x%x", eth_mode_v6_key.tunnel_id);

	test_finish();
}

/* Multi-TLV test buffer: 5 heterogeneous Geneve TLVs totaling 44 bytes (11 words):
 * TLV #1: Class 0x0101, Type 0x01, Len 1 word (8 bytes total)
 * TLV #2: Class 0x0102, Type 0x02, Len 2 words (12 bytes total)
 * TLV #3: Class 0x0103, Type 0x03, Len 0 words (4 bytes total)
 * TLV #4: Class 0x0104, Type 0x04, Len 1 word (8 bytes total)
 * TLV #5: DSR Option (Class DSR_GENEVE_OPT_CLASS=0x014B, Type DSR_GENEVE_OPT_TYPE=0x01, Len 2 words = 12 bytes total)
 */
struct multi_tlv_test_payload {
	struct geneve_opt_hdr tlv1;
	__u32 tlv1_data;
	struct geneve_opt_hdr tlv2;
	__u32 tlv2_data[2];
	struct geneve_opt_hdr tlv3;
	struct geneve_opt_hdr tlv4;
	__u32 tlv4_data;
	struct geneve_dsr_opt4 dsr_tlv;
} __packed;

static struct bpf_tunnel_key multi_tlv_key;

PKTGEN("tc", "geneve_multi_tlv_roundtrip")
int bpf_geneve_multi_tlv_roundtrip_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_multi_tlv_roundtrip")
int bpf_geneve_multi_tlv_roundtrip_setup(struct __ctx_buff *ctx)
{
	struct multi_tlv_test_payload opts = {
		.tlv1 = { .opt_class = bpf_htons(0x0101), .type = 0x01, .length = 1 },
		.tlv1_data = bpf_htonl(0x11111111),
		.tlv2 = { .opt_class = bpf_htons(0x0102), .type = 0x02, .length = 2 },
		.tlv2_data = { bpf_htonl(0x22222222), bpf_htonl(0x33333333) },
		.tlv3 = { .opt_class = bpf_htons(0x0103), .type = 0x03, .length = 0 },
		.tlv4 = { .opt_class = bpf_htons(0x0104), .type = 0x04, .length = 1 },
		.tlv4_data = bpf_htonl(0x44444444),
		.dsr_tlv = {
			.hdr = {
				.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
				.type = DSR_GENEVE_OPT_TYPE,
				.length = 2,
			},
			.addr = bpf_htonl(0x0A000099),
			.port = bpf_htons(8080),
		},
	};
	int ret;

	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IP), &opts, sizeof(opts));
	if (ret < 0)
		return ret;

	ret = bpf_geneve_decap4(ctx, &multi_tlv_key);
	return ret;
}

CHECK("tc", "geneve_multi_tlv_roundtrip")
int bpf_geneve_multi_tlv_roundtrip_check(const struct __ctx_buff *ctx)
{
	const struct bpf_geneve_metadata *meta;
	const struct geneve_opt_hdr *found_tlv2;
	const struct geneve_opt_hdr *found_dsr_hdr;
	const struct geneve_dsr_opt4 *dsr_opt;
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != 0)
		test_fatal("multi-tlv roundtrip returned error: %d", *status_code);

	meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_INGRESS);
	if (!meta || meta->magic != BPF_GENEVE_META_MAGIC)
		test_fatal("geneve metadata missing after multi-tlv decap");

	if (meta->opt_len != sizeof(struct multi_tlv_test_payload))
		test_fatal("expected opt_len %lu, got %u",
			   sizeof(struct multi_tlv_test_payload), meta->opt_len);

	/* Verify lookup of TLV #2 (0x0102, 0x02) */
	found_tlv2 = bpf_geneve_find_opt(meta, bpf_htons(0x0102), 0x02);
	if (!found_tlv2 || found_tlv2->length != 2)
		test_fatal("failed to locate TLV #2 via bpf_geneve_find_opt");

	/* Verify lookup of TLV #5 (DSR option at index #5) */
	found_dsr_hdr = bpf_geneve_find_opt(meta, bpf_htons(DSR_GENEVE_OPT_CLASS),
					    DSR_GENEVE_OPT_TYPE);
	if (!found_dsr_hdr || found_dsr_hdr->length != 2)
		test_fatal("failed to locate DSR TLV #5 via bpf_geneve_find_opt");

	dsr_opt = (const struct geneve_dsr_opt4 *)found_dsr_hdr;
	if (dsr_opt->addr != bpf_htonl(0x0A000099) || dsr_opt->port != bpf_htons(8080))
		test_fatal("DSR TLV #5 payload mismatch");

	test_finish();
}

