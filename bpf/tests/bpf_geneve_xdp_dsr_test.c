// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#undef ctx_pull_data
#define ctx_pull_data(ctx, ...) 0

#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define ENABLE_NODEPORT		1
#define ENABLE_DSR		1
#define DSR_ENCAP_MODE		DSR_ENCAP_GENEVE
#define TUNNEL_PROTOCOL		TUNNEL_PROTOCOL_GENEVE
#define ENABLE_BPF_GENEVE	1
#define TUNNEL_PORT		6081
#define ENCAP_IFINDEX		1

#include "lib/static_data.h"
#ifndef NOT_VTEP_DST
#define NOT_VTEP_DST 0
#endif
DECLARE_CONFIG(bool, enable_vtep, "Enable VTEP integration")

/* Runtime inner protocol selector for testing both ETH (L2 TEB) and IP (L3) modes
 * within the same compilation unit while honoring ASSIGN_CONFIG.
 */
static volatile __u8 test_geneve_inner_proto = 1;

#undef CONFIG
#define __REAL_CONFIG(name)	\
(*({				\
	void *out;		\
	asm volatile("%0 = " __stringify(__config_##name) " ll"	\
			: "=r"(out));	\
	(typeof(__config_##name) *)out;	\
}))
#define CONFIG(name) \
	__builtin_choose_expr(__builtin_strcmp(#name, "geneve_inner_protocol") == 0, \
			      test_geneve_inner_proto, \
			      __REAL_CONFIG(name))

#include "lib/common.h"
#include "lib/overloadable.h"
#include "lib/geneve_encap.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, TUNNEL_PORT)
ASSIGN_CONFIG(__u8, geneve_inner_protocol, GENEVE_INNER_PROTO_IP);

#define SRC_MAC		mac_one
#define DST_MAC		mac_two
#define SRC_IP		v4_pod_one
#define DST_IP		v4_pod_two
#define UNDERLAY_SRC_V4	v4_node_one
#define UNDERLAY_DST_V4	v4_node_two
#define TEST_VIP_V4	bpf_htonl(0x0A000001)
#define TEST_PORT	bpf_htons(8080)
#define TEST_SECLABEL	0x1234

#define DSR_OPT4_LEN_WORDS	((sizeof(struct geneve_dsr_opt4) - sizeof(struct geneve_opt_hdr)) >> 2)
#define DSR_OPT6_LEN_WORDS	((sizeof(struct geneve_dsr_opt6) - sizeof(struct geneve_opt_hdr)) >> 2)

static const union v6addr underlay_src_v6 = { .addr = v6_node_one_addr };
static const union v6addr underlay_dst_v6 = { .addr = v6_node_two_addr };
static const union v6addr test_vip_v6 = { .addr = v6_pod_one_addr };

struct custom_telemetry_tlv {
	struct geneve_opt_hdr hdr;
	__u32 data;
} __packed;

/* =========================================================================
 * Test 1: xdp_dsr_encap_v4_eth_multi_tlv
 * - Tests ctx_set_encap_info4 on XDP in default eth mode (GENEVE_INNER_PROTO_ETH).
 * - Populates cilium_geneve_meta[BPF_GENEVE_DIR_EGRESS] with a custom 8-byte
 *   telemetry TLV (opt_class = bpf_htons(0xFF01), type = 0x11, length = 1)
 *   and passes a 12-byte struct geneve_dsr_opt4 (VIP = 0x0A000001, port = 8080)
 *   to ctx_set_encap_info4.
 * - Asserts ctx_set_encap_info4 succeeds, outer Eth protocol is ETH_P_IP,
 *   outer UDP dest is 6081, geneve->protocol_type == bpf_htons(ETH_P_TEB),
 *   geneve->opt_len == 5 (20 bytes = 12B DSR + 8B custom TLV), and the inner
 *   Ethernet header is preserved after the options.
 * ========================================================================= */
PKTGEN("xdp", "xdp_dsr_encap_v4_eth_multi_tlv")
int xdp_dsr_encap_v4_eth_multi_tlv_pktgen(struct __ctx_buff *ctx)
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

SETUP("xdp", "xdp_dsr_encap_v4_eth_multi_tlv")
int xdp_dsr_encap_v4_eth_multi_tlv_setup(struct __ctx_buff *ctx)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);
	struct custom_telemetry_tlv custom_tlv = {
		.hdr = {
			.opt_class = bpf_htons(0xFF01),
			.type = 0x11,
			.length = 1,
		},
		.data = bpf_htonl(0xCAFEBABE),
	};
	struct geneve_dsr_opt4 dsr_opt = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = DSR_OPT4_LEN_WORDS,
		},
		.addr = TEST_VIP_V4,
		.port = TEST_PORT,
	};

	test_geneve_inner_proto = GENEVE_INNER_PROTO_ETH;

	if (!meta)
		return TEST_ERROR;

	meta->magic = BPF_GENEVE_META_MAGIC;
	meta->opt_len = sizeof(custom_tlv);
	memcpy(meta->raw_opts, &custom_tlv, sizeof(custom_tlv));

	return ctx_set_encap_info4(ctx, UNDERLAY_SRC_V4, bpf_htons(34567),
				   UNDERLAY_DST_V4, TEST_SECLABEL, 0,
				   &dsr_opt, sizeof(dsr_opt));
}

CHECK("xdp", "xdp_dsr_encap_v4_eth_multi_tlv")
int xdp_dsr_encap_v4_eth_multi_tlv_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *outer_eth, *inner_eth;
	struct iphdr *outer_ip4;
	struct udphdr *outer_udp;
	struct genevehdr *geneve;
	struct geneve_dsr_opt4 *dsr_opt;
	struct custom_telemetry_tlv *custom_tlv;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx_data_end(ctx);

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	outer_eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(outer_eth + 1) > data_end)
		test_fatal("outer eth out of bounds");
	assert(outer_eth->h_proto == bpf_htons(ETH_P_IP));

	outer_ip4 = (void *)(outer_eth + 1);
	if ((void *)(outer_ip4 + 1) > data_end)
		test_fatal("outer ip4 out of bounds");
	assert(outer_ip4->protocol == IPPROTO_UDP);

	outer_udp = (void *)(outer_ip4 + 1);
	if ((void *)(outer_udp + 1) > data_end)
		test_fatal("outer udp out of bounds");
	assert(outer_udp->dest == bpf_htons(6081));

	geneve = (void *)(outer_udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("geneve hdr out of bounds");
	assert(geneve->protocol_type == bpf_htons(ETH_P_TEB));
	assert(geneve->opt_len == 5); /* 20 bytes = 12B DSR + 8B custom TLV */

	dsr_opt = (void *)(geneve + 1);
	if ((void *)(dsr_opt + 1) > data_end)
		test_fatal("dsr_opt out of bounds");
	assert(dsr_opt->hdr.opt_class == bpf_htons(DSR_GENEVE_OPT_CLASS));
	assert(dsr_opt->hdr.type == DSR_GENEVE_OPT_TYPE);
	assert(dsr_opt->addr == TEST_VIP_V4);
	assert(dsr_opt->port == TEST_PORT);

	custom_tlv = (void *)(dsr_opt + 1);
	if ((void *)(custom_tlv + 1) > data_end)
		test_fatal("custom_tlv out of bounds");
	assert(custom_tlv->hdr.opt_class == bpf_htons(0xFF01));
	assert(custom_tlv->hdr.type == 0x11);
	assert(custom_tlv->hdr.length == 1);

	/* Inner Ethernet header must be preserved immediately after the 20B options */
	inner_eth = (void *)(custom_tlv + 1);
	if ((void *)(inner_eth + 1) > data_end)
		test_fatal("inner eth out of bounds");
	assert(inner_eth->h_proto == bpf_htons(ETH_P_IP));
	assert(memcmp(inner_eth->h_source, (const void *)SRC_MAC, ETH_ALEN) == 0);
	assert(memcmp(inner_eth->h_dest, (const void *)DST_MAC, ETH_ALEN) == 0);

	test_finish();
}

/* =========================================================================
 * Test 2: xdp_dsr_encap_v4_ip_mode
 * - Sets ASSIGN_CONFIG(__u8, geneve_inner_protocol, GENEVE_INNER_PROTO_IP);
 * - Calls ctx_set_encap_info4 with struct geneve_dsr_opt4.
 * - Asserts geneve->protocol_type == bpf_htons(ETH_P_IP) and the inner
 *   Ethernet header was stripped (L3 mode).
 * ========================================================================= */
PKTGEN("xdp", "xdp_dsr_encap_v4_ip_mode")
int xdp_dsr_encap_v4_ip_mode_pktgen(struct __ctx_buff *ctx)
{
	return xdp_dsr_encap_v4_eth_multi_tlv_pktgen(ctx);
}

SETUP("xdp", "xdp_dsr_encap_v4_ip_mode")
int xdp_dsr_encap_v4_ip_mode_setup(struct __ctx_buff *ctx)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);
	struct geneve_dsr_opt4 dsr_opt = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = DSR_OPT4_LEN_WORDS,
		},
		.addr = TEST_VIP_V4,
		.port = TEST_PORT,
	};

	/* Use the compile-time ASSIGN_CONFIG value (GENEVE_INNER_PROTO_IP) */
	test_geneve_inner_proto = __REAL_CONFIG(geneve_inner_protocol);
	if (meta)
		meta->magic = 0;

	return ctx_set_encap_info4(ctx, UNDERLAY_SRC_V4, bpf_htons(34567),
				   UNDERLAY_DST_V4, TEST_SECLABEL, 0,
				   &dsr_opt, sizeof(dsr_opt));
}

CHECK("xdp", "xdp_dsr_encap_v4_ip_mode")
int xdp_dsr_encap_v4_ip_mode_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *outer_eth;
	struct iphdr *outer_ip4, *inner_ip4;
	struct udphdr *outer_udp;
	struct genevehdr *geneve;
	struct geneve_dsr_opt4 *dsr_opt;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx_data_end(ctx);

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	outer_eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(outer_eth + 1) > data_end)
		test_fatal("outer eth out of bounds");
	assert(outer_eth->h_proto == bpf_htons(ETH_P_IP));

	outer_ip4 = (void *)(outer_eth + 1);
	if ((void *)(outer_ip4 + 1) > data_end)
		test_fatal("outer ip4 out of bounds");

	outer_udp = (void *)(outer_ip4 + 1);
	if ((void *)(outer_udp + 1) > data_end)
		test_fatal("outer udp out of bounds");
	assert(outer_udp->dest == bpf_htons(6081));

	geneve = (void *)(outer_udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("geneve hdr out of bounds");
	assert(geneve->protocol_type == bpf_htons(ETH_P_IP));
	assert(geneve->opt_len == 3); /* 12 bytes = struct geneve_dsr_opt4 */

	dsr_opt = (void *)(geneve + 1);
	if ((void *)(dsr_opt + 1) > data_end)
		test_fatal("dsr_opt out of bounds");
	assert(dsr_opt->addr == TEST_VIP_V4);
	assert(dsr_opt->port == TEST_PORT);

	/* Inner Ethernet header must be stripped: inner IPv4 header directly follows dsr_opt */
	inner_ip4 = (void *)(dsr_opt + 1);
	if ((void *)(inner_ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(inner_ip4->version == 4);
	assert(inner_ip4->saddr == SRC_IP);
	assert(inner_ip4->daddr == DST_IP);

	test_finish();
}

/* =========================================================================
 * Test 3: xdp_dsr_encap_v6_eth_multi_tlv
 * - Tests ctx_set_encap_info6 on XDP with an IPv6 underlay source/destination
 *   and struct geneve_dsr_opt6 (12 + 12 = 24 bytes) + custom 8-byte egress TLV
 *   (total 32 bytes, opt_len == 8).
 * - Asserts outer Eth protocol is ETH_P_IPV6, outer IPv6 nexthdr is IPPROTO_UDP,
 *   geneve->protocol_type == bpf_htons(ETH_P_TEB), and geneve->opt_len == 8.
 * ========================================================================= */
PKTGEN("xdp", "xdp_dsr_encap_v6_eth_multi_tlv")
int xdp_dsr_encap_v6_eth_multi_tlv_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
					  (__u8 *)v6_pod_one,
					  (__u8 *)v6_pod_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("xdp", "xdp_dsr_encap_v6_eth_multi_tlv")
int xdp_dsr_encap_v6_eth_multi_tlv_setup(struct __ctx_buff *ctx)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);
	struct custom_telemetry_tlv custom_tlv = {
		.hdr = {
			.opt_class = bpf_htons(0xFF01),
			.type = 0x11,
			.length = 1,
		},
		.data = bpf_htonl(0x12345678),
	};
	static const struct geneve_dsr_opt6 dsr_opt6 = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = DSR_OPT6_LEN_WORDS,
		},
		.addr = { .in6_u = { .u6_addr8 = v6_pod_one_addr } },
		.port = TEST_PORT,
	};

	test_geneve_inner_proto = GENEVE_INNER_PROTO_ETH;

	if (!meta)
		return TEST_ERROR;

	meta->magic = BPF_GENEVE_META_MAGIC;
	meta->opt_len = sizeof(custom_tlv);
	memcpy(meta->raw_opts, &custom_tlv, sizeof(custom_tlv));

	return ctx_set_encap_info6_with_src(ctx, &underlay_src_v6, bpf_htons(45678),
					    &underlay_dst_v6, TEST_SECLABEL,
					    &dsr_opt6, sizeof(dsr_opt6));
}

CHECK("xdp", "xdp_dsr_encap_v6_eth_multi_tlv")
int xdp_dsr_encap_v6_eth_multi_tlv_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *outer_eth, *inner_eth;
	struct ipv6hdr *outer_ip6;
	struct udphdr *outer_udp;
	struct genevehdr *geneve;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx_data_end(ctx);

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	outer_eth = (void *)status_code + sizeof(*status_code);
	if ((void *)outer_eth + sizeof(*outer_eth) > data_end)
		test_fatal("outer eth out of bounds");
	assert(outer_eth->h_proto == bpf_htons(ETH_P_IPV6));

	outer_ip6 = (void *)outer_eth + sizeof(*outer_eth);
	if ((void *)outer_ip6 + sizeof(*outer_ip6) > data_end)
		test_fatal("outer ip6 out of bounds");
	assert(outer_ip6->version == 6);
	assert(outer_ip6->nexthdr == IPPROTO_UDP);

	outer_udp = (void *)outer_ip6 + sizeof(*outer_ip6);
	if ((void *)outer_udp + sizeof(*outer_udp) > data_end)
		test_fatal("outer udp out of bounds");
	assert(outer_udp->dest == bpf_htons(TUNNEL_PORT));

	geneve = (void *)outer_udp + sizeof(*outer_udp);
	if ((void *)geneve + sizeof(*geneve) > data_end)
		test_fatal("geneve hdr out of bounds");
	assert(geneve->ver == BPF_GENEVE_VERSION);
	assert(geneve->protocol_type == bpf_htons(ETH_P_TEB));
	/* 24 bytes DSR opt6 + 8 bytes custom TLV = 32 bytes (8 words) */
	assert(geneve->opt_len == 8);

	inner_eth = (void *)geneve + sizeof(*geneve) + 32;
	if ((void *)inner_eth + sizeof(*inner_eth) > data_end)
		test_fatal("inner eth out of bounds");
	assert(inner_eth->h_proto == bpf_htons(ETH_P_IPV6));

	test_finish();
}

/* =========================================================================
 * Test 4: xdp_dsr_extract_in_place_non_zero_offset
 * - Constructs an encapsulated Geneve packet on XDP where 3 custom telemetry
 *   TLVs (24 bytes total) precede struct geneve_dsr_opt4 (at TLV offset 24,
 *   total options = 36 bytes).
 * - Calls bpf_geneve_extract_dsr_v4(ctx, &addr, &port, &dsr) directly on the
 *   encapsulated XDP packet (in-place without decap, exercising
 *   bpf_geneve_load_wire_opts).
 * - Asserts dsr == true, addr == expected_vip, and port == expected_port.
 * ========================================================================= */
struct wire_multi_tlv_v4 {
	struct custom_telemetry_tlv tlv1;
	struct custom_telemetry_tlv tlv2;
	struct custom_telemetry_tlv tlv3;
	struct geneve_dsr_opt4 dsr4;
} __packed;

static __be32 extracted_in_place_vip4;
static __be16 extracted_in_place_port4;
static bool extracted_in_place_dsr4;

PKTGEN("xdp", "xdp_dsr_extract_in_place_non_zero_offset")
int xdp_dsr_extract_in_place_non_zero_offset_pktgen(struct __ctx_buff *ctx)
{
	return xdp_dsr_encap_v4_eth_multi_tlv_pktgen(ctx);
}

SETUP("xdp", "xdp_dsr_extract_in_place_non_zero_offset")
int xdp_dsr_extract_in_place_non_zero_offset_setup(struct __ctx_buff *ctx)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);
	struct wire_multi_tlv_v4 wire_opts = {
		.tlv1 = {
			.hdr = { .opt_class = bpf_htons(0xFF01), .type = 0x01, .length = 1 },
			.data = bpf_htonl(0x11111111),
		},
		.tlv2 = {
			.hdr = { .opt_class = bpf_htons(0xFF01), .type = 0x02, .length = 1 },
			.data = bpf_htonl(0x22222222),
		},
		.tlv3 = {
			.hdr = { .opt_class = bpf_htons(0xFF01), .type = 0x03, .length = 1 },
			.data = bpf_htonl(0x33333333),
		},
		.dsr4 = {
			.hdr = {
				.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
				.type = DSR_GENEVE_OPT_TYPE,
				.length = DSR_OPT4_LEN_WORDS,
			},
			.addr = TEST_VIP_V4,
			.port = TEST_PORT,
		},
	};
	int ret;

	test_geneve_inner_proto = GENEVE_INNER_PROTO_ETH;
	if (meta)
		meta->magic = 0;

	/* Encapsulate packet with 36 bytes of options (3 custom TLVs + DSR opt4) */
	ret = ctx_set_encap_info4(ctx, UNDERLAY_SRC_V4, bpf_htons(12345),
				  UNDERLAY_DST_V4, TEST_SECLABEL, 0,
				  &wire_opts, sizeof(wire_opts));
	if (ret != CTX_ACT_REDIRECT)
		return TEST_ERROR;

	/* Clear ingress meta so bpf_geneve_extract_dsr_v4 exercises in-place
	 * wire inspection (bpf_geneve_load_wire_opts) without decapsulation.
	 */
	bpf_geneve_clear_ingress_meta();

	extracted_in_place_vip4 = 0;
	extracted_in_place_port4 = 0;
	extracted_in_place_dsr4 = false;

	return bpf_geneve_extract_dsr_v4(ctx, &extracted_in_place_vip4,
					 &extracted_in_place_port4,
					 &extracted_in_place_dsr4);
}

CHECK("xdp", "xdp_dsr_extract_in_place_non_zero_offset")
int xdp_dsr_extract_in_place_non_zero_offset_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx_data_end(ctx);

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);
	assert(extracted_in_place_dsr4 == true);
	assert(extracted_in_place_vip4 == TEST_VIP_V4);
	assert(extracted_in_place_port4 == TEST_PORT);

	test_finish();
}

/* =========================================================================
 * Test 5: xdp_dsr_extract_v6_after_decap_non_zero_offset
 * - Constructs an IPv6-encapsulated Geneve packet where custom TLVs precede
 *   struct geneve_dsr_opt6.
 * - Runs bpf_geneve_decap6(ctx, NULL) on XDP, then calls
 *   bpf_geneve_extract_dsr_v6(ctx, &addr6, &port, &dsr).
 * - Asserts dsr == true, port == expected_port, and addr6 matches the
 *   expected IPv6 VIP.
 * ========================================================================= */
struct wire_multi_tlv_v6 {
	struct custom_telemetry_tlv tlv1;
	struct custom_telemetry_tlv tlv2;
	struct geneve_dsr_opt6 dsr6;
} __packed;

static union v6addr extracted_decap_vip6;
static __be16 extracted_decap_port6;
static bool extracted_decap_dsr6;

PKTGEN("xdp", "xdp_dsr_extract_v6_after_decap_non_zero_offset")
int xdp_dsr_extract_v6_after_decap_non_zero_offset_pktgen(struct __ctx_buff *ctx)
{
	return xdp_dsr_encap_v6_eth_multi_tlv_pktgen(ctx);
}

SETUP("xdp", "xdp_dsr_extract_v6_after_decap_non_zero_offset")
int xdp_dsr_extract_v6_after_decap_non_zero_offset_setup(struct __ctx_buff *ctx)
{
	struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);
	static const struct wire_multi_tlv_v6 wire_opts6 = {
		.tlv1 = {
			.hdr = { .opt_class = bpf_htons(0xFF01), .type = 0x21, .length = 1 },
			.data = bpf_htonl(0xAAAA1111),
		},
		.tlv2 = {
			.hdr = { .opt_class = bpf_htons(0xFF01), .type = 0x22, .length = 1 },
			.data = bpf_htonl(0xBBBB2222),
		},
		.dsr6 = {
			.hdr = {
				.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
				.type = DSR_GENEVE_OPT_TYPE,
				.length = DSR_OPT6_LEN_WORDS,
			},
			.addr = { .in6_u = { .u6_addr8 = v6_pod_one_addr } },
			.port = TEST_PORT,
		},
	};
	int ret;

	test_geneve_inner_proto = GENEVE_INNER_PROTO_ETH;
	if (meta)
		meta->magic = 0;

	ret = ctx_set_encap_info6_with_src(ctx, &underlay_src_v6, bpf_htons(45678),
					   &underlay_dst_v6, TEST_SECLABEL,
					   &wire_opts6, sizeof(wire_opts6));
	if (ret != CTX_ACT_REDIRECT)
		return TEST_ERROR;

	bpf_geneve_clear_ingress_meta();

	ret = bpf_geneve_decap6(ctx, NULL);
	if (ret != 0)
		return ret;

	memset(&extracted_decap_vip6, 0, sizeof(extracted_decap_vip6));
	extracted_decap_port6 = 0;
	extracted_decap_dsr6 = false;

	return bpf_geneve_extract_dsr_v6(ctx, &extracted_decap_vip6,
					 &extracted_decap_port6,
					 &extracted_decap_dsr6);
}

CHECK("xdp", "xdp_dsr_extract_v6_after_decap_non_zero_offset")
int xdp_dsr_extract_v6_after_decap_non_zero_offset_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx_data_end(ctx);

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);
	assert(extracted_decap_dsr6 == true);
	assert(extracted_decap_port6 == TEST_PORT);
	assert(extracted_decap_vip6.p1 == test_vip_v6.p1);
	assert(extracted_decap_vip6.p2 == test_vip_v6.p2);
	assert(extracted_decap_vip6.p3 == test_vip_v6.p3);
	assert(extracted_decap_vip6.p4 == test_vip_v6.p4);

	test_finish();
}

/* =========================================================================
 * Test 6: xdp_dsr_in_place_has_encap_v4_with_existing_tlvs
 * - Verifies Scenario B (has_encap): an ALREADY Geneve-encapsulated packet
 *   arrives at XDP NodePort DSR acceleration with an existing 8-byte custom
 *   telemetry TLV (opt_len == 2).
 * - Instead of double-encapsulating, XDP DNATs the inner IPv4 destination
 *   in-place, rewrites outer IPv4 saddr/daddr in-place, and calls
 *   ctx_set_tunnel_opt(ctx, &dsr_opt4, sizeof(dsr_opt4)) to insert the 12-byte
 *   DSR option at the start of the Geneve options.
 * - Asserts there is still ONLY ONE Geneve header, geneve->opt_len == 5
 *   (20B = 12B DSR4 + 8B existing custom TLV), outer lengths updated by +12B,
 *   both TLVs intact, inner packet DNATed, and bpf_geneve_extract_dsr_v4
 *   extracts the VIP and port.
 * ========================================================================= */
static __be32 has_encap_extracted_vip4;
static __be16 has_encap_extracted_port4;
static bool has_encap_extracted_dsr4;
static __u16 has_encap_v4_orig_ip_len;
static __u16 has_encap_v4_orig_udp_len;

PKTGEN("xdp", "xdp_dsr_in_place_has_encap_v4_with_existing_tlvs")
int xdp_dsr_in_place_has_encap_v4_with_existing_tlvs_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *outer_eth, *inner_eth;
	struct iphdr *outer_ip4, *inner_ip4;
	struct udphdr *outer_udp;
	struct genevehdr *geneve;
	struct custom_telemetry_tlv *tlv;
	struct tcphdr *inner_tcp;

	pktgen__init(&builder, ctx);

	/* Layer 0: Outer Eth */
	outer_eth = pktgen__push_ethhdr(&builder);
	if (!outer_eth)
		return TEST_ERROR;
	memcpy(outer_eth->h_source, (const void *)SRC_MAC, ETH_ALEN);
	memcpy(outer_eth->h_dest, (const void *)DST_MAC, ETH_ALEN);
	outer_eth->h_proto = bpf_htons(ETH_P_IP);

	/* Layer 1: Outer IPv4 */
	outer_ip4 = pktgen__push_default_iphdr(&builder);
	if (!outer_ip4)
		return TEST_ERROR;
	outer_ip4->saddr = v4_ext_one;
	outer_ip4->daddr = UNDERLAY_SRC_V4;
	outer_ip4->protocol = IPPROTO_UDP;

	/* Layer 2: Outer UDP */
	outer_udp = pktgen__push_default_udphdr(&builder);
	if (!outer_udp)
		return TEST_ERROR;
	outer_udp->source = bpf_htons(33333);
	outer_udp->dest = bpf_htons(6081);

	/* Layer 3: Geneve + 8B existing custom telemetry TLV */
	geneve = pktgen__push_genevehdr(&builder, sizeof(struct custom_telemetry_tlv));
	if (!geneve)
		return TEST_ERROR;
	bpf_geneve_hdr_init(geneve, bpf_htons(ETH_P_TEB), TEST_SECLABEL, 2);

	tlv = (struct custom_telemetry_tlv *)(geneve + 1);
	tlv->hdr.opt_class = bpf_htons(0xFF01);
	tlv->hdr.type = 0x55;
	tlv->hdr.length = 1;
	tlv->data = bpf_htonl(0xCAFEBABE);

	/* Layer 4: Inner Eth */
	inner_eth = pktgen__push_ethhdr(&builder);
	if (!inner_eth)
		return TEST_ERROR;
	memcpy(inner_eth->h_source, (const void *)SRC_MAC, ETH_ALEN);
	memcpy(inner_eth->h_dest, (const void *)DST_MAC, ETH_ALEN);
	inner_eth->h_proto = bpf_htons(ETH_P_IP);

	/* Layer 5: Inner IPv4 */
	inner_ip4 = pktgen__push_default_iphdr(&builder);
	if (!inner_ip4)
		return TEST_ERROR;
	inner_ip4->saddr = v4_ext_one;
	inner_ip4->daddr = TEST_VIP_V4;
	inner_ip4->protocol = IPPROTO_TCP;

	/* Layer 6: Inner TCP */
	inner_tcp = pktgen__push_default_tcphdr(&builder);
	if (!inner_tcp)
		return TEST_ERROR;
	inner_tcp->source = tcp_src_one;
	inner_tcp->dest = TEST_PORT;
	inner_tcp->syn = 1;

	pktgen__finish(&builder);

	/* Ensure outer UDP checksum is 0 as specified */
	{
		__u16 zero_csum = 0;

		if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check),
				    &zero_csum, sizeof(zero_csum), 0) < 0)
			return TEST_ERROR;
	}

	return 0;
}

SETUP("xdp", "xdp_dsr_in_place_has_encap_v4_with_existing_tlvs")
int xdp_dsr_in_place_has_encap_v4_with_existing_tlvs_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx_data_end(ctx);
	struct ethhdr *outer_eth = data;
	struct iphdr *outer_ip4;
	struct udphdr *outer_udp;
	struct genevehdr *geneve;
	__be32 new_daddr = DST_IP;
	__u32 inner_l3_off;
	struct geneve_dsr_opt4 dsr_opt4 = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = DSR_OPT4_LEN_WORDS,
		},
		.addr = TEST_VIP_V4,
		.port = TEST_PORT,
	};
	int ret;

	if ((void *)(outer_eth + 1) > data_end)
		return TEST_ERROR;
	outer_ip4 = (void *)(outer_eth + 1);
	if ((void *)(outer_ip4 + 1) > data_end)
		return TEST_ERROR;
	outer_udp = (void *)(outer_ip4 + 1);
	if ((void *)(outer_udp + 1) > data_end)
		return TEST_ERROR;
	geneve = (void *)(outer_udp + 1);
	if ((void *)(geneve + 1) > data_end)
		return TEST_ERROR;

	/* 1. Verify incoming packet has geneve->opt_len == 2 (8 bytes) */
	if (geneve->opt_len != 2)
		return TEST_ERROR;

	has_encap_v4_orig_ip_len = bpf_ntohs(outer_ip4->tot_len);
	has_encap_v4_orig_udp_len = bpf_ntohs(outer_udp->len);

	/* 2. Rewrite inner IPv4 daddr to DST_IP (BackendPodIP) at inner_l3_off */
	inner_l3_off = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) +
		       sizeof(struct genevehdr) + 8 + ETH_HLEN;
	if (ctx_store_bytes(ctx, inner_l3_off + offsetof(struct iphdr, daddr),
			    &new_daddr, sizeof(new_daddr), 0) < 0)
		return TEST_ERROR;

	/* 3. Rewrite outer IPv4 saddr to UNDERLAY_SRC_V4 (LB_IP) and daddr to UNDERLAY_DST_V4 (BackendNodeIP) */
	outer_ip4->saddr = UNDERLAY_SRC_V4;
	outer_ip4->daddr = UNDERLAY_DST_V4;

	/* 4. Insert 12-byte DSR option into existing Geneve header in-place */
	ret = ctx_set_tunnel_opt(ctx, &dsr_opt4, sizeof(dsr_opt4));
	if (ret != 0)
		return ret;

	/* Verify in-place DSR extraction from the resulting packet */
	bpf_geneve_clear_ingress_meta();
	has_encap_extracted_vip4 = 0;
	has_encap_extracted_port4 = 0;
	has_encap_extracted_dsr4 = false;

	return bpf_geneve_extract_dsr_v4(ctx, &has_encap_extracted_vip4,
					 &has_encap_extracted_port4,
					 &has_encap_extracted_dsr4);
}

CHECK("xdp", "xdp_dsr_in_place_has_encap_v4_with_existing_tlvs")
int xdp_dsr_in_place_has_encap_v4_with_existing_tlvs_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *outer_eth, *inner_eth;
	struct iphdr *outer_ip4, *inner_ip4;
	struct udphdr *outer_udp;
	struct genevehdr *geneve;
	struct geneve_dsr_opt4 *dsr_opt;
	struct custom_telemetry_tlv *custom_tlv;
	struct tcphdr *inner_tcp;
	__be32 vip = 0;
	__be16 port = 0;
	bool dsr = false;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx_data_end(ctx);

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);

	/* Outer Eth */
	outer_eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(outer_eth + 1) > data_end)
		test_fatal("outer eth out of bounds");
	assert(outer_eth->h_proto == bpf_htons(ETH_P_IP));

	/* Outer IPv4: rewritten saddr/daddr and tot_len increased by +12 bytes */
	outer_ip4 = (void *)(outer_eth + 1);
	if ((void *)(outer_ip4 + 1) > data_end)
		test_fatal("outer ip4 out of bounds");
	assert(outer_ip4->protocol == IPPROTO_UDP);
	assert(outer_ip4->saddr == UNDERLAY_SRC_V4);
	assert(outer_ip4->daddr == UNDERLAY_DST_V4);
	assert(bpf_ntohs(outer_ip4->tot_len) == has_encap_v4_orig_ip_len + sizeof(struct geneve_dsr_opt4));

	/* Outer UDP: dest is 6081 and len increased by +12 bytes */
	outer_udp = (void *)(outer_ip4 + 1);
	if ((void *)(outer_udp + 1) > data_end)
		test_fatal("outer udp out of bounds");
	assert(outer_udp->dest == bpf_htons(6081));
	assert(bpf_ntohs(outer_udp->len) == has_encap_v4_orig_udp_len + sizeof(struct geneve_dsr_opt4));

	/* Single Geneve header: opt_len == 5 (20 bytes = 12B DSR + 8B custom TLV) */
	geneve = (void *)(outer_udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("geneve hdr out of bounds");
	assert(geneve->ver == BPF_GENEVE_VERSION);
	assert(geneve->protocol_type == bpf_htons(ETH_P_TEB));
	assert(geneve->opt_len == 5);

	/* First TLV at geneve + 1 is struct geneve_dsr_opt4 */
	dsr_opt = (void *)(geneve + 1);
	if ((void *)(dsr_opt + 1) > data_end)
		test_fatal("dsr_opt out of bounds");
	assert(dsr_opt->hdr.opt_class == bpf_htons(DSR_GENEVE_OPT_CLASS));
	assert(dsr_opt->hdr.type == DSR_GENEVE_OPT_TYPE);
	assert(dsr_opt->hdr.length == DSR_OPT4_LEN_WORDS);
	assert(dsr_opt->addr == TEST_VIP_V4);
	assert(dsr_opt->port == TEST_PORT);

	/* Second TLV immediately following dsr_opt4 is the preserved 8B custom telemetry TLV */
	custom_tlv = (void *)(dsr_opt + 1);
	if ((void *)(custom_tlv + 1) > data_end)
		test_fatal("custom_tlv out of bounds");
	assert(custom_tlv->hdr.opt_class == bpf_htons(0xFF01));
	assert(custom_tlv->hdr.type == 0x55);
	assert(custom_tlv->hdr.length == 1);
	assert(custom_tlv->data == bpf_htonl(0xCAFEBABE));

	/* Inner Ethernet + Inner IPv4 immediately follow (no double encapsulation!) */
	inner_eth = (void *)(custom_tlv + 1);
	if ((void *)(inner_eth + 1) > data_end)
		test_fatal("inner eth out of bounds");
	assert(inner_eth->h_proto == bpf_htons(ETH_P_IP));

	inner_ip4 = (void *)(inner_eth + 1);
	if ((void *)(inner_ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(inner_ip4->version == 4);
	assert(inner_ip4->saddr == v4_ext_one);
	assert(inner_ip4->daddr == DST_IP);
	assert(inner_ip4->protocol == IPPROTO_TCP);

	inner_tcp = (void *)(inner_ip4 + 1);
	if ((void *)(inner_tcp + 1) > data_end)
		test_fatal("inner tcp out of bounds");
	assert(inner_tcp->source == tcp_src_one);
	assert(inner_tcp->dest == TEST_PORT);
	assert(inner_tcp->syn == 1);

	/* Assert extraction from SETUP and also call bpf_geneve_extract_dsr_v4 directly in CHECK */
	assert(has_encap_extracted_dsr4 == true);
	assert(has_encap_extracted_vip4 == TEST_VIP_V4);
	assert(has_encap_extracted_port4 == TEST_PORT);

	bpf_geneve_clear_ingress_meta();
	if (xdp_adjust_head((struct __ctx_buff *)ctx, sizeof(*status_code)) == 0) {
		assert(bpf_geneve_extract_dsr_v4(ctx, &vip, &port, &dsr) == 0);
		assert(dsr == true);
		assert(vip == TEST_VIP_V4);
		assert(port == TEST_PORT);
		xdp_adjust_head((struct __ctx_buff *)ctx, -(__s32)sizeof(*status_code));
	}

	test_finish();
}

/* =========================================================================
 * Test 7: xdp_dsr_in_place_has_encap_v6_outer_with_existing_tlvs
 * - Same as Test 6, but with an IPv6 outer header (70 bytes outer header =
 *   Outer Eth 14B + Outer IPv6 40B + Outer UDP 8B + Geneve 8B) + existing
 *   8-byte custom telemetry TLV.
 * - Calls ctx_set_tunnel_opt(ctx, &dsr_opt6, sizeof(dsr_opt6)) inserting the
 *   24-byte struct geneve_dsr_opt6 in-place.
 * - Asserts no double encapsulation, geneve->opt_len == 8 (32 bytes =
 *   24B DSR6 + 8B custom TLV), both TLVs intact, and inner packet preserved.
 * ========================================================================= */
static union v6addr has_encap_extracted_vip6;
static __be16 has_encap_extracted_port6;
static bool has_encap_extracted_dsr6;
static __u16 has_encap_v6_orig_payload_len;
static __u16 has_encap_v6_orig_udp_len;

PKTGEN("xdp", "xdp_dsr_in_place_has_encap_v6_outer_with_existing_tlvs")
int xdp_dsr_in_place_has_encap_v6_outer_with_existing_tlvs_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *outer_eth, *inner_eth;
	struct ipv6hdr *outer_ip6, *inner_ip6;
	struct udphdr *outer_udp;
	struct genevehdr *geneve;
	struct custom_telemetry_tlv *tlv;
	struct tcphdr *inner_tcp;

	pktgen__init(&builder, ctx);

	/* Layer 0: Outer Eth (14B) */
	outer_eth = pktgen__push_ethhdr(&builder);
	if (!outer_eth)
		return TEST_ERROR;
	memcpy(outer_eth->h_source, (const void *)SRC_MAC, ETH_ALEN);
	memcpy(outer_eth->h_dest, (const void *)DST_MAC, ETH_ALEN);
	outer_eth->h_proto = bpf_htons(ETH_P_IPV6);

	/* Layer 1: Outer IPv6 (40B) */
	outer_ip6 = pktgen__push_default_ipv6hdr(&builder);
	if (!outer_ip6)
		return TEST_ERROR;
	memcpy(&outer_ip6->saddr, (const void *)v6_pod_one, sizeof(struct in6_addr));
	memcpy(&outer_ip6->daddr, &underlay_src_v6, sizeof(struct in6_addr));
	outer_ip6->nexthdr = IPPROTO_UDP;

	/* Layer 2: Outer UDP (8B) */
	outer_udp = pktgen__push_default_udphdr(&builder);
	if (!outer_udp)
		return TEST_ERROR;
	outer_udp->source = bpf_htons(33333);
	outer_udp->dest = bpf_htons(6081);

	/* Layer 3: Geneve (8B) + 8B existing custom telemetry TLV */
	geneve = pktgen__push_genevehdr(&builder, sizeof(struct custom_telemetry_tlv));
	if (!geneve)
		return TEST_ERROR;
	bpf_geneve_hdr_init(geneve, bpf_htons(ETH_P_TEB), TEST_SECLABEL, 2);

	tlv = (struct custom_telemetry_tlv *)(geneve + 1);
	tlv->hdr.opt_class = bpf_htons(0xFF01);
	tlv->hdr.type = 0x55;
	tlv->hdr.length = 1;
	tlv->data = bpf_htonl(0xCAFEBABE);

	/* Layer 4: Inner Eth */
	inner_eth = pktgen__push_ethhdr(&builder);
	if (!inner_eth)
		return TEST_ERROR;
	memcpy(inner_eth->h_source, (const void *)SRC_MAC, ETH_ALEN);
	memcpy(inner_eth->h_dest, (const void *)DST_MAC, ETH_ALEN);
	inner_eth->h_proto = bpf_htons(ETH_P_IPV6);

	/* Layer 5: Inner IPv6 */
	inner_ip6 = pktgen__push_default_ipv6hdr(&builder);
	if (!inner_ip6)
		return TEST_ERROR;
	memcpy(&inner_ip6->saddr, (const void *)v6_pod_one, sizeof(struct in6_addr));
	memcpy(&inner_ip6->daddr, &test_vip_v6, sizeof(struct in6_addr));
	inner_ip6->nexthdr = IPPROTO_TCP;

	/* Layer 6: Inner TCP */
	inner_tcp = pktgen__push_default_tcphdr(&builder);
	if (!inner_tcp)
		return TEST_ERROR;
	inner_tcp->source = tcp_src_one;
	inner_tcp->dest = TEST_PORT;
	inner_tcp->syn = 1;

	pktgen__finish(&builder);

	{
		__u16 zero_csum = 0;

		if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, check),
				    &zero_csum, sizeof(zero_csum), 0) < 0)
			return TEST_ERROR;
	}

	return 0;
}

SETUP("xdp", "xdp_dsr_in_place_has_encap_v6_outer_with_existing_tlvs")
int xdp_dsr_in_place_has_encap_v6_outer_with_existing_tlvs_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx_data_end(ctx);
	struct ethhdr *outer_eth = data;
	struct ipv6hdr *outer_ip6;
	struct udphdr *outer_udp;
	struct genevehdr *geneve;
	__u32 inner_l3_off;
	static const struct geneve_dsr_opt6 dsr_opt6 = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = DSR_OPT6_LEN_WORDS,
		},
		.addr = { .in6_u = { .u6_addr8 = v6_pod_one_addr } },
		.port = TEST_PORT,
	};
	int ret;

	if ((void *)(outer_eth + 1) > data_end)
		return TEST_ERROR;
	outer_ip6 = (void *)(outer_eth + 1);
	if ((void *)(outer_ip6 + 1) > data_end)
		return TEST_ERROR;
	outer_udp = (void *)(outer_ip6 + 1);
	if ((void *)(outer_udp + 1) > data_end)
		return TEST_ERROR;
	geneve = (void *)(outer_udp + 1);
	if ((void *)(geneve + 1) > data_end)
		return TEST_ERROR;

	/* 1. Verify incoming packet has geneve->opt_len == 2 (8 bytes) */
	if (geneve->opt_len != 2)
		return TEST_ERROR;

	has_encap_v6_orig_payload_len = bpf_ntohs(outer_ip6->payload_len);
	has_encap_v6_orig_udp_len = bpf_ntohs(outer_udp->len);

	/* 2. Rewrite inner IPv6 daddr to v6_pod_two (BackendPodIP) at inner_l3_off */
	inner_l3_off = ETH_HLEN + sizeof(struct ipv6hdr) + sizeof(struct udphdr) +
		       sizeof(struct genevehdr) + 8 + ETH_HLEN;
	if (ctx_store_bytes(ctx, inner_l3_off + offsetof(struct ipv6hdr, daddr),
			    (const void *)v6_pod_two, sizeof(struct in6_addr), 0) < 0)
		return TEST_ERROR;

	/* 3. Rewrite outer IPv6 saddr to underlay_src_v6 and daddr to underlay_dst_v6 */
	ipv6_addr_copy((union v6addr *)&outer_ip6->saddr, &underlay_src_v6);
	ipv6_addr_copy((union v6addr *)&outer_ip6->daddr, &underlay_dst_v6);

	/* 4. Insert 24-byte DSR6 option into existing Geneve header in-place */
	ret = ctx_set_tunnel_opt(ctx, &dsr_opt6, sizeof(dsr_opt6));
	if (ret != 0)
		return ret;

	/* Verify in-place DSR6 extraction from the resulting packet */
	bpf_geneve_clear_ingress_meta();
	memset(&has_encap_extracted_vip6, 0, sizeof(has_encap_extracted_vip6));
	has_encap_extracted_port6 = 0;
	has_encap_extracted_dsr6 = false;

	return bpf_geneve_extract_dsr_v6(ctx, &has_encap_extracted_vip6,
					 &has_encap_extracted_port6,
					 &has_encap_extracted_dsr6);
}

CHECK("xdp", "xdp_dsr_in_place_has_encap_v6_outer_with_existing_tlvs")
int xdp_dsr_in_place_has_encap_v6_outer_with_existing_tlvs_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *outer_eth, *inner_eth;
	struct ipv6hdr *outer_ip6, *inner_ip6;
	struct udphdr *outer_udp;
	struct genevehdr *geneve;
	struct geneve_dsr_opt6 *dsr_opt6;
	struct custom_telemetry_tlv *custom_tlv;
	struct tcphdr *inner_tcp;
	union v6addr vip6 = {};
	__be16 port6 = 0;
	bool dsr6 = false;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx_data_end(ctx);

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);

	/* Outer Eth */
	outer_eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(outer_eth + 1) > data_end)
		test_fatal("outer eth out of bounds");
	assert(outer_eth->h_proto == bpf_htons(ETH_P_IPV6));

	/* Outer IPv6: 70B outer headers, rewritten saddr/daddr, payload_len increased by +24B */
	outer_ip6 = (void *)(outer_eth + 1);
	if ((void *)(outer_ip6 + 1) > data_end)
		test_fatal("outer ip6 out of bounds");
	assert(outer_ip6->version == 6);
	assert(outer_ip6->nexthdr == IPPROTO_UDP);
	assert(memcmp(&outer_ip6->saddr, &underlay_src_v6, sizeof(struct in6_addr)) == 0);
	assert(memcmp(&outer_ip6->daddr, &underlay_dst_v6, sizeof(struct in6_addr)) == 0);
	assert(bpf_ntohs(outer_ip6->payload_len) == has_encap_v6_orig_payload_len + sizeof(struct geneve_dsr_opt6));

	/* Outer UDP: dest 6081, len increased by +24B */
	outer_udp = (void *)(outer_ip6 + 1);
	if ((void *)(outer_udp + 1) > data_end)
		test_fatal("outer udp out of bounds");
	assert(outer_udp->dest == bpf_htons(6081));
	assert(bpf_ntohs(outer_udp->len) == has_encap_v6_orig_udp_len + sizeof(struct geneve_dsr_opt6));

	/* Single Geneve header: opt_len == 8 (32 bytes = 24B DSR6 + 8B custom TLV) */
	geneve = (void *)(outer_udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("geneve hdr out of bounds");
	assert(geneve->ver == BPF_GENEVE_VERSION);
	assert(geneve->protocol_type == bpf_htons(ETH_P_TEB));
	assert(geneve->opt_len == 8);

	/* First TLV at geneve + 1 is struct geneve_dsr_opt6 */
	dsr_opt6 = (void *)(geneve + 1);
	if ((void *)(dsr_opt6 + 1) > data_end)
		test_fatal("dsr_opt6 out of bounds");
	assert(dsr_opt6->hdr.opt_class == bpf_htons(DSR_GENEVE_OPT_CLASS));
	assert(dsr_opt6->hdr.type == DSR_GENEVE_OPT_TYPE);
	assert(dsr_opt6->hdr.length == DSR_OPT6_LEN_WORDS);
	assert(dsr_opt6->port == TEST_PORT);
	assert(memcmp(&dsr_opt6->addr, &test_vip_v6, sizeof(struct in6_addr)) == 0);

	/* Second TLV immediately following dsr_opt6 is preserved 8B custom telemetry TLV */
	custom_tlv = (void *)(dsr_opt6 + 1);
	if ((void *)(custom_tlv + 1) > data_end)
		test_fatal("custom_tlv out of bounds");
	assert(custom_tlv->hdr.opt_class == bpf_htons(0xFF01));
	assert(custom_tlv->hdr.type == 0x55);
	assert(custom_tlv->hdr.length == 1);
	assert(custom_tlv->data == bpf_htonl(0xCAFEBABE));

	/* Inner Ethernet + Inner IPv6 preserved immediately after options (no double encap!) */
	inner_eth = (void *)(custom_tlv + 1);
	if ((void *)(inner_eth + 1) > data_end)
		test_fatal("inner eth out of bounds");
	assert(inner_eth->h_proto == bpf_htons(ETH_P_IPV6));

	inner_ip6 = (void *)(inner_eth + 1);
	if ((void *)(inner_ip6 + 1) > data_end)
		test_fatal("inner ip6 out of bounds");
	assert(inner_ip6->version == 6);
	assert(inner_ip6->nexthdr == IPPROTO_TCP);
	assert(memcmp(&inner_ip6->saddr, (const void *)v6_pod_one, sizeof(struct in6_addr)) == 0);
	assert(memcmp(&inner_ip6->daddr, (const void *)v6_pod_two, sizeof(struct in6_addr)) == 0);

	inner_tcp = (void *)(inner_ip6 + 1);
	if ((void *)(inner_tcp + 1) > data_end)
		test_fatal("inner tcp out of bounds");
	assert(inner_tcp->source == tcp_src_one);
	assert(inner_tcp->dest == TEST_PORT);
	assert(inner_tcp->syn == 1);

	/* Assert DSR6 extraction results */
	assert(has_encap_extracted_dsr6 == true);
	assert(has_encap_extracted_port6 == TEST_PORT);
	assert(has_encap_extracted_vip6.p1 == test_vip_v6.p1);
	assert(has_encap_extracted_vip6.p2 == test_vip_v6.p2);
	assert(has_encap_extracted_vip6.p3 == test_vip_v6.p3);
	assert(has_encap_extracted_vip6.p4 == test_vip_v6.p4);

	bpf_geneve_clear_ingress_meta();
	if (xdp_adjust_head((struct __ctx_buff *)ctx, sizeof(*status_code)) == 0) {
		assert(bpf_geneve_extract_dsr_v6(ctx, &vip6, &port6, &dsr6) == 0);
		assert(dsr6 == true);
		assert(port6 == TEST_PORT);
		assert(vip6.p1 == test_vip_v6.p1);
		assert(vip6.p2 == test_vip_v6.p2);
		assert(vip6.p3 == test_vip_v6.p3);
		assert(vip6.p4 == test_vip_v6.p4);
		xdp_adjust_head((struct __ctx_buff *)ctx, -(__s32)sizeof(*status_code));
	}

	test_finish();
}
