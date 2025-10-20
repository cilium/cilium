// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "bpf/ctx/skb.h"
#include "common.h"
#include "pktgen.h"

#include "scapy.h"

#include "node_config.h"
#include "lib/common.h"

#define ENABLE_FLOWTRACER 1
#include "lib/flowtracer.h"

#define TCP_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr))

CHECK("tc", "tc_ft_test_align")
int check_struct_alignments(struct __ctx_buff *ctx)
{
	(void)ctx;

	test_init();

	assert(sizeof(struct ft_cmds) == 16);
	assert(sizeof(struct ft_tl) == 8);
	assert(sizeof(struct ft_tlv_info) == 36);

	/* 32 bit TLVs */
	assert(sizeof(struct ft_tlv_32) == 16);
	assert(sizeof(struct ft_tlv_iface) == 16);
	assert(sizeof(struct ft_tlv_cpu) == 16);

	/* 64 bit TLVs */
	assert(sizeof(struct ft_tlv_64) == 20);
	assert(sizeof(struct ft_tlv_ts) == 20);

	/* Var. length tlvs */
	assert(sizeof(struct ft_tlv_pkt_snap) == 12);

	/* Main Flowtracer header */
	assert(sizeof(struct ft_hdr) == 24);

	/* Other */
	assert(sizeof(struct ft_l4_ports) == 4);

	/* Make sure l4_sport is in aligned to multiple of 2 */
	assert(offsetof(struct ft_hdr, l4_sport) % 2 == 0);

	/* TODO add TLV DBG once properly defined */

	test_finish();
}

PKTGEN("tc", "test_intercept")
int test_intercept_build_pkt(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(FT_TC_SENTINEL_PKT1, ee_tc_ft_sentinel);
	BUILDER_PUSH_BUF(builder, FT_TC_SENTINEL_PKT1);

	pktgen__finish(&builder);

	return 0;
}

CHECK("tc", "test_intercept")
int test_intercept_check(struct __ctx_buff *ctx)
{
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	struct ft_ctx *ft = NULL;
	struct ft_hdr *hdr;
	struct ft_l4_ports *l4;
	__u32 tlvs_len;
	__u16 off;

	test_init();

	/**
	 * Intercept
	 */
	ft_intercept(ctx, IPPROTO_TCP, TCP_OFFSET);

	ft = __ft_get();

	/* Verify parsing state is congruent */
	assert(ft);
	assert(ft->parsed);
	assert(ft->l4_off == TCP_OFFSET);
	off = (TCP_OFFSET + offsetof(struct tcphdr, check));
	assert(ft->l4_csum_off == off);
	off = (TCP_OFFSET + sizeof(struct tcphdr));
	assert(ft->ft_hdr_off == off);

	/** FT hdr sport MUST be aligned to a power of 2 so flipping ports is
	 * csum neutral
	 */
	off = ft->ft_hdr_off + offsetof(struct ft_hdr, l4_sport);
	assert(off % 2 == 0);

	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		test_fatal("hdr out of bounds");

	l4 = (struct ft_l4_ports *)(data + ft->l4_off);
	if (((void *)(l4 + 1)) > data_end)
		test_fatal("l4 out of bounds");

	/* Now check ports have been flipped */
	assert(hdr->l4_sport == bpf_htons(896));
	assert(l4->sport == bpf_htons(64000));

	/* Eth ... TCP should not have changed except for TCP.sport */
	BUF_DECL(EXP_FT_TC_SENTINEL_INTER, ee_tc_ft_sentinel_intercepted);
	ASSERT_CTX_BUF_OFF("ft_tc_intercept_ok", "Ether", ctx, 0,
			   EXP_FT_TC_SENTINEL_INTER,
			   sizeof(BUF(EXP_FT_TC_SENTINEL_INTER)));

	/**
	 * 32 bit traces
	 */
	ft_add_trace32(ctx, FT_TLV_ING_IFINDEX, 0x16E55, 1);
	ft_add_trace32(ctx, FT_TLV_EGR_IFINDEX, 0xE6E55, 2);
	ft_add_trace32(ctx, FT_TLV_CPU, 0xC06E, 2);

	/* Parsing state should not have been modified */
	assert(ft->parsed);
	assert(ft->l4_off == TCP_OFFSET);
	off = (TCP_OFFSET + offsetof(struct tcphdr, check));
	assert(ft->l4_csum_off == off);
	off = (TCP_OFFSET + sizeof(struct tcphdr));
	assert(ft->ft_hdr_off == off);

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		test_fatal("hdr out of bounds");
	tlvs_len = 3 * sizeof(struct ft_tlv_32);
	assert(hdr->tlvs_len == bpf_htonl(tlvs_len));

	BUF_DECL(EXP_FT_TC_TRACES32, ee_tc_ft_traces32);
	ASSERT_CTX_BUF_OFF("ft_tc_traces32_ok", "Ether", ctx, 0,
			   EXP_FT_TC_TRACES32, sizeof(BUF(EXP_FT_TC_TRACES32)));

	/**
	 * 64 bit traces
	 */
	ft_add_trace64(ctx, FT_TLV_ING_TS, 0x16E55, 0x1234ULL);
	ft_add_trace64(ctx, FT_TLV_EGR_TS, 0xE6E55, 0x4321ULL);
	ft_add_trace64(ctx, FT_TLV_NODE, 0xE6E55, 0x1B00F1ULL);
	ft_add_trace64(ctx, FT_TLV_LB_NODE, 0xE6E55, 0x1B00F2ULL);
	ft_add_trace64(ctx, FT_TLV_LB_BACK, 0xE6E55, 0x1B00BEULL);

	/* Parsing state should not have been modified */
	assert(ft->parsed);
	assert(ft->l4_off == TCP_OFFSET);
	off = (TCP_OFFSET + offsetof(struct tcphdr, check));
	assert(ft->l4_csum_off == off);
	off = (TCP_OFFSET + sizeof(struct tcphdr));
	assert(ft->ft_hdr_off == off);

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		test_fatal("hdr out of bounds");
	tlvs_len += 5 * sizeof(struct ft_tlv_64);

	assert(hdr->tlvs_len == bpf_htonl(tlvs_len));

	BUF_DECL(EXP_FT_TC_TRACES3264, ee_tc_ft_traces3264);
	ASSERT_CTX_BUF_OFF("ft_tc_traces3264_ok", "Ether", ctx, 0,
			   EXP_FT_TC_TRACES3264,
			   sizeof(BUF(EXP_FT_TC_TRACES3264)));

	/**
	 * Test ft_trap
	 */
	/* TODO */

	/**
	 * Test ft_drop
	 */

	/* Mimic a non-intercepted pkt, which must NOT be dropped */
	off = ft->ft_hdr_off;
	ft->ft_hdr_off = 0;
	assert(ft_drop(ctx) == 0);

	/* Now an intercepted one */
	ft->ft_hdr_off = (__u8)off;
	assert(ft_drop(ctx) == DROP_UNROUTABLE);

	/**
	 * Test ft_prep_tx
	 */
	assert(!ft->tx_ready);
	ft_prep_tx(ctx);
	assert(ft->tx_ready);

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		test_fatal("hdr out of bounds");

	l4 = (struct ft_l4_ports *)(data + ft->l4_off);
	if (((void *)(l4 + 1)) > data_end)
		test_fatal("l4 out of bounds");

	/* Ports must be flipped back */
	assert(hdr->l4_sport == bpf_htons(64000));
	assert(l4->sport == bpf_htons(896));

	/* Testing idempotency */
	ft_prep_tx(ctx);
	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		test_fatal("hdr out of bounds");

	l4 = (struct ft_l4_ports *)(data + ft->l4_off);
	if (((void *)(l4 + 1)) > data_end)
		test_fatal("l4 out of bounds");

	assert(ft->tx_ready);
	assert(hdr->l4_sport == bpf_htons(64000));
	assert(l4->sport == bpf_htons(896));

	/* A packet that is intercepted can't be re-intercepted */
	ft_intercept(ctx, IPPROTO_TCP, TCP_OFFSET);

	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		test_fatal("hdr out of bounds");

	l4 = (struct ft_l4_ports *)(data + ft->l4_off);
	if (((void *)(l4 + 1)) > data_end)
		test_fatal("l4 out of bounds");

	assert(hdr->l4_sport == bpf_htons(896));
	assert(l4->sport == bpf_htons(64000));
	assert(ft->tx_ready);

	/* Check deferred checksum adjustment */
	BUF_DECL(EXP_FT_TC_TRACES3264_CSUM, ee_tc_ft_traces3264_csum);
	ASSERT_CTX_BUF_OFF("ft_tc_traces3264_csum_ok", "Ether", ctx, 0,
			   EXP_FT_TC_TRACES3264_CSUM,
			   sizeof(BUF(EXP_FT_TC_TRACES3264_CSUM)));

	test_finish();

	return 0;
}

/* Necessary for test functions calling indirectly printk() */
BPF_LICENSE("Dual BSD/GPL");
