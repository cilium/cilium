// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "bpf/ctx/skb.h"
#include "common.h"
#include "pktgen.h"

#include "scapy.h"

#include "node_config.h"
#include "lib/common.h"

#define ENABLE_FLOWTRACER 1
#include "tc_flowtracer.h"

#define TCP_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr))

PKTGEN("tc", "test_err_nospace")
int test_err_nospace_build_pkt(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(FT_TC_NOSPACE, ee_tc_ft_nospace);
	BUILDER_PUSH_BUF(builder, FT_TC_NOSPACE);

	pktgen__finish(&builder);

	return 0;
}

CHECK("tc", "test_err_nospace")
int test_err_nospace(struct __ctx_buff *ctx)
{
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	struct ft_ctx *ft = NULL;
	struct ft_hdr *hdr;
	__u16 off;

	test_init();

	/**
	 * Intercept
	 */
	ft_intercept(ctx, IPPROTO_TCP, TCP_OFFSET);

	/* Verify parsing state is congruent */
	ft = __ft_get();
	assert(ft);
	assert(ft->parsed);
	assert(ft->l4_off == TCP_OFFSET);
	off = (TCP_OFFSET + offsetof(struct tcphdr, check));
	assert(ft->l4_csum_off == off);
	off = (TCP_OFFSET + sizeof(struct tcphdr));
	assert(ft->ft_hdr_off == off);

	/* Add a trace without space */
	ft_add_trace32(ctx, FT_TLV_ING_IFINDEX, 0x16E55, 1);

	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		test_fatal("hdr out of bounds");
	assert(hdr->tlvs_len == 0);
	assert(hdr->flags & FT_TRUNCATED);

	ft_prep_tx(ctx);

	BUF_DECL(EXP_FT_TC_ERR_NOSPACE, ee_tc_ft_nospace_err);
	ASSERT_CTX_BUF_OFF("ft_tc_err_nospace", "Ether", ctx, 0,
			   EXP_FT_TC_ERR_NOSPACE,
			   sizeof(BUF(EXP_FT_TC_ERR_NOSPACE)));

	test_finish();

	return 0;
}

/* Necessary for test functions calling indirectly printk() */
BPF_LICENSE("Dual BSD/GPL");
