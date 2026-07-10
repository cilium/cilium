// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

#include "pktgen.h"

/* We need to mock loggers to test ASSERT MACRO failures */
#define __ASSERT_TRACE_FAIL_LEN(...)
#define __ASSERT_TRACE_FAIL_BUF(...)
#include "scapy.h"

#define fake_test_end() (void)suite_result; } while (0)

#define ASSERT1 "assert1"
#define ASSERT2 "assert2"

#define ASSERT1_FAIL "assert1_fail"
#define ASSERT2_FAIL "assert2_fail"
#define ASSERT3_FAIL "assert3_fail"

const __u8 sst_req[] = {
	SCAPY_BUF_BYTES(sst_req)
};

const __u8 sst_rep[] = {
	SCAPY_BUF_BYTES(sst_rep)
};

const __u8 sst_rep_pad[] = {
	SCAPY_BUF_BYTES(sst_rep_pad)
};

const __u8 sst_lpkt[] = {
	SCAPY_BUF_BYTES(sst_lpkt)
};

const __u8 sst_xlpkt[] = {
	SCAPY_BUF_BYTES(sst_xlpkt)
};

#define LEN_SST_EXP sizeof(sst_req)
#define LEN_SST_NOT_EXP sizeof(sst_rep)
#define LEN_SST_NOT_EXP_PAD sizeof(sst_rep_pad)

/**
 * These are here so that test_fail_now() that returns is captured
 * for expected errors
 */
static __always_inline
int force_assert_fail_off(struct __ctx_buff *ctx)
{
	test_init();

	ASSERT_CTX_BUF_OFF(ASSERT1_FAIL, "Ether", ctx, 0, sst_rep,
			   LEN_SST_NOT_EXP);

	fake_test_end();

	return TEST_PASS;
}

static __always_inline
int force_assert_fail_off2(struct __ctx_buff *ctx)
{
	test_init();

	ASSERT_CTX_BUF_OFF2(ASSERT2_FAIL, "Ether", ctx, 0, "sst_rep",
			    sst_rep, LEN_SST_NOT_EXP,
			    LEN_SST_NOT_EXP);
	fake_test_end();

	return TEST_PASS;
}

static __always_inline
int force_assert_fail_ctx_smaller_exp(struct __ctx_buff *ctx)
{
	test_init();

	ASSERT_CTX_BUF_OFF2(ASSERT3_FAIL, "Ether", ctx, 0, "sst_rep_pad",
			    sst_rep_pad, LEN_SST_NOT_EXP_PAD,
			    LEN_SST_NOT_EXP_PAD);
	fake_test_end();

	return TEST_PASS;
}

PKTGEN("tc", "1_basic_test")
int pktgen_scapy_basic_test(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, sst_req, sizeof(sst_req));

	pktgen__finish(&builder);

	return 0;
}

CHECK("tc", "1_basic_test")
int check_scapy_basic_test(struct __ctx_buff *ctx)
{
	int rc, id;
	struct scapy_assert *entry;

	test_init();

	ASSERT_CTX_BUF_OFF(ASSERT1, "Ether", ctx, 0, sst_req,
			   LEN_SST_EXP);
	ASSERT_CTX_BUF_OFF2(ASSERT2, "Ether", ctx, 0, "sst_req",
			    sst_req, LEN_SST_EXP, LEN_SST_EXP);

	/* Test failures */
	rc = force_assert_fail_off(ctx);
	assert(rc == TEST_FAIL);
	rc = force_assert_fail_off2(ctx);
	assert(rc == TEST_FAIL);
	rc = force_assert_fail_ctx_smaller_exp(ctx);
	assert(rc == TEST_FAIL);

	assert(scapy_assert_map_cnt == 3);

	{
		/* ASSERT_CTX_BUF_OFF */
		id = 0;
		entry = map_lookup_elem(&scapy_assert_map, &id);
		assert(entry);
		assert(scapy_memcmp(entry->exp_buf, sst_rep,
				    LEN_SST_NOT_EXP) == 0);
		assert(scapy_memcmp(entry->got_buf, sst_req,
				    LEN_SST_EXP) == 0);
		assert(memcmp(entry->name, ASSERT1_FAIL,
			      sizeof(ASSERT1_FAIL)) == 0);
		assert(entry->exp_len == LEN_SST_NOT_EXP);
		assert(entry->got_len == LEN_SST_EXP);
		assert(entry->exp_len == entry->got_len);

		rc = map_update_elem(&scapy_assert_map, &id,
				     &__scapy_null_assert, BPF_ANY);
		assert(rc == 0);
	}
	{
		/* ASSERT_CTX_BUF_OFF2 */
		id = 1;
		entry = map_lookup_elem(&scapy_assert_map, &id);
		assert(entry);
		assert(scapy_memcmp(entry->exp_buf, sst_rep,
				    LEN_SST_NOT_EXP) == 0);
		assert(scapy_memcmp(entry->got_buf, sst_req,
				    LEN_SST_EXP) == 0);
		assert(memcmp(entry->name, ASSERT2_FAIL,
			      sizeof(ASSERT2_FAIL)) == 0);
		assert(entry->exp_len == LEN_SST_NOT_EXP);
		assert(entry->got_len == LEN_SST_EXP);
		assert(entry->exp_len == entry->got_len);
		rc = map_update_elem(&scapy_assert_map, &id,
				     &__scapy_null_assert, BPF_ANY);
		assert(rc == 0);
	}
	{
		/* len(CTX) < len(EXP) */
		id = 2;
		entry = map_lookup_elem(&scapy_assert_map, &id);
		assert(entry);
		assert(scapy_memcmp(entry->exp_buf, sst_rep,
				    LEN_SST_NOT_EXP) == 0);
		assert(scapy_memcmp(entry->got_buf, __scapy_null_assert.got_buf,
				    LEN_SST_EXP) == 0);
		assert(memcmp(entry->name, ASSERT3_FAIL,
			      sizeof(ASSERT3_FAIL)) == 0);
		assert(entry->exp_len == LEN_SST_NOT_EXP_PAD);
		assert(entry->got_len == LEN_SST_EXP);
		rc = map_update_elem(&scapy_assert_map, &id,
				     &__scapy_null_assert, BPF_ANY);
		assert(rc == 0);
	}

	test_finish();

	return 0;
}

PKTGEN("tc", "1_test_large_pkts")
int pktgen_scapy_large_pkts(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, sst_lpkt, sizeof(sst_lpkt));

	pktgen__finish(&builder);

	return 0;
}

CHECK("tc", "1_test_large_pkts")
int check_scapy_large_pkts(struct __ctx_buff *ctx)
{
	test_init();

	ASSERT_CTX_BUF_OFF("assert_large_1", "Ether", ctx, 0, sst_lpkt,
			   sizeof(sst_lpkt));

	test_finish();

	return 0;
}

PKTGEN("tc", "2_test_xlarge_pkts")
int pktgen_scapy_xlarge_pkts(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, sst_xlpkt, sizeof(sst_xlpkt));

	pktgen__finish(&builder);

	return 0;
}

CHECK("tc", "2_test_xlarge_pkts")
int check_scapy_xlarge_pkts(struct __ctx_buff *ctx)
{
	test_init();

	ASSERT_CTX_BUF_OFF("assert_xl_1", "Ether", ctx, 0, sst_xlpkt,
			   sizeof(sst_xlpkt));

	test_finish();

	return 0;
}

BPF_LICENSE("Dual BSD/GPL");
