// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

#include "pktgen.h"

/* We need to mock loggers to test ASSERT MACRO failures */
#define __ASSERT_TRACE_FAIL_LEN(...)
#define __ASSERT_TRACE_FAIL_BUF(...)
#include "scapy.h"

#define fake_test_end() (void)suite_result; } while(0)

#define ASSERT1 "assert1"
#define ASSERT2 "assert2"
#define ASSERT3 "assert3"

#define ASSERT1_FAIL "assert1_fail"
#define ASSERT2_FAIL "assert2_fail"
#define ASSERT3_FAIL "assert3_fail"

#define LEN_EXP_ARP_REQ sizeof(BUF(EXP_ARP_REQ))
#define LEN_NOT_EXP_ARP_REPLY sizeof(BUF(NOT_EXP_ARP_REPLY))

/* These are here so that test_fail_now() that returns is captured
 * for expected errors */
static __always_inline
int force_assert_fail_off(struct __ctx_buff *ctx)
{
	test_init();

	BUF_DECL(NOT_EXP_ARP_REPLY, l2_announce_arp_reply);

	ASSERT_CTX_BUF_OFF(ASSERT1_FAIL, "Ether", ctx, 0, NOT_EXP_ARP_REPLY,
			   LEN_NOT_EXP_ARP_REPLY);

	fake_test_end();

	return TEST_PASS;
}

static __always_inline
int force_assert_fail_off2(struct __ctx_buff *ctx)
{
	test_init();

	BUF_DECL(NOT_EXP_ARP_REPLY, l2_announce_arp_reply);

	ASSERT_CTX_BUF_OFF2(ASSERT2_FAIL, "Ether", ctx, 0, NOT_EXP_ARP_REPLY,
			    BUF(NOT_EXP_ARP_REPLY), LEN_NOT_EXP_ARP_REPLY,
			    LEN_NOT_EXP_ARP_REPLY);
	fake_test_end();

	return TEST_PASS;
}

static __always_inline
int force_assert_fail_off2_cfi(struct __ctx_buff *ctx)
{
	test_init();

	BUF_DECL(NOT_EXP_ARP_REPLY, l2_announce_arp_reply);

	ASSERT_CTX_BUF_OFF2_CFI(ASSERT3_FAIL, 123, "Ether", ctx, 0,
			    BUF(NOT_EXP_ARP_REPLY), LEN_NOT_EXP_ARP_REPLY,
			    LEN_NOT_EXP_ARP_REPLY);
	fake_test_end();

	return TEST_PASS;
}
static struct scapy_assert null_entry = {0};

PKTGEN("tc", "1_basic_test")
int pktgen_scapy_basic_test(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(EXP_ARP_REQ, l2_announce_arp_req);
	BUILDER_PUSH_BUF(builder, EXP_ARP_REQ);

	pktgen__finish(&builder);

	return 0;
}

CHECK("tc", "1_basic_test")
int check_scapy_basic_test(struct __ctx_buff *ctx)
{
	int rc, id;
	struct scapy_assert *entry;

	test_init();

	BUF_DECL(EXP_ARP_REQ, l2_announce_arp_req);
	BUF_DECL(NOT_EXP_ARP_REPLY, l2_announce_arp_reply);

	ASSERT_CTX_BUF_OFF(ASSERT1, "Ether", ctx, 0, EXP_ARP_REQ,
			   LEN_EXP_ARP_REQ);
	ASSERT_CTX_BUF_OFF2(ASSERT2, "Ether", ctx, 0, EXP_ARP_REQ,
			    BUF(EXP_ARP_REQ), LEN_EXP_ARP_REQ, LEN_EXP_ARP_REQ);
	ASSERT_CTX_BUF_OFF2_CFI(ASSERT3, 1, "Ether", ctx, 0, BUF(EXP_ARP_REQ),
			         LEN_EXP_ARP_REQ, LEN_EXP_ARP_REQ);

	/* Test failures */
	rc = force_assert_fail_off(ctx);
	assert(rc == TEST_FAIL);
	rc = force_assert_fail_off2(ctx);
	assert(rc == TEST_FAIL);
	rc = force_assert_fail_off2_cfi(ctx);
	assert(rc == TEST_FAIL);

	assert(scapy_assert_map_cnt == 3);

	{
		/* ASSERT_CTX_BUF_OFF */
		id = 0;
		entry = map_lookup_elem(&scapy_assert_map, &id);
		assert(entry != NULL);
		assert(scapy_memcmp(entry->exp_buf, BUF(NOT_EXP_ARP_REPLY),
				    LEN_NOT_EXP_ARP_REPLY) == 0);
		assert(scapy_memcmp(entry->got_buf, BUF(EXP_ARP_REQ),
				    LEN_EXP_ARP_REQ) == 0);
		assert(memcmp(entry->name, ASSERT1_FAIL,
			      sizeof(ASSERT1_FAIL)) == 0);
		assert(entry->len == LEN_NOT_EXP_ARP_REPLY);
		assert(entry->cfi == -1);
		rc = map_update_elem(&scapy_assert_map, &id, &null_entry,
				     BPF_ANY);
		assert(rc == 0);
	}
	{
		/* ASSERT_CTX_BUF_OFF2 */
		id = 1;
		entry = map_lookup_elem(&scapy_assert_map, &id);
		assert(entry != NULL);
		assert(scapy_memcmp(entry->exp_buf, BUF(NOT_EXP_ARP_REPLY),
				    LEN_NOT_EXP_ARP_REPLY) == 0);
		assert(scapy_memcmp(entry->got_buf, BUF(EXP_ARP_REQ),
				    LEN_EXP_ARP_REQ) == 0);
		assert(memcmp(entry->name, ASSERT2_FAIL,
			      sizeof(ASSERT2_FAIL)) == 0);
		assert(entry->cfi == -1);
		rc = map_update_elem(&scapy_assert_map, &id, &null_entry,
				     BPF_ANY);
		assert(rc == 0);
	}
	{
		/* ASSERT_CTX_BUF_OFF2_CFI */
		id = 2;
		entry = map_lookup_elem(&scapy_assert_map, &id);
		assert(entry != NULL);
		assert(scapy_memcmp(entry->exp_buf, BUF(NOT_EXP_ARP_REPLY),
				    LEN_NOT_EXP_ARP_REPLY) == 0);
		assert(scapy_memcmp(entry->got_buf, BUF(EXP_ARP_REQ),
				    LEN_EXP_ARP_REQ) == 0);
		assert(memcmp(entry->name, ASSERT3_FAIL,
			      sizeof(ASSERT2_FAIL)) == 0);
		assert(entry->cfi == 123);
		rc = map_update_elem(&scapy_assert_map, &id, &null_entry,
				     BPF_ANY);
		assert(rc == 0);
	}

	test_finish();

	return 0;
}

BPF_LICENSE("Dual BSD/GPL");
