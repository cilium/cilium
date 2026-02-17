/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/compiler.h>
#include <bpf/loader.h>
#include <bpf/section.h>

/* We can use this macro inside the actual datapath code
 * to compile-in the code for testing. The primary usecase
 * is initializing map-in-map or prog-map.
 */
#define BPF_TEST

/* These values have to stay in sync with the enum */
/* values in bpf/tests/bpftest/trf.proto */
#define TEST_ERROR 100
#define TEST_PASS 101
#define TEST_FAIL 102
#define TEST_SKIP 103

/* Max number of cpus to check when doing percpu hash assertions */
#define NR_CPUS 128

#define TEST_MAX_LOG_ENTRIES 64
#define TEST_MAX_BUF_SIZE 256

struct suite_test_result {
	bool valid;
	__u8 pad;
	__u16 n_asserts;
	char name[TEST_MAX_BUF_SIZE]; /* Test name */
	int result;
	__u8 n_logs;
	__u8 pad2[3];
	char logs[TEST_MAX_LOG_ENTRIES][TEST_MAX_BUF_SIZE]; /* test logs */
};

static int __suite_test_cnt;
static int __suite_result;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct suite_test_result));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 32);
} suite_result_map2 __section_maps_btf;

#define __get_curr_test()						\
	struct suite_test_result *__curr_test;				\
	__curr_test = map_lookup_elem(&suite_result_map2,		\
				      &__suite_test_cnt);		\
	if (!__curr_test) return TEST_FAIL

#define __test_log(fmt, args...)					\
	if (__curr_test->n_logs < TEST_MAX_LOG_ENTRIES) {		\
		char *___p = __curr_test->logs[__curr_test->n_logs];	\
		SNPRINTF(___p, TEST_MAX_BUF_SIZE, fmt, args);		\
	}								\
	__curr_test->n_logs++

/**
 * Write a log message
 */
#define test_log(fmt, args...)		\
	{				\
		__get_curr_test();	\
		__test_log(fmt, args);	\
	} do {} while (0)

/* This is a hack to allow us to convert the integer produced by __LINE__ */
/* to a string so we can concat it at compile time. */
#define STRINGIZE(x) STRINGIZE2(x)
#define STRINGIZE2(x) #x
#define LINE_STRING STRINGIZE(__LINE__)

#define __test_set_result(RC) __curr_test->result = RC
#define __test_set_result_now(RC) __test_set_result(RC); break

/* Mark the current test as failed */
#define test_fail()				\
	{					\
		__get_curr_test();		\
		__test_set_result(TEST_FAIL);	\
	} do {} while (0)

/* Mark the current test as failed and exit the current TEST/CHECK */
#define test_fail_now()					\
	{						\
		__get_curr_test();			\
		__test_set_result_now(TEST_FAIL);	\
	} do {} while (0)

/* Mark the current test as skipped */
#define test_skip()					\
	{						\
		__get_curr_test();			\
		__test_set_result(TEST_SKIP);		\
	} do {} while (0)

/* Mark the current test as skipped and exit the current TEST/CHECK */
#define test_skip_now()					\
	{						\
		__get_curr_test();			\
		__test_set_result_now(TEST_SKIP);	\
	} do {} while (0)

/* Write message to the log and mark current test as failed. */
#define test_error(fmt, ...)			\
	{					\
		__get_curr_test();		\
		__test_log(fmt, ##__VA_ARGS__);	\
		__test_set_result(TEST_FAIL);	\
	}

/* Log a message bpf_then fail_now */
#define test_fatal(fmt, ...)				\
	{						\
		__get_curr_test();			\
		__test_log(fmt, ##__VA_ARGS__);		\
		__test_set_result_now(TEST_FAIL);	\
	} do {} while (0)

/* Assert that `cond` is true, fail the rest otherwise */
#define assert(cond)									\
	{										\
		__get_curr_test();							\
		__curr_test->n_asserts++;						\
		if (!(cond)) {								\
			__test_log("assert failed at " __FILE__ ":" LINE_STRING);	\
			__test_set_result_now(TEST_FAIL);				\
		}									\
	} do {} while (0)

/**
 * Initialize a test suite
 */
#define test_init()					\
do {							\
	{						\
	__suite_result = TEST_PASS;			\
	__get_curr_test();				\
	SNPRINTF(__curr_test->name, TEST_MAX_BUF_SIZE,	\
		 "test_" __FILE__  ":" LINE_STRING);	\
	__curr_test->n_logs = 0;			\
	__curr_test->n_asserts = 0;			\
	__curr_test->result = TEST_PASS;		\
	} do {} while (0)

#define __test_finish()						\
} while (0);							\
	{							\
		__get_curr_test();				\
		__suite_test_cnt++;				\
		__curr_test->valid = true;			\
		if (__curr_test->result != TEST_PASS)		\
			__suite_result = __curr_test->result;	\
	} do {} while (0)

#define multi_test_init()			\
	int __multi_test_rc = TEST_PASS;	\
	test_init()

/**
 * Finish test suite
 */
#define test_finish() __test_finish(); return __suite_result

#define multi_test_finish() __test_finish(); return __multi_test_rc

/**
 * TEST() defines an individual test within the test suite
 * Each test is single iteration do-while loop so we can break,
 * to exit the test without unique label names and goto's
 */
#define TEST(NAME, BODY)							\
	do {									\
		test_init();							\
		{								\
			__get_curr_test();					\
			SNPRINTF(__curr_test->name, TEST_MAX_BUF_SIZE, NAME);	\
		}								\
		do {								\
			BODY							\
		} while (0);							\
		__test_finish();						\
		if (__suite_result != TEST_PASS) 				\
			__multi_test_rc = __suite_result;			\
	} while (0)

#define PKTGEN(progtype, name) __section(progtype "/test/" name "/pktgen")
#define SETUP(progtype, name) __section(progtype "/test/" name "/setup")
#define CHECK(progtype, name) __section(progtype "/test/" name "/check")

/* Asserts that the sum of per-cpu metrics map slots for a key equals count */
#define assert_metrics_count(key, count) \
({ \
	struct metrics_value *__entry = NULL; \
	__u64 sum = 0; \
	/* Iterate until lookup encounters null when hitting cpu number */ \
	/* Assumes at most 128 CPUS */ \
	for (int i = 0; i < NR_CPUS; i++) { \
		__entry = map_lookup_percpu_elem(&cilium_metrics, &key, i); \
		if (!__entry) { \
			break; \
		} \
		sum += __entry->count; \
	} \
	assert(sum == count); \
})
