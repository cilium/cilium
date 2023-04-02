/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef ____BPF_TEST_COMMON____
#define ____BPF_TEST_COMMON____

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

#ifndef ___bpf_concat
#define ___bpf_concat(a, b) a ## b
#endif
#ifndef ___bpf_apply
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#endif
#ifndef ___bpf_nth
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#endif
#ifndef ___bpf_narg
#define ___bpf_narg(...) \
	___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#endif

#define __bpf_log_arg0(ptr, arg) do {} while (0)
#define __bpf_log_arg1(ptr, arg) *(ptr++) = MKR_LOG_ARG; *(__u64 *)(ptr) = arg; ptr += sizeof(__u64)
#define __bpf_log_arg2(ptr, arg, args...) *(ptr++) = MKR_LOG_ARG; *(__u64 *)(ptr) = arg; \
					  ptr += sizeof(__u64); __bpf_log_arg1(ptr, args)
#define __bpf_log_arg3(ptr, arg, args...) *(ptr++) = MKR_LOG_ARG; *(__u64 *)(ptr) = arg; \
					  ptr += sizeof(__u64); __bpf_log_arg2(ptr, args)
#define __bpf_log_arg4(ptr, arg, args...) *(ptr++) = MKR_LOG_ARG; *(__u64 *)(ptr) = arg; \
					  ptr += sizeof(__u64); __bpf_log_arg3(ptr, args)
#define __bpf_log_arg5(ptr, arg, args...) *(ptr++) = MKR_LOG_ARG; *(__u64 *)(ptr) = arg; \
					  ptr += sizeof(__u64); __bpf_log_arg4(ptr, args)
#define __bpf_log_arg6(ptr, arg, args...) *(ptr++) = MKR_LOG_ARG; *(__u64 *)(ptr) = arg; \
					  ptr += sizeof(__u64); __bpf_log_arg5(ptr, args)
#define __bpf_log_arg7(ptr, arg, args...) *(ptr++) = MKR_LOG_ARG; *(__u64 *)(ptr) = arg; \
					  ptr += sizeof(__u64); __bpf_log_arg6(ptr, args)
#define __bpf_log_arg8(ptr, arg, args...) *(ptr++) = MKR_LOG_ARG; *(__u64 *)(ptr) = arg; \
					  ptr += sizeof(__u64); __bpf_log_arg7(ptr, args)
#define __bpf_log_arg9(ptr, arg, args...) *(ptr++) = MKR_LOG_ARG; *(__u64 *)(ptr) = arg; \
					  ptr += sizeof(__u64); __bpf_log_arg8(ptr, args)
#define __bpf_log_arg10(ptr, arg, args...) *(ptr++) = MKR_LOG_ARG; *(__u64 *)(ptr) = arg; \
					  ptr += sizeof(__u64); __bpf_log_arg9(ptr, args)
#define __bpf_log_arg11(ptr, arg, args...) *(ptr++) = MKR_LOG_ARG; *(__u64 *)(ptr) = arg; \
					  ptr += sizeof(__u64); __bpf_log_arg10(ptr, args)
#define __bpf_log_arg12(ptr, arg, args...) *(ptr++) = MKR_LOG_ARG; *(__u64 *)(ptr) = arg; \
					  ptr += sizeof(__u64); __bpf_log_arg11(ptr, args)
#define __bpf_log_arg(ptr, args...) \
	___bpf_apply(__bpf_log_arg, ___bpf_narg(args))(ptr, args)

/* These values have to stay in sync with the enum */
/* values in test/bpf_tests/trf.proto */
#define TEST_ERROR 0
#define TEST_PASS 1
#define TEST_FAIL 2
#define TEST_SKIP 3

/* Use an array map with 1 key and a large value size as buffer to write results */
/* into. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, 8192);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} suite_result_map __section_maps_btf;

/* Values for the markers below are derived from this guide: */
/* https://developers.google.com/protocol-buffers/docs/encoding#structure */

#define PROTOBUF_WIRE_TYPE(field, type) ((field) << 3 | (type))

#define PROTOBUF_VARINT 0
#define PROTOBUF_FIXED64 1
#define PROTOBUF_LENGTH_DELIMITED 2

/* message SuiteResult */
#define MKR_TEST_RESULT PROTOBUF_WIRE_TYPE(1, PROTOBUF_LENGTH_DELIMITED)
#define MKR_SUITE_LOG	PROTOBUF_WIRE_TYPE(2, PROTOBUF_LENGTH_DELIMITED)

/* message TestResult */
#define MKR_TEST_NAME	PROTOBUF_WIRE_TYPE(1, PROTOBUF_LENGTH_DELIMITED)
#define MKR_TEST_STATUS PROTOBUF_WIRE_TYPE(2, PROTOBUF_VARINT)
#define MKR_TEST_LOG	PROTOBUF_WIRE_TYPE(3, PROTOBUF_LENGTH_DELIMITED)

/* message Log */
#define MKR_LOG_FMT	PROTOBUF_WIRE_TYPE(1, PROTOBUF_LENGTH_DELIMITED)
#define MKR_LOG_ARG	PROTOBUF_WIRE_TYPE(2, PROTOBUF_FIXED64)

/* Write a message to the unit log
 *	The conversion specifiers supported by *fmt* are the same as for
 *      bpf_trace_printk(). They are **%d**, **%i**, **%u**, **%x**, **%ld**,
 *      **%li**, **%lu**, **%lx**, **%lld**, **%lli**, **%llu**, **%llx**,
 *      **%p**. No modifier (size of field, padding with zeroes, etc.)
 *      is available
 */
#define test_log(fmt, args...)						\
({									\
	static const char ____fmt[] = fmt;				\
	if (test_result_cursor) {					\
		*(suite_result_cursor++) = MKR_TEST_LOG;		\
	} else {							\
		*(suite_result_cursor++) = MKR_SUITE_LOG;		\
	}								\
	*(suite_result_cursor++) = 2 + sizeof(____fmt) +		\
		___bpf_narg(args) +					\
		(___bpf_narg(args) * sizeof(unsigned long long));	\
	*(suite_result_cursor++) = MKR_LOG_FMT;			\
	*(suite_result_cursor++) = sizeof(____fmt);			\
	memcpy(suite_result_cursor, ____fmt, sizeof(____fmt));		\
	suite_result_cursor += sizeof(____fmt);			\
									\
									\
	if (___bpf_narg(args) > 0) {					\
		__bpf_log_arg(suite_result_cursor, args);		\
	}								\
})

/* This is a hack to allow us to convert the integer produced by __LINE__ */
/* to a string so we can concat it at compile time. */
#define STRINGIZE(x) STRINGIZE2(x)
#define STRINGIZE2(x) #x
#define LINE_STRING STRINGIZE(__LINE__)

/* Mark the current test as failed */
#define test_fail()				\
	if (test_result_cursor) {		\
		*test_result_status = TEST_FAIL;\
	} else {				\
		suite_result = TEST_FAIL;	\
	}					\

/* Mark the current test as failed and exit the current TEST/CHECK */
#define test_fail_now()				\
	if (test_result_cursor) {		\
		*test_result_status = TEST_FAIL;\
		break;				\
	} else {				\
		return TEST_FAIL;		\
	}

/* Mark the current test as skipped */
#define test_skip()				\
	if (test_result_cursor) {		\
		*test_result_status = TEST_SKIP;\
	} else {				\
		suite_result = TEST_SKIP;	\
	}

/* Mark the current test as skipped and exit the current TEST/CHECK */
#define test_skip_now()					\
	if (test_result_cursor) {			\
		*test_result_status = TEST_SKIP;	\
		break;					\
	} else {					\
		return TEST_SKIP;			\
	}

/* Write message to the log and mark current test as failed. */
#define test_error(fmt, ...)			\
	{					\
		test_log(fmt, ##__VA_ARGS__);	\
		test_fail();			\
	}

/* Log a message bpf_then fail_now */
#define test_fatal(fmt, ...)			\
	{					\
		test_log(fmt, ##__VA_ARGS__);	\
		test_fail_now()			\
	}

/* Assert that `cond` is true, fail the rest otherwise */
#define assert(cond)							\
	if (!(cond)) {							\
		test_log("assert failed at " __FILE__ ":" LINE_STRING);	\
		test_fail_now();					\
	}

/* Declare bpf_map_lookup_elem with the test_ prefix to avoid conflicts in the */
/* future. */
static void *(*test_bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

/* Init sets up a number of variables which will be used by other macros. */
/* - suite_result will be returned from the eBPF program */
/* - test_result_status is a pointer into the suite_result_map when in a test */
/* - suite_result_cursor keeps track of where in the suite result we are. */
/* - test_result_cursor is a pointer to the varint of a test result, used to */
/*   write the amount of bytes used after a test is done. */
#define test_init()							  \
	char suite_result = TEST_PASS;					  \
	__maybe_unused char *test_result_status = 0;			  \
	char *suite_result_cursor;					  \
	{								  \
		__u32 __key = 0;						  \
		suite_result_cursor =					  \
			test_bpf_map_lookup_elem(&suite_result_map, &__key);\
		if (!suite_result_cursor) {				  \
			return TEST_ERROR;				  \
		}							  \
	}								  \
	__maybe_unused char *test_result_cursor = 0;			  \
	__maybe_unused __u16 test_result_size;				  \
	do {
/* */
/* Each test is single iteration do-while loop so we can break, to exit the */
/* test without unique label names and goto's */
#define TEST(name, body)						   \
do {									   \
	*(suite_result_cursor++) = MKR_TEST_RESULT;			   \
	/* test_result_cursor will stay at test result length varint */    \
	test_result_cursor = suite_result_cursor;			   \
	/* Reserve 2 bytes for the varint indicating test result length */ \
	suite_result_cursor += 2;					   \
									   \
	static const char ____name[] = name;				   \
	*(suite_result_cursor++) = MKR_TEST_NAME;			   \
	*(suite_result_cursor++) = sizeof(____name);			   \
	memcpy(suite_result_cursor, ____name, sizeof(____name));	   \
	suite_result_cursor += sizeof(____name);			   \
									   \
	*(suite_result_cursor++) = MKR_TEST_STATUS;			   \
	test_result_status = suite_result_cursor;			   \
									   \
	*test_result_status = TEST_PASS;				   \
	suite_result_cursor++;						   \
									   \
	body								   \
} while (0);								   \
/* Write the total size of the test result in bytes as varint */	   \
test_result_size = (__u16)((long)suite_result_cursor -			   \
	(long)test_result_cursor) - 2;					   \
if (test_result_size > 127) {						   \
	*(test_result_cursor) = (__u8)(test_result_size & 0b01111111) |	   \
		0b10000000;						   \
	test_result_size >>= 7;						   \
	*(test_result_cursor + 1) = (__u8)test_result_size;		   \
} else {								   \
	*test_result_cursor = (__u8)(test_result_size) | 0b10000000;	   \
}									   \
test_result_cursor = 0;

#define test_finish()		\
	} while (0);		\
	return suite_result

#define PKTGEN(progtype, name) __section(progtype "/test/" name "/pktgen")
#define SETUP(progtype, name) __section(progtype "/test/" name "/setup")
#define CHECK(progtype, name) __section(progtype "/test/" name "/check")

#define LPM_LOOKUP_FN(NAME, IPTYPE, PREFIXES, MAP, LOOKUP_FN)	\
static __always_inline int __##NAME(IPTYPE addr)		\
{								\
	int prefixes[] = { PREFIXES };				\
	const int size = ARRAY_SIZE(prefixes);			\
	int i;							\
								\
_Pragma("unroll")						\
	for (i = 0; i < size; i++)				\
		if (LOOKUP_FN(&(MAP), addr, prefixes[i]))	\
			return 1;				\
								\
	return 0;						\
}

#endif /* ____BPF_TEST_COMMON____ */
