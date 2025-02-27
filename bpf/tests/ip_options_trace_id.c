// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "node_config.h"

#define DEBUG
#include <lib/ip_options.h>

/* Used to define IP options for packet generation. */
struct ipopthdr {
	/* type field of the IP option. */
	__u8 type;
	/* len field of the IP option. Usually equal to total length of the IP
	 * option, including type and len. Can be specified different from data
	 * length for testing purposes. If zero, it will not be written to the
	 * packet, so that tests can specify single-byte options.
	 */
	__u8 len;
	/* Arbitrary data for the payload of the IP option. */
	__u8 *data;
	/* Length of the data field in bytes. Must match exactly. */
	__u8 data_len;
};

/* Injects a packet into the ctx with the IPv4 options specified. See comments
 * on the struct for more details on how to specify options. The total byte
 * content of the options must align on 4-byte boundaries so that the IHL can be
 * accurate.
 * opts_len:   the number of options in opts.
 * opts_bytes: the total number of bytes in options.
 */
static __always_inline __maybe_unused int
gen_packet_with_options(struct __sk_buff *ctx,
			const struct ipopthdr *opts,
			__u8 opts_len, __u8 opt_bytes)
{
	struct pktgen builder;
	struct iphdr *l3;
	__u8 *new_opt;
	int i, j, new_opt_len;

	if (opt_bytes % 4 != 0)
		return TEST_ERROR;
	pktgen__init(&builder, ctx);
	if (!pktgen__push_ethhdr(&builder))
		return TEST_ERROR;
	l3 = pktgen__push_default_iphdr_with_options(&builder, opt_bytes / 4);
	if (!l3)
		return TEST_ERROR;

	new_opt = (__u8 *)&l3[1];
	for (i = 0; i < opts_len; i++) {
		new_opt_len = 0;
		new_opt[0] = opts[i].type;
		new_opt_len++;
		if (opts[i].len != 0) {
			new_opt[new_opt_len] = opts[i].len;
			new_opt_len++;
		}
		for (j = 0; j < opts[i].data_len; j++) {
			new_opt[new_opt_len] = opts[i].data[j];
			new_opt_len++;
		}
		new_opt += new_opt_len;
	}
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;
	pktgen__finish(&builder);
	return TEST_PASS;
}

/* Following section has tests for trace ID feature for packet
 * validation and preprocessing.
 */

/* Test packet with no l3 header should return TRACE_ID_ERROR. */
PKTGEN("tc", "extract_trace_id_with_no_l3_header_error")
int test_extract_trace_id_with_no_l3_header_error_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	if (!pktgen__push_ethhdr(&builder))
		return TEST_ERROR;
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;
	pktgen__finish(&builder);
	return TEST_PASS;
}

CHECK("tc", "extract_trace_id_with_no_l3_header_error")
int test_extract_trace_id_with_no_l3_header_error_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_ERROR;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test packet with no eth header should return TRACE_ID_NO_FAMILY. */
PKTGEN("tc", "extract_trace_id_with_no_eth_header_no_family")
int test_extract_trace_id_with_no_eth_header_no_family_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;
	pktgen__finish(&builder);
	return TEST_PASS;
}

CHECK("tc", "extract_trace_id_with_no_eth_header_no_family")
int test_extract_trace_id_with_no_eth_header_no_family_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_NO_FAMILY;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test packet with IPv6 header should return TRACE_ID_SKIP_IPV6. */
PKTGEN("tc", "extract_trace_id_no_ipv6_options")
int test_extract_trace_id_no_ipv6_options_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	if (!pktgen__push_ethhdr(&builder))
		return TEST_ERROR;
	if (!pktgen__push_default_ipv6hdr(&builder))
		return TEST_ERROR;
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return TEST_PASS;
}

CHECK("tc", "extract_trace_id_no_ipv6_options")
int test_extract_trace_id_no_ipv6_options_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_SKIP_IPV6;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
	test_finish();
}

/* Test a single option specifying the trace ID with no special cases. */
PKTGEN("tc", "extract_trace_id_solo")
int test_extract_trace_id_solo_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 136,
			.len = 4,
			.data = (__u8 *)"\x00\x01",
			.data_len = 2,
		},
	};
	return gen_packet_with_options(ctx, opts, 1, 4);
}

CHECK("tc", "extract_trace_id_solo")
int test_extract_trace_id_solo_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 1;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test packet with IPv4 header should return TRACE_ID_NOT_FOUND. */
PKTGEN("tc", "extract_trace_id_no_ipv4_options")
int test_extract_trace_id_no_options_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	if (!pktgen__push_ethhdr(&builder))
		return TEST_ERROR;
	if (!pktgen__push_iphdr(&builder, 0))
		return TEST_ERROR;
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return TEST_PASS;
}

CHECK("tc", "extract_trace_id_no_ipv4_options")
int test_extract_trace_id_no_options_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_NOT_FOUND;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test trace ID after END should return TRACE_ID_NOT_FOUND. */
PKTGEN("tc", "extract_trace_id_after_ipopt_end_not_found")
int test_extract_trace_id_after_ipopt_end_not_found_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = IPOPT_END,
			.len = 0,
			.data_len = 0,
		},
		{
			.type = 136,
			.len = 4,
			.data = (__u8 *)"\x00\x01",
			.data_len = 2,
		},
		/* Add padding to align on 4-byte boundary. */
		{
			.type = IPOPT_NOOP,
			.len = 0,
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0,
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0,
			.data_len = 0,
		},
	};
	return gen_packet_with_options(ctx, opts, 5, 8);
}

CHECK("tc", "extract_trace_id_after_ipopt_end_not_found")
int test_extract_trace_id_after_ipopt_end_not_found_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_NOT_FOUND;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test trace ID comes after loop limit should return TRACE_ID_NOT_FOUND. */
PKTGEN("tc", "extract_trace_id_after_loop_limit_not_found")
int test_extract_trace_id_after_loop_limit_not_found_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = IPOPT_NOOP,
			.len = 0,
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0,
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0,
			.data_len = 0,
		},
		/* The loop limit is 3 so the following options are ignored. */
		{
			.type = 136,
			.len = 4,
			.data = (__u8 *)"\x00\x01",
			.data_len = 2,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0,
			.data_len = 0,
		},
	};
	return gen_packet_with_options(ctx, opts, 5, 8);
}

CHECK("tc", "extract_trace_id_after_loop_limit_not_found")
int test_extract_trace_id_after_loop_limit_not_found_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_NOT_FOUND;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test three options with the trace ID option being first. */
PKTGEN("tc", "extract_trace_id_first_of_three")
int test_extract_trace_id_first_of_three_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 136,
			.len = 4,
			.data = (__u8 *)"\x00\x01",
			.data_len = 2,
		},
		{
			.type = 10,
			.len = 4,
			.data = (__u8 *)"\x10\x10",
			.data_len = 2,
		},
		{
			.type = 11,
			.len = 4,
			.data = (__u8 *)"\x11\x11",
			.data_len = 2,
		},
	};
	return gen_packet_with_options(ctx, opts, 3, 12);
}

CHECK("tc", "extract_trace_id_first_of_three")
int test_extract_trace_id_first_of_three_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 1;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test three options with the trace ID option being between the other two. */
PKTGEN("tc", "extract_trace_id_middle_of_three")
int test_extract_trace_id_middle_of_three_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 10,
			.len = 4,
			.data = (__u8 *)"\x10\x10",
			.data_len = 2,
		},
		{
			.type = 136,
			.len = 4,
			.data = (__u8 *)"\x00\x01",
			.data_len = 2,
		},
		{
			.type = 11,
			.len = 4,
			.data = (__u8 *)"\x11\x11",
			.data_len = 2,
		},
	};
	return gen_packet_with_options(ctx, opts, 3, 12);
}

CHECK("tc", "extract_trace_id_middle_of_three")
int test_extract_trace_id_middle_of_three_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 1;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test three options with the trace ID option being last of the three. */
PKTGEN("tc", "extract_trace_id_last_of_three")
int test_extract_trace_id_last_of_three_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 10,
			.len = 4,
			.data = (__u8 *)"\x10\x10",
			.data_len = 2,
		},
		{
			.type = 11,
			.len = 4,
			.data = (__u8 *)"\x11\x11",
			.data_len = 2,
		},
		{
			.type = 136,
			.len = 4,
			.data = (__u8 *)"\x00\x01",
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 3, 12);
}

CHECK("tc", "extract_trace_id_last_of_three")
int test_extract_trace_id_last_of_three_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 1;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test multiple options with the trace ID coming after a NOOP option. */
PKTGEN("tc", "extract_trace_id_after_ipopt_noop")
int test_extract_trace_id_after_ipopt_noop_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = IPOPT_NOOP,
			.len = 0, /* Single byte option. */
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, /* Single byte option. */
			.data_len = 0,
		},
		{
			.type = 136,
			.len = 4,
			.data = (__u8 *)"\x00\x01",
			.data_len = 2,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, /* Single byte option. */
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, /* Single byte option. */
			.data_len = 0,
		},
	};
	return gen_packet_with_options(ctx, opts, 5, 8);
}

CHECK("tc", "extract_trace_id_after_ipopt_noop")
int test_extract_trace_id_after_ipopt_noop_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 1;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test multiple options with the trace ID not present should return TRACE_ID_NOT_FOUND. */
PKTGEN("tc", "extract_trace_id_not_found_with_other_options")
int test_extract_trace_id__not_found_with_other_options_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 10,
			.len = 4,
			.data = (__u8 *)"\x10\x10",
			.data_len = 2,
		},
		{
			.type = 11,
			.len = 4,
			.data = (__u8 *)"\x11\x11",
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 2, 8);
}

CHECK("tc", "extract_trace_id_not_found_with_other_options")
int test_extract_trace_id_not_found_with_other_options_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_NOT_FOUND;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test trace ID with incorrect length field should return INVALID. */
PKTGEN("tc", "extract_trace_id_wrong_len_invalid")
int test_extract_trace_id_wrong_len_invalid_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 136,
			.len = 3, /* Invalid length with this option. */
			.data = (__u8 *)"\x00\x01",
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 1, 4);
}

CHECK("tc", "extract_trace_id_wrong_len_invalid")
int test_extract_trace_id_wrong_len_invalid_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_INVALID;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test trace ID with negative value should return TRACE_ID_INVALID. */
PKTGEN("tc", "extract_trace_id_negative")
int test_extract_trace_id_negative_invalid_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
				.type = 136,
				.len = 4,
				.data = (__u8 *)"\x80\x01",
				.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 1, 4);
}

CHECK("tc", "extract_trace_id_negative")
int test_extract_trace_id_negative_invalid_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 0x8001;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);

	test_finish();
}

/* Store and read trace ID to different option than stream ID with 2 bytes of data. */
PKTGEN("tc", "extract_trace_id_different_option_type")
int test_extract_trace_id_different_option_type_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 137,
			.len = 4,
			.data = (__u8 *)"\x00\x02",
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 1, 4);
}

CHECK("tc", "extract_trace_id_different_option_type")
int test_extract_trace_id_different_option_type_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 0x0002;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 137);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Read trace ID from wrong IP option. */
PKTGEN("tc", "extract_read_trace_id_wrong_option_type")
int test_extract_read_trace_id_wrong_option_type_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 137,
			.len = 4,
			.data = (__u8 *)"\x00\x02",
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 1, 4);
}

CHECK("tc", "extract_read_trace_id_wrong_option_type")
int test_extract_read_trace_id_wrong_option_type_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_NOT_FOUND;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	test_finish();
}

/* Test a valid 4-byte trace ID. */
PKTGEN("tc", "extract_trace_id_4_bytes_valid")
int test_extract_trace_id_4_bytes_valid_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 136,
			.len = 6,
			.data = (__u8 *)"\x00\x01\x23\x45",
			.data_len = 4,
		},
	};

	return gen_packet_with_options(ctx, opts, 1, 8);
}

CHECK("tc", "extract_trace_id_4_bytes_valid")
int test_extract_trace_id_4_bytes_valid_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 0x00012345;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
	test_finish();
}

/* Test negative trace id should return valid. */
PKTGEN("tc", "extract_trace_id_negative_4_bytes")
int test_extract_trace_id_negative_4_bytes_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 136,
			.len = 6,
			.data = (__u8 *)"\x80\x01\x23\x45",
			.data_len = 4,
		},
	};

	return gen_packet_with_options(ctx, opts, 1, 8);
}

CHECK("tc", "extract_trace_id_negative_4_bytes")
int test_extract_trace_id_negative_4_bytes_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 0x80012345;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
	test_finish();
}

/* Test a 4-byte trace ID with incorrect length. */
PKTGEN("tc", "extract_trace_id_4_bytes_wrong_length")
int test_extract_trace_id_4_bytes_wrong_length_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 136,
			.len = 5, /* Incorrect length */
			.data = (__u8 *)"\x01\x23\x45\x67",
			.data_len = 4,
		},
	};
	return gen_packet_with_options(ctx, opts, 1, 8);
}

CHECK("tc", "extract_trace_id_4_bytes_wrong_length")
int test_extract_trace_id_4_bytes_wrong_length_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_INVALID;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
	test_finish();
}

/* Test a 4-byte trace ID before the end of option list. */
PKTGEN("tc", "extract_trace_id_4_bytes_before_end")
int test_extract_trace_id_4_bytes_before_end_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 136,
			.len = 6,
			.data = (__u8 *)"\x00\x01\x23\x45",
			.data_len = 4,
		},
		{
			.type = IPOPT_END,
			.len = 0,
			.data_len = 0,
		},
	};
	return gen_packet_with_options(ctx, opts, 2, 8);
}

CHECK("tc", "extract_trace_id_4_bytes_before_end")
int test_extract_trace_id_4_bytes_before_end_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 0x12345;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
	test_finish();
}

/* Test a valid 8-byte trace ID should return TRACE_ID_ERROR. */
PKTGEN("tc", "extract_trace_id_8_bytes_valid")
int test_extract_trace_id_8_bytes_valid_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 136,
			.len = 10,
			.data = (__u8 *)"\x12\x34\x56\x78\x9A\xBC\xDE\xF0",
			.data_len = 8,
		},
	};
	return gen_packet_with_options(ctx, opts, 1, 12);
}

CHECK("tc", "extract_trace_id_8_bytes_valid")
int test_extract_trace_id_8_bytes_valid_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 0x123456789abcdef0;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
	test_finish();
}

/* Test an 8-byte trace ID followed by padding. */
PKTGEN("tc", "extract_trace_id_8_bytes_with_padding")
int test_extract_trace_id_8_bytes_with_padding_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 136,
			.len = 10, /* Total length including type and len fields */
			.data = (__u8 *)"\x01\x02\x03\x04\x00\x00\x00\x00",
			.data_len = 8,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0,
			.data_len = 0,
		},
	};

	return gen_packet_with_options(ctx, opts, 2, 12);
}

CHECK("tc", "extract_trace_id_8_bytes_with_padding")
int test_extract_trace_id_8_bytes_with_padding_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 0x0102030400000000; /* Expected valid trace ID */
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
	test_finish();
}

/* Test an 8-byte trace ID that represents a negative value. */
PKTGEN("tc", "extract_trace_id_8_bytes_negative")
int test_extract_trace_id_8_bytes_negative_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 136,
			.len = 10,
			.data = (__u8 *)"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFA",
			.data_len = 8,
		},
	};

	return gen_packet_with_options(ctx, opts, 1, 12);
}

CHECK("tc", "extract_trace_id_8_bytes_negative")
int test_extract_trace_id_8_bytes_negative_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 0xFFFFFFFFFFFFFFFA;
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);

	test_finish();
}

/* Test an 8-byte trace ID with an invalid option length. */
PKTGEN("tc", "extract_trace_id_8_bytes_invalid_length")
int test_extract_trace_id_8_bytes_invalid_length_pktgen(struct __ctx_buff *ctx)
{
	struct ipopthdr opts[] = {
		{
			.type = 136,
			.len = 9, /* Invalid length, should be 10 */
			.data = (__u8 *)"\x01\x02\x03\x04\x05\x06\x07\x08",
			.data_len = 8,
		},
	};
	return gen_packet_with_options(ctx, opts, 1, 12);
}

CHECK("tc", "extract_trace_id_8_bytes_invalid_length")
int test_extract_trace_id_8_bytes_invalid_length_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_INVALID; /* Expected invalid trace ID */
	__s64 trace_id = 0;
	int ret;

	ret = trace_id_from_ctx(ctx, &trace_id, 136);
	if (IS_ERR(ret))
		trace_id = ret;

	if (trace_id != want)
		test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
	test_finish();
}
