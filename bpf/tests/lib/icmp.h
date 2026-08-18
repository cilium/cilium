/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

struct validate_icmpv6_reply_args {
	const struct __ctx_buff *ctx;
	const __u8 *buf_expected;
	__u16 buf_len;
	__u32 dst_idx;
	__u32 retval;
};

static __always_inline int
validate_icmpv6_reply(const struct validate_icmpv6_reply_args *args)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ratelimit_value *value;

	test_init();

	data = (void *)(long)ctx_data(args->ctx);
	data_end = (void *)(long)args->ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	test_log("Status code: %d", *status_code);
	assert(*status_code == args->retval);

	ASSERT_CTX_BUF_OFF2("icmpv6_reply",
			    "Ether", args->ctx, sizeof(__u32),
			    "icmpv6_reply",
			    args->buf_expected,
			    args->buf_len,
			    args->buf_len);

	struct ratelimit_key key = {
		.usage = RATELIMIT_USAGE_ICMPV6,
		.key = {
			.icmpv6 = {
				.netdev_idx = args->dst_idx,
			},
		},
	};

	value = map_lookup_elem(&cilium_ratelimit, &key);
	if (!value)
		test_fatal("ratelimit map lookup failed");

	assert(value->tokens > 0);

	test_finish();
}
