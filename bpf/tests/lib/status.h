/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Returns true if the status code that the test framework prepends to the
 * packet in CHECK programs (i.e. the SETUP program's return value) matches
 * @expected.
 */
static __always_inline bool
ctx_status_code_is(const struct __ctx_buff *ctx, __u32 expected)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		return false;

	return *(__u32 *)data == expected;
}
