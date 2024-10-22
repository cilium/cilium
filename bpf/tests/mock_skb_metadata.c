// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/builtins.h>
#include <bpf/ctx/skb.h>

#include "mock_skb_metadata.h"

PKTGEN("tc", "01_mock_skb_metadata")
int mock_skb_metadata_pktgen(__maybe_unused struct __ctx_buff *ctx)
{
	ctx_store_meta(ctx, 0, 1);
	ctx_store_meta(ctx, 1, 2);
	ctx_store_meta(ctx, 2, 3);
	ctx_store_meta(ctx, 3, 4);
	ctx_store_meta(ctx, 4, 5);
	return 0;
}

CHECK("tc", "01_mock_skb_metadata")
int mock_skb_metadata_check1(__maybe_unused struct __ctx_buff *ctx)
{
	__u32 data;

	/*
	 * metadata values survives over single test among
	 * multiple prog run.
	 */
	test_init();

	data = ctx_load_meta(ctx, 0);
	assert(data == 1);
	data = ctx_load_meta(ctx, 1);
	assert(data == 2);
	data = ctx_load_meta(ctx, 2);
	assert(data == 3);
	data = ctx_load_meta(ctx, 3);
	assert(data == 4);
	data = ctx_load_meta(ctx, 4);
	assert(data == 5);

	test_finish();
}

CHECK("tc", "02_mock_skb_metadata")
int mock_skb_metadata_check2(__maybe_unused struct __ctx_buff *ctx)
{
	__u32 data;

	/*
	 * shouldn't leak values from previous test to next test
	 */
	test_init();

	data = ctx_load_meta(ctx, 0);
	assert(data == 0);
	data = ctx_load_meta(ctx, 1);
	assert(data == 0);
	data = ctx_load_meta(ctx, 2);
	assert(data == 0);
	data = ctx_load_meta(ctx, 3);
	assert(data == 0);
	data = ctx_load_meta(ctx, 4);
	assert(data == 0);

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
