/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf_overlay.c>

#define FROM_OVERLAY		0
#define TO_OVERLAY		1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_OVERLAY] = &cil_from_overlay,
		[TO_OVERLAY] = &cil_to_overlay,
	},
};

static __always_inline int
overlay_receive_packet(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	return TEST_ERROR;
}

static __always_inline int
overlay_send_packet(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, TO_OVERLAY);
	return TEST_ERROR;
}

