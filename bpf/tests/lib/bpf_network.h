/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf_network.c>

#define FROM_NETWORK		0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETWORK] = &cil_from_network,
	},
};

static __always_inline int
network_receive_packet(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, FROM_NETWORK);
	return TEST_ERROR;
}
