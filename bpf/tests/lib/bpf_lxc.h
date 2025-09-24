/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf_lxc.c>

#define FROM_CONTAINER		0
#define TO_CONTAINER		1
#define TO_CONTAINER_TAILCALL	2

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 3);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_CONTAINER] = &cil_from_container,
		[TO_CONTAINER] = &cil_to_container,
		[TO_CONTAINER_TAILCALL] = &cil_lxc_policy,
	},
};

static __always_inline int
pod_send_packet(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

static __always_inline int
pod_receive_packet(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, TO_CONTAINER);
	return TEST_ERROR;
}

static __always_inline int
pod_receive_packet_by_tailcall(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, TO_CONTAINER_TAILCALL);
	return TEST_ERROR;
}
