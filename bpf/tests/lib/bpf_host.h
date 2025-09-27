/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf_host.c>

#define FROM_NETDEV		0
#define TO_NETDEV		1
#define FROM_HOST		2
#define TO_HOST			3

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 4);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
		[TO_NETDEV] = &cil_to_netdev,
		[FROM_HOST] = &cil_from_host,
		[TO_HOST] = &cil_to_host,
	},
};

static __always_inline int
netdev_receive_packet(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

static __always_inline int
netdev_send_packet(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

static __always_inline int
host_receive_packet(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, TO_HOST);
	return TEST_ERROR;
}

static __always_inline int
host_send_packet(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, FROM_HOST);
	return TEST_ERROR;
}
