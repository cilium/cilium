// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>
#include <lib/static_data.h>

#include "bpf_plugins.h"
#include <bpf/tailcall.h>

/* Every field of the loader test's config struct must exist in each base
 * collection, so declare the same config variables as bpf_plugins_base.c.
 */
DECLARE_CONFIG(int, tail_call_enabled, "enable tail call in caller program")
DECLARE_CONFIG(int, policy_caller_enabled, "enable tail call in policy caller program")
DECLARE_CONFIG(int, policy_outbound_enabled, "enable outbound tail call in policy program")

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 100);
} cilium_calls __section_maps_btf;

/* Set at runtime to pick which of the two static tail calls
 * program_tc_multi_caller takes.
 */
int tc_multi_caller_second_target;

int program_tc_multi_caller_seq;
__section("tc/entry")
int program_tc_multi_caller(struct __sk_buff *ctx __maybe_unused)
{
	program_tc_multi_caller_seq = inc();
	if (CONFIG(tail_call_enabled)) {
		if (tc_multi_caller_second_target) {
			tail_call_static(ctx, cilium_calls, 14);
		} else {
			tail_call_static(ctx, cilium_calls, 13);
		}
	}
	return 1;
}

TAIL_PROGRAM("tc/tail", tail_tc_a, struct __sk_buff *, 13)
TAIL_PROGRAM("tc/tail", tail_tc_b, struct __sk_buff *, 14)

BPF_LICENSE("Dual BSD/GPL");
