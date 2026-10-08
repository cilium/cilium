// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>
#include <lib/static_data.h>

#include "bpf_plugins.h"
#include <bpf/tailcall.h>

DECLARE_CONFIG(int, tail_call_enabled, "enable tail call in caller program")
DECLARE_CONFIG(int, policy_caller_enabled, "enable tail call in policy caller program")

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 100);
} cilium_calls __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1024);
} cilium_call_policy __section_maps_btf;

int cil_lxc_policy_egress_seq;
__section("xdp/entry")
int cil_lxc_policy_egress(struct xdp_md *ctx __maybe_unused)
{
	cil_lxc_policy_egress_seq = inc();
	return 1;
}

PROGRAM("xdp/entry", xdp, struct xdp_md *)

TAIL_PROGRAM_CALLER("xdp/entry", xdp_caller, cilium_calls, 13, struct xdp_md *, tail_call_enabled)
TAIL_PROGRAM("xdp/tail", tail_xdp, struct xdp_md *, 13)

TAIL_PROGRAM_CALLER("xdp/entry", xdp_policy_caller, cilium_call_policy, 42, struct xdp_md *, policy_caller_enabled)

BPF_LICENSE("Dual BSD/GPL");
