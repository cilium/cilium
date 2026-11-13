// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>
#include <bpf/tailcall.h>
#include <lib/static_data.h>

#include "bpf_plugins.h"

DECLARE_CONFIG(int, tail_call_enabled, "enable tail call in caller program")
DECLARE_CONFIG(int, policy_caller_enabled, "enable tail call in policy caller program")
DECLARE_CONFIG(int, policy_outbound_enabled, "enable outbound tail call in policy program")

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

PROGRAM("xdp/entry", xdp, struct xdp_md *)
MULTI_TAIL_PROGRAM_CALLER("xdp/entry", xdp_caller, cilium_calls, 13, 14,
			  struct xdp_md *, tail_call_enabled)
TAIL_PROGRAM("xdp/tail", tail_xdp, struct xdp_md *, 13)
TAIL_PROGRAM("xdp/tail", tail_xdp_b, struct xdp_md *, 14)
TAIL_PROGRAM_CALLER("xdp/entry", xdp_policy_caller, cilium_call_policy, 42,
		    struct xdp_md *, policy_caller_enabled)
POLICY_PROGRAM("xdp/entry", cil_lxc_policy_egress, struct xdp_md *)

BPF_LICENSE("Dual BSD/GPL");
