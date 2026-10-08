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

int cil_lxc_policy_seq;
__section("tc/entry")
int cil_lxc_policy(struct __sk_buff *ctx __maybe_unused)
{
	cil_lxc_policy_seq = inc();
	return 1;
}

TAIL_PROGRAM_CALLER("tc/entry", tc_caller, cilium_calls, 13, struct __sk_buff *, tail_call_enabled)
TAIL_PROGRAM("tc/tail", tail_tc, struct __sk_buff *, 13)

TAIL_PROGRAM_CALLER("tc/entry", policy_caller, cilium_call_policy, 42, struct __sk_buff *, policy_caller_enabled)

PROGRAM("tc/entry", tc, struct __sk_buff *)
PROGRAM("xdp/entry", xdp, struct xdp_md *)

PROGRAM("cgroup/connect4", connect4, struct bpf_sock_addr *)
PROGRAM("cgroup/bind4", bind4, struct bpf_sock_addr *)
PROGRAM("cgroup/post_bind4", post_bind4, struct bpf_sock *)
PROGRAM("cgroup/sendmsg4", sendmsg4, struct bpf_sock_addr *)
PROGRAM("cgroup/recvmsg4", recvmsg4, struct bpf_sock_addr *)
PROGRAM("cgroup/getpeername4", getpeername4, struct bpf_sock_addr *)

PROGRAM("cgroup/connect6", connect6, struct bpf_sock_addr *)
PROGRAM("cgroup/bind6", bind6, struct bpf_sock_addr *)
PROGRAM("cgroup/post_bind6", post_bind6, struct bpf_sock *)
PROGRAM("cgroup/sendmsg6", sendmsg6, struct bpf_sock_addr *)
PROGRAM("cgroup/recvmsg6", recvmsg6, struct bpf_sock_addr *)
PROGRAM("cgroup/getpeername6", getpeername6, struct bpf_sock_addr *)

PROGRAM("cgroup/sock_release", sock_release, struct bpf_sock *)

BPF_LICENSE("Dual BSD/GPL");
