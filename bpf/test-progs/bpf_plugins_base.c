// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include "bpf_plugins.h"

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
