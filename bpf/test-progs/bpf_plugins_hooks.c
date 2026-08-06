// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include "bpf_plugins.h"

PRE("freplace", tc, struct __sk_buff *, -1, 3)
POST(tc, struct __sk_buff *, -1, 3)

PRE("freplace", tc_caller, struct __sk_buff *, -1, 3)
POST(tc_caller, struct __sk_buff *, -1, 3)
PRE("tc", tail_tc, struct __sk_buff *, -1, 3)

PRE("freplace", policy_caller, struct __sk_buff *, -1, 3)
PRE_POLICY("tc", cil_lxc_policy, struct __sk_buff *, -1, 3)
POST(policy_caller, struct __sk_buff *, -1, 3)

PRE("freplace", xdp, struct xdp_md *, -1, 3)
POST(xdp, struct xdp_md *, -1, 3)

PRE("freplace", xdp_caller, struct xdp_md *, -1, 3)
POST(xdp_caller, struct xdp_md *, -1, 3)
PRE("xdp/tail", tail_xdp, struct xdp_md *, -1, 3)

PRE("freplace", xdp_policy_caller, struct xdp_md *, -1, 3)
PRE_POLICY("xdp/tail", cil_lxc_policy_egress, struct xdp_md *, -1, 3)
POST(xdp_policy_caller, struct xdp_md *, -1, 3)

PRE("freplace", connect4, struct bpf_sock_addr *, 0, 1)
POST(connect4, struct bpf_sock_addr *, 0, 1)
PRE("freplace", bind4, struct bpf_sock_addr *, 0, 3)
POST(bind4, struct bpf_sock_addr *, 0, 3)
PRE("freplace", post_bind4, struct bpf_sock *, 0, 1)
POST(post_bind4, struct bpf_sock *, 0, 1)
PRE("freplace", sendmsg4, struct bpf_sock_addr *, 0, 1)
POST(sendmsg4, struct bpf_sock_addr *, 0, 1)
PRE("freplace", recvmsg4, struct bpf_sock_addr *, 1, 1)
POST(recvmsg4, struct bpf_sock_addr *, 1, 1)
PRE("freplace", getpeername4, struct bpf_sock_addr *, 1, 1)
POST(getpeername4, struct bpf_sock_addr *, 1, 1)
PRE("freplace", connect6, struct bpf_sock_addr *, 0, 1)
POST(connect6, struct bpf_sock_addr *, 0, 1)
PRE("freplace", bind6, struct bpf_sock_addr *, 0, 3)
POST(bind6, struct bpf_sock_addr *, 0, 3)
PRE("freplace", post_bind6, struct bpf_sock *, 0, 1)
POST(post_bind6, struct bpf_sock *, 0, 1)
PRE("freplace", sendmsg6, struct bpf_sock_addr *, 0, 1)
POST(sendmsg6, struct bpf_sock_addr *, 0, 1)
PRE("freplace", recvmsg6, struct bpf_sock_addr *, 1, 1)
POST(recvmsg6, struct bpf_sock_addr *, 1, 1)
PRE("freplace", getpeername6, struct bpf_sock_addr *, 1, 1)
POST(getpeername6, struct bpf_sock_addr *, 1, 1)
PRE("freplace", sock_release, struct bpf_sock *, 0, 1)
POST(sock_release, struct bpf_sock *, 0, 1)

BPF_LICENSE("Dual BSD/GPL");
