// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include "bpf_plugins.h"

PRE(tc, struct __sk_buff *, -1, 3)
POST(tc, struct __sk_buff *, -1, 3)

PRE(xdp, struct xdp_md *, -1, 3)
POST(xdp, struct xdp_md *, -1, 3)

PRE(connect4, struct bpf_sock_addr *, 0, 1)
POST(connect4, struct bpf_sock_addr *, 0, 1)
PRE(bind4, struct bpf_sock_addr *, 0, 3)
POST(bind4, struct bpf_sock_addr *, 0, 3)
PRE(post_bind4, struct bpf_sock *, 0, 1)
POST(post_bind4, struct bpf_sock *, 0, 1)
PRE(sendmsg4, struct bpf_sock_addr *, 0, 1)
POST(sendmsg4, struct bpf_sock_addr *, 0, 1)
PRE(recvmsg4, struct bpf_sock_addr *, 1, 1)
POST(recvmsg4, struct bpf_sock_addr *, 1, 1)
PRE(getpeername4, struct bpf_sock_addr *, 1, 1)
POST(getpeername4, struct bpf_sock_addr *, 1, 1)
PRE(connect6, struct bpf_sock_addr *, 0, 1)
POST(connect6, struct bpf_sock_addr *, 0, 1)
PRE(bind6, struct bpf_sock_addr *, 0, 3)
POST(bind6, struct bpf_sock_addr *, 0, 3)
PRE(post_bind6, struct bpf_sock *, 0, 1)
POST(post_bind6, struct bpf_sock *, 0, 1)
PRE(sendmsg6, struct bpf_sock_addr *, 0, 1)
POST(sendmsg6, struct bpf_sock_addr *, 0, 1)
PRE(recvmsg6, struct bpf_sock_addr *, 1, 1)
POST(recvmsg6, struct bpf_sock_addr *, 1, 1)
PRE(getpeername6, struct bpf_sock_addr *, 1, 1)
POST(getpeername6, struct bpf_sock_addr *, 1, 1)
PRE(sock_release, struct bpf_sock *, 0, 1)
POST(sock_release, struct bpf_sock *, 0, 1)

BPF_LICENSE("Dual BSD/GPL");
