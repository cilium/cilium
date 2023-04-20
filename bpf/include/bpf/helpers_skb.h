/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_HELPERS_SKB__
#define __BPF_HELPERS_SKB__

#include <linux/bpf.h>

#include "compiler.h"
#include "helpers.h"
#include "features_skb.h"

/* Only used helpers in Cilium go below. */

/* Packet redirection */
static int BPF_FUNC(redirect, int ifindex, __u32 flags);
static int BPF_FUNC(redirect_neigh, int ifindex, struct bpf_redir_neigh *params,
		    int plen, __u32 flags);
static int BPF_FUNC(redirect_peer, int ifindex, __u32 flags);

/* Packet manipulation */
static int BPF_FUNC(skb_load_bytes, struct __sk_buff *skb, __u32 off,
		    void *to, __u32 len);
static int BPF_FUNC(skb_store_bytes, struct __sk_buff *skb, __u32 off,
		    const void *from, __u32 len, __u32 flags);

static int BPF_FUNC(l3_csum_replace, struct __sk_buff *skb, __u32 off,
		    __u32 from, __u32 to, __u32 flags);
static int BPF_FUNC(l4_csum_replace, struct __sk_buff *skb, __u32 off,
		    __u32 from, __u32 to, __u32 flags);

static int BPF_FUNC(skb_adjust_room, struct __sk_buff *skb, __s32 len_diff,
		    __u32 mode, __u64 flags);

static int BPF_FUNC(skb_change_type, struct __sk_buff *skb, __u32 type);
static int BPF_FUNC(skb_change_proto, struct __sk_buff *skb, __u32 proto,
		    __u32 flags);
static int BPF_FUNC(skb_change_tail, struct __sk_buff *skb, __u32 nlen,
		    __u32 flags);
static int BPF_FUNC(skb_change_head, struct __sk_buff *skb, __u32 head_room,
		    __u64 flags);

static int BPF_FUNC(skb_pull_data, struct __sk_buff *skb, __u32 len);

/* Packet tunnel encap/decap */
static int BPF_FUNC(skb_get_tunnel_key, struct __sk_buff *skb,
		    struct bpf_tunnel_key *to, __u32 size, __u32 flags);
static int BPF_FUNC(skb_set_tunnel_key, struct __sk_buff *skb,
		    const struct bpf_tunnel_key *from, __u32 size,
		    __u32 flags);
static int BPF_FUNC(skb_get_tunnel_opt, struct __sk_buff *skb,
		    void *opt, __u32 size);
static int BPF_FUNC(skb_set_tunnel_opt, struct __sk_buff *skb,
		    void *opt, __u32 size);

/* Events for user space */
static int BPF_FUNC_REMAP(skb_event_output, struct __sk_buff *skb, void *map,
			  __u64 index, const void *data, __u32 size) =
			 (void *)BPF_FUNC_perf_event_output;

/* Socket lookup, assign, release */
static struct bpf_sock *BPF_FUNC(skc_lookup_tcp, struct __sk_buff *skb,
				 struct bpf_sock_tuple *tuple, __u32 tuple_size,
				 __u64 netns, __u64 flags);
static int BPF_FUNC(sk_release, struct bpf_sock *sk);
static int BPF_FUNC(sk_assign, struct __sk_buff *skb, struct bpf_sock *sk,
		    __u64 flags);

#endif /* __BPF_HELPERS_SKB__ */
