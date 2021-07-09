/* GENERATED FROM bpf/helpers_skb.h */
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __MOCK_HELPERS_SKB__
#define __MOCK_HELPERS_SKB__

#include <linux/bpf.h>

#include <bpf/compiler.h>
#include <bpf/features_skb.h>

/* Only used helpers in Cilium go below. */

/* Packet redirection */
int redirect(int ifindex, __u32 flags);
int redirect_neigh(int ifindex, struct bpf_redir_neigh *params,
		    int plen, __u32 flags);
int redirect_peer(int ifindex, __u32 flags);

/* Packet manipulation */
int skb_load_bytes(struct __sk_buff *skb, __u32 off,
		    void *to, __u32 len);
int skb_store_bytes(struct __sk_buff *skb, __u32 off,
		    const void *from, __u32 len, __u32 flags);

int l3_csum_replace(struct __sk_buff *skb, __u32 off,
		    __u32 from, __u32 to, __u32 flags);
int l4_csum_replace(struct __sk_buff *skb, __u32 off,
		    __u32 from, __u32 to, __u32 flags);

int skb_adjust_room(struct __sk_buff *skb, __s32 len_diff,
		    __u32 mode, __u64 flags);

int skb_change_type(struct __sk_buff *skb, __u32 type);
int skb_change_proto(struct __sk_buff *skb, __u32 proto,
		    __u32 flags);
int skb_change_tail(struct __sk_buff *skb, __u32 nlen,
		    __u32 flags);
int skb_change_head(struct __sk_buff *skb, __u32 head_room,
		    __u64 flags);

int skb_pull_data(struct __sk_buff *skb, __u32 len);

/* Packet tunnel encap/decap */
int skb_get_tunnel_key(struct __sk_buff *skb,
		    struct bpf_tunnel_key *to, __u32 size, __u32 flags);
int skb_set_tunnel_key(struct __sk_buff *skb,
		    const struct bpf_tunnel_key *from, __u32 size,
		    __u32 flags);

/* Events for user space */
int skb_event_output(struct __sk_buff *skb, void *map,
			  __u64 index, const void *data, __u32 size);

/* Socket lookup, assign, release */
struct bpf_sock *skc_lookup_tcp(struct __sk_buff *skb,
				 struct bpf_sock_tuple *tuple, __u32 tuple_size,
				 __u64 netns, __u64 flags);
int sk_release(struct bpf_sock *sk);
int sk_assign(struct __sk_buff *skb, struct bpf_sock *sk,
		    __u64 flags);

#endif /* __MOCK_HELPERS_SKB__ */
