/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __BPF_HELPERS_SKB__
#define __BPF_HELPERS_SKB__

#include <linux/bpf.h>

#include "compiler.h"
#include "helpers.h"
#include "features_skb.h"

/* Only used helpers in Cilium go below. */

/* Packet redirection */
static int BPF_FUNC(redirect, int ifindex, __u32 flags);

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

static int BPF_FUNC(skb_pull_data, struct __sk_buff *skb, __u32 len);

/* Packet tunnel encap/decap */
static int BPF_FUNC(skb_get_tunnel_key, struct __sk_buff *skb,
		    struct bpf_tunnel_key *to, __u32 size, __u32 flags);
static int BPF_FUNC(skb_set_tunnel_key, struct __sk_buff *skb,
		    const struct bpf_tunnel_key *from, __u32 size,
		    __u32 flags);

/* Packet classification (egress) */
static __u64 BPF_FUNC(get_cgroup_classid, struct __sk_buff *skb);

/* Events for user space */
static int BPF_FUNC_REMAP(skb_event_output, struct __sk_buff *skb, void *map,
			  __u64 index, const void *data, __u32 size) =
			 (void *)BPF_FUNC_perf_event_output;

#endif /* __BPF_HELPERS_SKB__ */
