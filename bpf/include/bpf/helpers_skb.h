/*
 *  Copyright (C) 2016-2020 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __BPF_HELPERS_SKB__
#define __BPF_HELPERS_SKB__

#include <linux/bpf.h>

#include "compiler.h"
#include "helpers.h"

/* Packet misc meta data */
static __u32 BPF_FUNC(get_cgroup_classid, struct __sk_buff *skb);
static __u32 BPF_FUNC(get_route_realm, struct __sk_buff *skb);
static __u32 BPF_FUNC(get_hash_recalc, struct __sk_buff *skb);
static __u32 BPF_FUNC(set_hash_invalid, struct __sk_buff *skb);

static int BPF_FUNC(skb_under_cgroup, void *map, __u32 index);

/* Packet redirection */
static int BPF_FUNC(redirect, int ifindex, __u32 flags);
static int BPF_FUNC(clone_redirect, struct __sk_buff *skb, int ifindex,
		    __u32 flags);

/* Packet manipulation */
static int BPF_FUNC(skb_load_bytes_relative, struct __sk_buff *skb, __u32 off,
		    void *to, __u32 len, __u32 hdr);
static int BPF_FUNC(skb_load_bytes, struct __sk_buff *skb, __u32 off,
		    void *to, __u32 len);
static int BPF_FUNC(skb_store_bytes, struct __sk_buff *skb, __u32 off,
		    const void *from, __u32 len, __u32 flags);
static int BPF_FUNC(skb_adjust_room, struct __sk_buff *skb, __s32 len_diff,
		    __u32 mode, __u64 flags);

static int BPF_FUNC(l3_csum_replace, struct __sk_buff *skb, __u32 off,
		    __u32 from, __u32 to, __u32 flags);
static int BPF_FUNC(l4_csum_replace, struct __sk_buff *skb, __u32 off,
		    __u32 from, __u32 to, __u32 flags);

static int BPF_FUNC(skb_change_type, struct __sk_buff *skb, __u32 type);
static int BPF_FUNC(skb_change_proto, struct __sk_buff *skb, __u32 proto,
		    __u32 flags);
static int BPF_FUNC(skb_change_tail, struct __sk_buff *skb, __u32 nlen,
		    __u32 flags);
static int BPF_FUNC(skb_pull_data, struct __sk_buff *skb, __u32 len);

/* Packet vlan encap/decap */
static int BPF_FUNC(skb_vlan_push, struct __sk_buff *skb, __u16 proto,
		    __u16 vlan_tci);
static int BPF_FUNC(skb_vlan_pop, struct __sk_buff *skb);

/* Packet tunnel encap/decap */
static int BPF_FUNC(skb_get_tunnel_key, struct __sk_buff *skb,
		    struct bpf_tunnel_key *to, __u32 size, __u32 flags);
static int BPF_FUNC(skb_set_tunnel_key, struct __sk_buff *skb,
		    const struct bpf_tunnel_key *from, __u32 size,
		    __u32 flags);

static int BPF_FUNC(skb_get_tunnel_opt, struct __sk_buff *skb,
		    void *to, __u32 size);
static int BPF_FUNC(skb_set_tunnel_opt, struct __sk_buff *skb,
		    const void *from, __u32 size);

/* Events for user space */
static int BPF_FUNC_REMAP(skb_event_output, struct __sk_buff *skb, void *map,
			  __u64 index, const void *data, __u32 size) =
			 (void *)BPF_FUNC_perf_event_output;

#endif /* __BPF_HELPERS_SKB__ */
