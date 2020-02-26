/*
 *  Copyright (C) 2020 Authors of Cilium
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
#ifndef __BPF_CTX_SKB_H_
#define __BPF_CTX_SKB_H_

#include "common.h"

#ifndef TC_ACT_OK
# define TC_ACT_OK		0
#endif

#ifndef TC_ACT_SHOT
# define TC_ACT_SHOT		2
#endif

#ifndef TC_ACT_REDIRECT
# define TC_ACT_REDIRECT	7
#endif

#define __ctx_buff		__sk_buff

#define CTX_ACT_OK		TC_ACT_OK
#define CTX_ACT_DROP		TC_ACT_SHOT
#define CTX_ACT_TX		TC_ACT_REDIRECT

#define ctx_under_cgroup	skb_under_cgroup
#define ctx_load_bytes_relative	skb_load_bytes_relative
#define ctx_load_bytes		skb_load_bytes
#define ctx_store_bytes		skb_store_bytes
#define ctx_adjust_room		skb_adjust_room
#define ctx_change_type		skb_change_type
#define ctx_change_proto	skb_change_proto
#define ctx_change_tail		skb_change_tail
#define ctx_pull_data		skb_pull_data
#define ctx_vlan_push		skb_vlan_push
#define ctx_vlan_pop		skb_vlan_pop
#define ctx_get_tunnel_key	skb_get_tunnel_key
#define ctx_set_tunnel_key	skb_set_tunnel_key
#define ctx_get_tunnel_opt	skb_get_tunnel_opt
#define ctx_set_tunnel_opt	skb_set_tunnel_opt
#define ctx_event_output	skb_event_output

static __always_inline __maybe_unused __overloadable __u32
ctx_full_len(struct __sk_buff *ctx)
{
	return ctx->len;
}

#endif /* __BPF_CTX_SKB_H_ */
