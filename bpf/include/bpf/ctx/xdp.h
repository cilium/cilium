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
#ifndef __BPF_CTX_XDP_H_
#define __BPF_CTX_XDP_H_

#include "common.h"

#define __ctx_buff			xdp_md

#define CTX_ACT_OK			XDP_PASS
#define CTX_ACT_DROP			XDP_DROP
#define CTX_ACT_TX			XDP_TX	/* hairpin only */

#define ctx_pull_data(ctx, ...)		do { /* Already linear. */ } while (0)
#define ctx_event_output		xdp_event_output

/* Empty stubs below. */
#ifndef ENOTSUPP
# define ENOTSUPP			524
#endif

#define ctx_under_cgroup(...)		({ -ENOTSUPP; })
#define ctx_load_bytes_relative(...)	({ -ENOTSUPP; })
#define ctx_store_bytes(...)		({ -ENOTSUPP; })
#define ctx_adjust_room(...)		({ -ENOTSUPP; })
#define ctx_change_type(...)		({ -ENOTSUPP; })
#define ctx_change_proto(...)		({ -ENOTSUPP; })
#define ctx_change_tail(...)		({ -ENOTSUPP; })
#define ctx_vlan_push(...)		({ -ENOTSUPP; })
#define ctx_vlan_pop(...)		({ -ENOTSUPP; })
#define ctx_get_tunnel_key(...)		({ -ENOTSUPP; })
#define ctx_set_tunnel_key(...)		({ -ENOTSUPP; })
#define ctx_get_tunnel_opt(...)		({ -ENOTSUPP; })
#define ctx_set_tunnel_opt(...)		({ -ENOTSUPP; })

#define get_hash_recalc(ctx)		0

static __always_inline __maybe_unused int
ctx_load_bytes(struct xdp_md *xdp, __u32 off, void *to, __u32 len)
{
	/* Dummy stub. */
	__builtin_memset(to, 0, len);
	return -ENOTSUPP;
}

static __always_inline __maybe_unused __overloadable __u32
ctx_full_len(struct xdp_md *ctx)
{
	/* No non-linear section. */
	return (unsigned long)(__u32)ctx->data_end -
	       (unsigned long)(__u32)ctx->data;
}

#endif /* __BPF_CTX_SKB_H_ */
