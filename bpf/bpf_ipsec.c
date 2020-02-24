/*
 *  Copyright (C) 2019 Authors of Cilium
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
#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#include "lib/common.h"
#include "lib/dbg.h"

__section("from-netdev")
int from_netdev(struct __ctx_buff *ctx)
{
	if ((ctx->cb[0] & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT) {
		ctx->mark = ctx->cb[0];
		set_identity(ctx, ctx->cb[1]);
	} else {
		// Upper 16 bits may carry proxy port number, clear it out
		__u32 magic = ctx->cb[0] & 0xFFFF;
		if (magic == MARK_MAGIC_TO_PROXY) {
			__be16 port = ctx->cb[0] >> 16;

			ctx->mark = ctx->cb[0];
			ctx_change_type(ctx, PACKET_HOST);
			cilium_dbg_capture(ctx, DBG_CAPTURE_PROXY_POST, port);
		}
	}
	return CTX_ACT_OK;
}

BPF_LICENSE("GPL");
