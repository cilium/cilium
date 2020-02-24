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
#ifndef __LIB_OVERLOADABLE_XDP_H_
#define __LIB_OVERLOADABLE_XDP_H_

static __always_inline __maybe_unused __overloadable void
bpf_clear_cb(struct xdp_md *ctx)
{
}

static __always_inline __maybe_unused __overloadable int
get_identity(struct xdp_md *ctx)
{
	return 0;
}

static __always_inline __maybe_unused __overloadable void
set_encrypt_dip(struct xdp_md *ctx, __u32 ip_endpoint)
{
}

static __always_inline __maybe_unused __overloadable void
set_identity(struct xdp_md *ctx, __u32 identity)
{
}

static __always_inline __maybe_unused __overloadable void
set_identity_cb(struct xdp_md *ctx, __u32 identity)
{
}

static __always_inline __maybe_unused __overloadable void
set_encrypt_key(struct xdp_md *ctx, __u8 key)
{
}

static __always_inline __maybe_unused __overloadable void
set_encrypt_key_cb(struct xdp_md *ctx, __u8 key)
{
}

static __always_inline __maybe_unused __overloadable int
redirect_self(struct xdp_md *ctx)
{
	return -ENOTSUP;
}

#endif /* __LIB_OVERLOADABLE_XDP_H_ */
