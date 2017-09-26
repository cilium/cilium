/*
 *  Copyright (C) 2017 Authors of Cilium
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
#ifndef __LIB_XDP_H_
#define __LIB_XDP_H_

#include <stdbool.h>

struct lpm_v4_key {
	struct bpf_lpm_trie_key lpm;
	__u8 addr[4];
};

struct lpm_v6_key {
	struct bpf_lpm_trie_key lpm;
	__u8 addr[16];
};

struct lpm_val {
	/* Just dummy for now. */
	__u8 flags;
};

static __always_inline void *xdp_data(const struct xdp_md *xdp)
{
	return (void *)(unsigned long)xdp->data;
}

static __always_inline void *xdp_data_end(const struct xdp_md *xdp)
{
	return (void *)(unsigned long)xdp->data_end;
}

static __always_inline bool xdp_no_room(const void *needed, const void *limit)
{
	return unlikely(needed > limit);
}

#endif /* __LIB_XDP_H_ */
