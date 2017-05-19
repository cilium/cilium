/*
 *  Copyright (C) 2016-2017 Authors of Cilium
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
#ifndef __LIB_MAPS_H_
#define __LIB_MAPS_H_

#include "common.h"

#define CILIUM_MAP_POLICY	1
#define CILIUM_MAP_CALLS	2
#define CILIUM_MAP_RES_POLICY	3

struct bpf_elf_map __section_maps cilium_lxc = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct lxc_info),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 1024,
};

/* Global map to jump into policy enforcement of receiving endpoint */
struct bpf_elf_map __section_maps cilium_policy = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_POLICY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= POLICY_MAP_SIZE,
};

struct bpf_elf_map __section_maps cilium_reserved_policy = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_RES_POLICY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= RESERVED_POLICY_SIZE,
};

struct bpf_elf_map __section_maps cilium_proxy4 = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct proxy4_tbl_key),
	.size_value	= sizeof(struct proxy4_tbl_value),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 8192,
};

struct bpf_elf_map __section_maps cilium_proxy6= {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct proxy6_tbl_key),
	.size_value	= sizeof(struct proxy6_tbl_value),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 8192,
};

/* Private per EP map for internal tail calls */
struct bpf_elf_map __section_maps CALLS_MAP = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_CALLS,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_CALL_SIZE,
};

static __always_inline void ep_tail_call(struct __sk_buff *skb, uint32_t index)
{
	tail_call(skb, &CALLS_MAP, index);
}

#endif
