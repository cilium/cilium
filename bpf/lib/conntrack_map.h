/*
 *  Copyright (C) 2016-2019 Authors of Cilium
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
#ifndef __LIB_CONNTRACK_MAP_H_
#define __LIB_CONNTRACK_MAP_H_

#include "common.h"
#include "config.h"

#if defined CT_MAP_TCP4 && defined CT_MAP_TCP6
#ifdef HAVE_LRU_MAP_TYPE
#define CT_MAP_TYPE BPF_MAP_TYPE_LRU_HASH
#else
#define CT_MAP_TYPE BPF_MAP_TYPE_HASH
#endif

#ifdef ENABLE_IPV6
struct bpf_elf_map __section_maps CT_MAP_TCP6 = {
	.type		= CT_MAP_TYPE,
	.size_key	= sizeof(struct ipv6_ct_tuple),
	.size_value	= sizeof(struct ct_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CT_MAP_SIZE_TCP,
#ifndef HAVE_LRU_MAP_TYPE
	.flags		= CONDITIONAL_PREALLOC,
#endif
};

struct bpf_elf_map __section_maps CT_MAP_ANY6 = {
	.type		= CT_MAP_TYPE,
	.size_key	= sizeof(struct ipv6_ct_tuple),
	.size_value	= sizeof(struct ct_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CT_MAP_SIZE_ANY,
#ifndef HAVE_LRU_MAP_TYPE
	.flags		= CONDITIONAL_PREALLOC,
#endif
};

static inline struct bpf_elf_map *
get_ct_map6(struct ipv6_ct_tuple *tuple)
{
	if (tuple->nexthdr == IPPROTO_TCP) {
		return &CT_MAP_TCP6;
	}
	return &CT_MAP_ANY6;
}
#endif

#ifdef ENABLE_IPV4
struct bpf_elf_map __section_maps CT_MAP_TCP4 = {
	.type		= CT_MAP_TYPE,
	.size_key	= sizeof(struct ipv4_ct_tuple),
	.size_value	= sizeof(struct ct_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CT_MAP_SIZE_TCP,
#ifndef HAVE_LRU_MAP_TYPE
	.flags		= CONDITIONAL_PREALLOC,
#endif
};

struct bpf_elf_map __section_maps CT_MAP_ANY4 = {
	.type		= CT_MAP_TYPE,
	.size_key	= sizeof(struct ipv4_ct_tuple),
	.size_value	= sizeof(struct ct_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CT_MAP_SIZE_ANY,
#ifndef HAVE_LRU_MAP_TYPE
	.flags		= CONDITIONAL_PREALLOC,
#endif
};

static inline struct bpf_elf_map *
get_ct_map4(struct ipv4_ct_tuple *tuple)
{
	if (tuple->nexthdr == IPPROTO_TCP) {
		return &CT_MAP_TCP4;
	}
	return &CT_MAP_ANY4;
}
#endif
#endif
#endif /* __LIB_CONNTRACK_MAP_H_ */
