/*
 *  Copyright (C) 2018 Authors of Cilium
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

#include <node_config.h>
#include <lxc_config.h>

#define EVENT_SOURCE LXC_ID

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/utils.h"
#include "lib/common.h"

#define printk(fmt, ...)				\
	({						\
		char ____fmt[] = fmt;			\
		trace_printk(____fmt, sizeof(____fmt),	\
			     ##__VA_ARGS__);		\
	})

#if 0
#define CILIUM_MAP_EGRESS 0xff

struct bpf_elf_map __section_maps EGRESS_MAP = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_EGRESS,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 1,
};

__section_tail(CILIUM_MAP_EGRESS, 0) int lxc_egress_entry(struct __sk_buff *skb)
{
	return TC_ACT_OK;
}
#endif

__section("entry") int x(struct __sk_buff *skb)
{
//	printk("hello world from %u\n", EVENT_SOURCE);
	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
