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
#ifndef __LIB_SIGNAL_H_
#define __LIB_SIGNAL_H_

#include <bpf/api.h>

struct bpf_elf_map __section_maps SIGNAL_MAP = {
	.type		= BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= __NR_CPUS__,
};

enum {
	SIGNAL_NAT_FILL_UP = 0,
	SIGNAL_CT_FILL_UP,
};

enum {
	SIGNAL_PROTO_V4 = 0,
	SIGNAL_PROTO_V6,
};

struct signal_msg {
	__u32 signal_nr;
	union {
		struct {
			__u32 proto;
		};
	};
};

static inline void send_signal(struct __sk_buff *skb, struct signal_msg *msg)
{
	skb_event_output(skb, &SIGNAL_MAP, BPF_F_CURRENT_CPU,
			 msg, sizeof(*msg));
}

static inline void send_signal_nat_fill_up(struct __sk_buff *skb, __u32 proto)
{
	struct signal_msg msg = {
		.signal_nr	= SIGNAL_NAT_FILL_UP,
		.proto		= proto,
	};

	send_signal(skb, &msg);
}

static __always_inline void send_signal_ct_fill_up(struct __sk_buff *skb,
						   __u32 proto)
{
	struct signal_msg msg = {
		.signal_nr	= SIGNAL_CT_FILL_UP,
		.proto		= proto,
	};

	send_signal(skb, &msg);
}

#endif /* __LIB_SIGNAL_H_ */
