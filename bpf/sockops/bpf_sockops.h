/*
 *  Copyright (C) 2018-2019 Authors of Cilium
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

#include "sockops_config.h"

/* Structure representing an L7 sock */
struct sock_key {
	union {
		struct {
			__u32		sip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	sip6;
	};
	union {
		struct {
			__u32		dip4;
			__u32		pad4;
			__u32		pad5;
			__u32		pad6;
		};
		union v6addr	dip6;
	};
	__u8 family;
	__u8 pad7;
	__u16 pad8;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

struct bpf_elf_map __section_maps SOCK_OPS_MAP = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.size_key       = sizeof(struct sock_key),
	.size_value     = sizeof(int),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = SOCKOPS_MAP_SIZE,
};

static __always_inline void sk_extract4_key(struct bpf_sock_ops *ops,
					    struct sock_key *key)
{
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = ENDPOINT_KEY_IPV4;

	key->sport = (bpf_ntohl(ops->local_port) >> 16);
	key->dport = ops->remote_port >> 16;
}

static __always_inline void sk_msg_extract4_key(struct sk_msg_md *msg,
						struct sock_key *key)
{
	key->dip4 = msg->remote_ip4;
	key->sip4 = msg->local_ip4;
	key->family = ENDPOINT_KEY_IPV4;

	key->sport = (bpf_ntohl(msg->local_port) >> 16);
	key->dport = msg->remote_port >> 16;
}

static __always_inline void sk_lb4_key_v2(struct lb4_key_v2 *lb4,
					  struct sock_key *key)
{
	/* SK MSG is always egress, so use daddr */
	lb4->address = key->dip4;
	lb4->dport = key->dport;
}

static __always_inline bool redirect_to_proxy(int verdict)
{
	return verdict > 0;
}
