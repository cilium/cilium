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

#define SKIP_CALLS_MAP

#include <node_config.h>
#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <sys/socket.h>

#include "../lib/utils.h"
#include "../lib/common.h"
#include "../lib/maps.h"

#include "sockops_config.h"
#include "bpf_sockops.h"

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

__section("sk_msg")
int bpf_ipc(struct sk_msg_md *msg)
{
	struct sock_key key = {};
	__u64 flags = BPF_F_INGRESS;
	int err;

#if 0
	// TODO: IPV6
	key.sip6.p1 = msg->remote_ip6[0];
	key.sip6.p2 = msg->remote_ip6[1];
	key.sip6.p3 = msg->remote_ip6[2];
	key.sip6.p4 = msg->remote_ip6[3];
	key.dip6.p1 = msg->local_ip6[0];
	key.dip6.p2 = msg->local_ip6[1];
	key.dip6.p3 = msg->local_ip6[2];
	key.dip6.p4 = msg->local_ip6[3];
	key.family = ENDPOINT_KEY_IPV6;
#endif

	key.sip4 = msg->remote_ip4;
	key.dip4 = msg->local_ip4;
	key.family = ENDPOINT_KEY_IPV4;

	key.dport = bpf_ntohl(msg->local_port);
	key.sport = msg->remote_port;

	err = msg_redirect_hash(msg, &SOCK_OPS_MAP, &key, flags);

#if DBG
	printk("ipc key1: sip4 %u dip4 %u family %u\n", key.sip4, key.dip4, key.family);
	printk("ipc key2: dport %u sport %u\n", key.dport, key.sport);
	printk("ipc ipv4(%i) (%i -> %i)!\n", err, bpf_ntohl(msg->local_port), msg->remote_port);
#endif
	return err;
}

BPF_LICENSE("GPL");
int _version __section("version") = 1;
