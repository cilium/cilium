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
#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <sys/socket.h>

#include "lib/utils.h"
#include "lib/common.h"
//#include "lib/maps.h"
//#include "lib/eps.h"
//#include "lib/events.h"

#include "sockops_config.h"
#include "bpf_sockops.h"

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

#if 0
struct bpf_elf_map __section_maps SOCK_OPS_MAP = {
	.type		= BPF_MAP_TYPE_SOCKHASH,
	.size_key	= sizeof(struct sock_key),
	.size_value	= sizeof(int),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= SOCKOPS_MAP_SIZE,
};
#endif

__section("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	__u32 family, op;
	struct endpoint_key key = {};
//	int err;

	if (!skops)
		return 0;

	family = skops->family;
	op = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		/* Lookup the destination in the list of known local destinations,
		 * if there is a match then add the socket to the list of Fast-IPC
		 * sockets.
		 */
#if 0
		// TODO: IPV6
		key.ip6.p1 = skops->remote_ip6[0];
		key.ip6.p2 = skops->remote_ip6[1];
		key.ip6.p3 = skops->remote_ip6[2];
		key.ip6.p4 = skops->remote_ip6[3];
		key.family = ENDPOINT_KEY_IPV6;
#endif
		key.ip4 = skops->remote_ip4;
		key.family = ENDPOINT_KEY_IPV4;

#if 0
		if (map_lookup_elem(&cilium_lxc, &key)) {
			struct sock_key s = {};
			__u32 local, remote;

			local = bpf_htonl(skops->local_port);
			remote = skops->remote_port;
#if 0
			// TODO: IPV6
			s.sip6.p1 = skops->local_ip6[0];
			s.sip6.p2 = skops->local_ip6[1];
			s.sip6.p3 = skops->local_ip6[2];
			s.sip6.p4 = skops->local_ip6[3];

			s.dip6.p1 = skops->remote_ip6[0];
			s.dip6.p2 = skops->remote_ip6[1];
			s.dip6.p3 = skops->remote_ip6[2];
			s.dip6.p4 = skops->remote_ip6[3];
			s.family = ENDPOINT_KEY_IPV6;
#endif
			s.sip4 = skops->local_ip4;
			s.dip4 = skops->remote_ip4;
			s.family = ENDPOINT_KEY_IPV4;
			s.sport = local;
			s.dport = remote;

#if DBG
			printk("ipc key1: sip4 %u dip4 %u family %u\n", s.sip4, s.dip4, s.family);
			printk("ipc key2: dport %u sport %u\n", s.dport, s.sport);
			printk("add sockops(%i) key %i -> %i\n", err, s.sport, s.dport);
#endif

//			err = sock_hash_update(skops, &SOCK_OPS_MAP, &s, BPF_ANY);
		}
#endif
		break;
	default:
		break;
	}

	return 0;
}

BPF_LICENSE("GPL");
int _version __section("version") = 1;
