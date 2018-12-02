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

#define SOCKMAP 1

#include "../lib/utils.h"
#include "../lib/common.h"
#include "../lib/maps.h"
#include "../lib/lb.h"
#include "../lib/eps.h"
#include "../lib/events.h"
#include "../lib/policy.h"

#include "bpf_sockops.h"

#define bpf_printk(fmt, ...)                                   \
({                                                             \
              char ____fmt[] = fmt;                            \
              trace_printk(____fmt, sizeof(____fmt),   \
                               ##__VA_ARGS__);                 \
})

__section("sk_msg")
int bpf_redir_ktls(struct sk_msg_md *msg)
{
	struct sock_key *pkey, key;
	__u64 flags = 0;
	__u32 dip4, dport;
	int err;

	if (msg->data + sizeof(struct sock_key) > msg->data_end) {
		bpf_printk("ktls down: abort no key\n");
		return SK_DROP;
	}

	memset(&key, 0, sizeof(key));

	pkey = &msg->data[0];
	key = *pkey; 
	err = msg_pop_data(msg, 0, sizeof(key), 0); 
	if (err) {
		printk("ktls down: pop data error sk_drop\n");
		return SK_DROP;
	}

	dip4 = key.dip4;
	dport = key.dport;
	key.dip4 = key.sip4;
	key.dport = key.sport;
	key.sip4 = dip4;
	key.sport = dport;
	key.size = 0;

	err = msg_redirect_hash(msg, &SOCK_OPS_MAP, &key, flags);
	bpf_printk("ktls down key: %d %d %d\n", key.sport, key.dport, key.family);
	bpf_printk("ktls down pad: %d %d\n", key.pad7, key.pad8);
	bpf_printk("ktls down key: %d %d\n", key.sip4, key.dip4);
	bpf_printk("ktls down key: pad(%d %d %d)", key.pad1, key.pad2, key.pad3);
	bpf_printk("ktls down key: pad(%d %d %d)", key.pad4, key.pad5, key.pad6);
	bpf_printk("ktls down: redirect flags(%d) %d\n", flags, err);
	return err;
}

BPF_LICENSE("GPL");
int _version __section("version") = 1;
