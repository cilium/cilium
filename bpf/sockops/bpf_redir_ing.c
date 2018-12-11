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
	
__section("sk_skb2")
int bpf_prog2(struct __sk_buff *skb)
{
	struct sock_key *pkey, key = {};
	struct endpoint_info *exists;
	__u64 flags = BPF_F_INGRESS;
	void *data, *data_end;
	int err = 0;

	sk_skb_extract4_key(skb, &key);


	exists = __lookup_ip4_endpoint(key.sip4);
	if (!exists) {
		bpf_printk("ing drop: !exists key sipe %u dip4 %u\n", key.sip4, key.dip4);
		return SK_PASS;
	}

	if (key.dport != SFD_PORT && key.sport != SFD_PORT ) {
		return SK_PASS;
	}

	err = skb_change_head(skb, sizeof(struct sock_key), 0);
	if (err) {
		bpf_printk("sk_skb: data dropped (push): %i\n", err);
		return SK_DROP;
	}

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	if (data + sizeof(struct sock_key) > data_end) {
		bpf_printk("sk_skb: data dropped length error\n");
		return SK_DROP;
	}

	pkey = (struct sock_key *)data;
	pkey->dip4 = key.sip4;
	pkey->sip4 = key.dip4;
	pkey->dport = key.sport;
	pkey->sport = key.dport;
	pkey->family = key.family;
	pkey->size = skb->len;

	bpf_printk("sk_skb key: %u %u %d\n", key.sport, key.dport, key.family);
	bpf_printk("sk_skb key: %d %d\n", key.sip4, key.dip4);
	bpf_printk("sk_skb pad: %d %d %d\n", key.pad1, key.pad2, key.pad3);
	bpf_printk("sk_skb pad: %d %d %d\n", key.pad4, key.pad5, key.pad6);
	bpf_printk("sk_skb pad: %d %d\n", key.pad7, key.pad8);
	bpf_printk("sk_skb length: %d\n", pkey->size);
	err =  sk_redirect_map(skb, &SOCK_OPS_KTLS_UP, 0, flags);
	bpf_printk("sk_skb data pushed: %i\n", err);
	return SK_PASS;
}

BPF_LICENSE("GPL");
int _version __section("version") = 1;
