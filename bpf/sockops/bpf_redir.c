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
int bpf_redir_proxy(struct sk_msg_md *msg)
{
	struct remote_endpoint_info *info;
	__u64 flags = BPF_F_INGRESS;
	struct sock_key key = {.sip4=0};
	__u32 srcID, dstID = 0;
	int verdict, err;

	sk_msg_extract4_key(msg, &key);

	if (key.dport == SFD_PORT) {
		void *data, *data_end;
		struct sock_key *pkey;
		int err;

		err = msg_push_data(msg, 0, sizeof(struct sock_key), 0);
		if (err) {
			bpf_printk("data dropped (push): %i\n", err);
			return SK_DROP;
		}

		data = (void *)(long)msg->data;
		data_end = (void *)(long)msg->data_end;
		if (data + sizeof(struct sock_key) > data_end) {
			bpf_printk("data dropped length error\n");
			return SK_DROP;
		}

		pkey = (struct sock_key *)&msg->data[0];
		memset(pkey, 0, sizeof(*pkey));
		pkey->dip4 = key.dip4;
		pkey->dport = key.dport;
		pkey->sip4 = key.sip4;
		pkey->sport = key.sport;
		pkey->family = key.family;
		pkey->size = msg->size;

		bpf_printk("redir key: %d %d %d\n", key.sport, key.dport, key.family);
		bpf_printk("redir key: %d %d\n", key.sip4, key.dip4);
		bpf_printk("redir pad: %d %d\n", key.pad7, key.pad8);
		bpf_printk("redir length: %d\n", msg->size);
		err = msg_redirect_map(msg, &SOCK_OPS_KTLS_DOWN, 0, flags);
		bpf_printk("redir data pushed: %i\n", err);
		return SK_PASS;
	}

	/* Currently, pulling proxy port and dstIP out of policy and endpoint
	 * tables. This can be simplified by caching this information with the
	 * socket to avoid extra overhead. This would require the agent though
	 * to flush the sock ops map on policy changes.
	 */
	info = lookup_ip4_remote_endpoint(key.dip4);
	if (info != NULL && info->sec_label)
		dstID = info->sec_label;
	else
		dstID = WORLD_ID;

	info = lookup_ip4_remote_endpoint(key.sip4);
	if (info != NULL && info->sec_label)
		srcID = info->sec_label;
	else
		srcID = WORLD_ID;

	verdict = policy_sk_egress(dstID, key.sip4, key.dport);
	if (redirect_to_proxy(verdict)) {
		struct proxy4_tbl_value value = {
			.orig_daddr = key.dip4,
			.orig_dport = key.dport,
			.identity = srcID,
		};
		struct proxy4_tbl_key proxy_key = {
			.saddr = key.sip4,
			.sport = key.sport,
			.dport = verdict & 0xffff,
			.nexthdr = IPPROTO_TCP,
		};
		__be32 host_ip = IPV4_GATEWAY;

		value.lifetime = bpf_ktime_get_sec() + PROXY_DEFAULT_LIFETIME;

		if (map_update_elem(&cilium_proxy4, &proxy_key, &value, 0) < 0)
			return SK_PASS;
		if (verdict >> 16) {
			void *data, *data_end;
			struct sock_key *pkey;
			int err;

			err = msg_push_data(msg, 0, sizeof(key), 0);
			if (err)
				return SK_DROP;

			data = (void *)(long)msg->data;
			data_end = (void *)(long)msg->data_end;
			if (data + sizeof(struct sock_key) < data_end)
				return SK_DROP;

			pkey = (struct sock_key *)&msg->data[0];
			pkey->dip4 = key.sip4;
			pkey->dport = key.sport;
			pkey->sip4 = host_ip;
			pkey->sport = verdict & 0xffff;

			err = msg_redirect_map(msg, &SOCK_OPS_KTLS_DOWN, 0, flags);
		} else { 
			key.dport = verdict & 0xffff;
			key.dip4 = host_ip;
			err = msg_redirect_hash(msg, &SOCK_OPS_MAP, &key, flags);
		}
	} else if (!verdict) {
		msg_redirect_hash(msg, &SOCK_OPS_MAP, &key, flags);
	}

	return SK_PASS;
}

BPF_LICENSE("GPL");
int _version __section("version") = 1;
