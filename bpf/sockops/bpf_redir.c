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

__section("sk_msg")
int bpf_redir_proxy(struct sk_msg_md *msg)
{
	struct remote_endpoint_info *info;
	__u64 flags = BPF_F_INGRESS;
	struct sock_key key = {};
	__u32 srcID, dstID = 0;
	int verdict, err;

	sk_msg_extract4_key(msg, &key);

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
			.dport = verdict,
			.nexthdr = IPPROTO_TCP,
		};
		__be32 host_ip = IPV4_GATEWAY;

		value.lifetime = bpf_ktime_get_sec() + PROXY_DEFAULT_LIFETIME;

		key.dport = verdict;
		key.dip4 = host_ip;

		if (map_update_elem(&PROXY4_MAP, &proxy_key, &value, 0) < 0)
			return SK_PASS;
		err = msg_redirect_hash(msg, &SOCK_OPS_MAP, &key, flags);
	} else if (!verdict) {
		msg_redirect_hash(msg, &SOCK_OPS_MAP, &key, flags);
	}

	return SK_PASS;
}

BPF_LICENSE("GPL");
int _version __section("version") = 1;
