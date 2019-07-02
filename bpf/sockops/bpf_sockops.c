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
#define SOCKMAP 1

#include <node_config.h>
#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include "../lib/utils.h"
#include "../lib/common.h"
#include "../lib/maps.h"
#include "../lib/lb.h"
#include "../lib/eps.h"
#include "../lib/events.h"
#include "../lib/policy.h"

#include "bpf_sockops.h"

static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
	struct lb4_key_v2 lb4_key = {};
	__u32 dip4, dport, dstID = 0;
	struct endpoint_info *exists;
	struct lb4_service_v2 *svc;
	struct sock_key key = {};
	int verdict;

	sk_extract4_key(skops, &key);

	/* If endpoint a service use L4/L3 stack for now. These can be
	 * pulled in as needed.
	 */
	sk_lb4_key_v2(&lb4_key, &key);
	svc = __lb4_lookup_service_v2(&lb4_key);
	if (svc)
		return;

	/* Policy lookup required to learn proxy port */
	if (1) {
		struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(key.dip4);
		if (info != NULL && info->sec_label)
			dstID = info->sec_label;
		else
			dstID = WORLD_ID;
	}

	verdict = policy_sk_egress(dstID, key.sip4, key.dport);
	if (redirect_to_proxy(verdict)) {
		__be32 host_ip = IPV4_GATEWAY;

		key.dip4 = key.sip4;
		key.dport = key.sport;
		key.sip4 = host_ip;
		key.sport = verdict;

		sock_hash_update(skops, &SOCK_OPS_MAP, &key, BPF_NOEXIST);
		return;
	}

	/* Lookup IPv4 address, this will return a match if:
	 * - The destination IP address belongs to the local endpoint manage
	 *   by Cilium.
	 * - The destination IP address is an IP address associated with the
	 *   host itself.
	 * Then because these are local IPs that have passed LB/Policy/NAT
	 * blocks redirect directly to socket.
	 */
	exists = __lookup_ip4_endpoint(key.dip4);
	if (!exists)
		return;

	dip4 = key.dip4;
	dport = key.dport;
	key.dip4 = key.sip4;
	key.dport = key.sport;
	key.sip4 = dip4;
	key.sport = dport;

	sock_hash_update(skops, &SOCK_OPS_MAP, &key, BPF_NOEXIST);
}

static inline void bpf_sock_ops_ipv6(struct bpf_sock_ops *skops)
{
	if (skops->remote_ip4)
		bpf_sock_ops_ipv4(skops);
}

__section("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	__u32 family, op;

	family = skops->family;
	op = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (family == AF_INET6)
			bpf_sock_ops_ipv6(skops);
		else if (family == AF_INET)
			bpf_sock_ops_ipv4(skops);
		break;
	default:
		break;
	}

	return 0;
}

BPF_LICENSE("GPL");
int _version __section("version") = 1;
