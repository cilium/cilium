// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2020 Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include <node_config.h>

#include <linux/if_ether.h>

#define SKIP_CALLS_MAP 1
#define SKIP_POLICY_MAP 1

#define SOCKMAP 1

#include "../lib/common.h"
#include "../lib/maps.h"
#include "../lib/lb.h"
#include "../lib/eps.h"
#include "../lib/events.h"
#include "../lib/policy.h"

#include "bpf_sockops.h"

#ifdef ENABLE_IPV4
static __always_inline void sk_extract4_key(const struct bpf_sock_ops *ops,
					    struct sock_key *key)
{
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = ENDPOINT_KEY_IPV4;
	/* We will get misses on UDP, but the verifier
	 * does not allow access to the socket field until >= 5.3
	 * cf GH issue #13490 to fix
	 */
	key->protocol = IPPROTO_TCP;

	key->sport = (bpf_ntohl(ops->local_port) >> 16);
	/* clang-7.1 or higher seems to think it can do a 16-bit read here
	 * which unfortunately most kernels (as of October 2019) do not
	 * support, which leads to verifier failures. Insert a READ_ONCE
	 * to make sure that a 32-bit read followed by shift is generated.
	 */
	key->dport = READ_ONCE(ops->remote_port) >> 16;
}

static __always_inline void sk_lb4_key(struct lb4_key *lb4,
					  const struct sock_key *key)
{
	/* SK MSG is always egress, so use daddr */
	lb4->address = key->dip4;
	lb4->dport = key->dport;
	lb4->proto = key->protocol;
}

static __always_inline bool redirect_to_proxy(int verdict)
{
	return verdict > 0;
}

static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
	struct lb4_key lb4_key = {};
	__u32 dip4, dport, dstID = 0;
	struct endpoint_info *exists;
	struct lb4_service *svc;
	struct sock_key key = {};
	int verdict;

	sk_extract4_key(skops, &key);

	/* If endpoint a service use L4/L3 stack for now. These can be
	 * pulled in as needed.
	 */
	sk_lb4_key(&lb4_key, &key);
	svc = lb4_lookup_service(&lb4_key, true);
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
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
static inline void bpf_sock_ops_ipv6(struct bpf_sock_ops *skops)
{
	if (skops->remote_ip4)
		bpf_sock_ops_ipv4(skops);
}
#endif /* ENABLE_IPV6 */

__section("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	__u32 family, op;

	family = skops->family;
	op = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
#ifdef ENABLE_IPV6
		if (family == AF_INET6)
			bpf_sock_ops_ipv6(skops);
#endif
#ifdef ENABLE_IPV4
		if (family == AF_INET)
			bpf_sock_ops_ipv4(skops);
#endif
		break;
	default:
		break;
	}

	return 0;
}

BPF_LICENSE("GPL");
int _version __section("version") = 1;
