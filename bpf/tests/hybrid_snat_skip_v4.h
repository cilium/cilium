/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_SCTP
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENCAP_IFINDEX 1
#define TUNNEL_MODE
#include <bpf/config/global.h>
#include <bpf/config/node.h>

#define ENABLE_BPF_MASQUERADE 1
#define ENABLE_MASQUERADE_IPV4 1
#define IS_BPF_HOST 1

#define IPV4_MASQUERADE v4_node_one
#define IPV4_SRC v4_pod_one
#define IPV4_DST v4_node_two

#include "lib/bpf_host.h"

ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, { .be32 = IPV4_MASQUERADE })
ASSIGN_CONFIG(bool, enable_remote_node_masquerade, ENABLE_REMOTE_NODE_MASQUERADE)
ASSIGN_CONFIG(bool, hybrid_routing_enabled, true)
ASSIGN_CONFIG(bool, enable_extended_ip_protocols, false)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/subnet.h"

static __always_inline int
run_hybrid_snat_v4_test(struct __ctx_buff *ctx, __u32 src_subnet_id,
			__u32 dst_subnet_id)
{
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};
	struct ipv4_ct_tuple tuple = {
		.daddr = IPV4_DST,
		.saddr = IPV4_SRC,
		.nexthdr = 253,
		.sport = bpf_htons(12345),
		.dport = bpf_htons(443),
		.flags = NAT_DIR_EGRESS,
	};
	struct iphdr ip4 = { .protocol = 253 };

	if (src_subnet_id)
		subnet_v4_add_entry(IPV4_SRC, src_subnet_id);
	if (dst_subnet_id)
		subnet_v4_add_entry(IPV4_DST, dst_subnet_id);
	ipcache_v4_add_entry(IPV4_DST, 0, REMOTE_NODE_ID, 0, 0);
	endpoint_v4_add_entry(IPV4_SRC, 0, 0, 0, 0, 0, NULL, NULL);

	return __snat_v4_needs_masquerade(ctx, &tuple, &ip4, 0, 0, &target);
}
