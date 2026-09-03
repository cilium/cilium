/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENCAP_IFINDEX 1
#define TUNNEL_MODE
#include <bpf/config/global.h>
#include <bpf/config/node.h>

#define ENABLE_BPF_MASQUERADE 1
#define ENABLE_MASQUERADE_IPV6 1
#define IS_BPF_HOST 1

#define IPV6_MASQUERADE_ADDR { .addr = v6_node_one_addr }
#define IPV6_SRC_ADDR { .addr = v6_pod_one_addr }
#define IPV6_DST_ADDR { .addr = v6_node_two_addr }

#include "lib/bpf_host.h"

ASSIGN_CONFIG(union v6addr, nat_ipv6_masquerade, IPV6_MASQUERADE_ADDR)
ASSIGN_CONFIG(bool, enable_remote_node_masquerade, ENABLE_REMOTE_NODE_MASQUERADE)
ASSIGN_CONFIG(bool, hybrid_routing_enabled, true)
ASSIGN_CONFIG(bool, enable_extended_ip_protocols, false)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/subnet.h"

static __always_inline int
run_hybrid_snat_v6_test(struct __ctx_buff *ctx, __u32 src_subnet_id,
			__u32 dst_subnet_id)
{
	union v6addr src = IPV6_SRC_ADDR;
	union v6addr dst = IPV6_DST_ADDR;
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};
	struct ipv6_ct_tuple tuple __align_stack_8 = {
		.nexthdr = 253,
		.sport = bpf_htons(12345),
		.dport = bpf_htons(443),
		.flags = NAT_DIR_EGRESS,
	};

	ipv6_addr_copy(&tuple.saddr, &src);
	ipv6_addr_copy(&tuple.daddr, &dst);
	if (src_subnet_id)
		subnet_v6_add_entry(&src, src_subnet_id);
	if (dst_subnet_id)
		subnet_v6_add_entry(&dst, dst_subnet_id);
	ipcache_v6_add_entry(&dst, 0, REMOTE_NODE_ID, 0, 0);
	endpoint_v6_add_entry(&src, 0, 0, 0, 0, NULL, NULL);

	return __snat_v6_needs_masquerade(ctx, &tuple, 0, 0, &target);
}
