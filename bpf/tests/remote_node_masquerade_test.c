// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_SCTP
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#include <bpf/config/node.h>

#define DEBUG

/* Flags for this test case: Remote Node Masquerade ENABLED */
/* Note: Remote node masquerade is configured via ASSIGN_CONFIG below */
#define ENABLE_BPF_MASQUERADE 1
#define ENABLE_MASQUERADE_IPV4 1
#define IS_BPF_HOST 1
/* For this test, we assume non-tunnel mode to hit the specific path */
/* #undef TUNNEL_MODE */

#include <lib/eps.h>
/* Mock for lookup_ip4_remote_endpoint */
static struct remote_endpoint_info *mocked_remote_endpoint;
#undef lookup_ip4_remote_endpoint
#define lookup_ip4_remote_endpoint(addr, cluster_id) \
    (mocked_remote_endpoint)
/* Mock for __lookup_ip4_endpoint to ensure source is not a local endpoint */
#undef __lookup_ip4_endpoint
#define __lookup_ip4_endpoint(addr) \
    (NULL)

#include <lib/dbg.h>
#include <lib/time.h>
#include "bpf_nat_tuples.h"
#define IPV4_MASQUERADE bpf_htonl(0x0A000001) /* 10.0.0.1 */

/* Include conntrack headers for extend protocols declaration */
#include <lib/conntrack.h>

/* Include necessary headers to get configuration declarations */
#include <lib/nat.h>

/* Configure the test with proper values for enabled remote node masquerade */
ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, { .be32 = IPV4_MASQUERADE })
ASSIGN_CONFIG(bool, enable_remote_node_masquerade, true)
ASSIGN_CONFIG(__u32, trace_payload_len, 128UL)
ASSIGN_CONFIG(bool, enable_extended_ip_protocols, false)

CHECK("tc", "nat4_remote_node_masquerade_enabled_test")
int test_nat4_remote_node_masquerade_enabled(__maybe_unused struct __ctx_buff *ctx)
{
    struct ipv4_ct_tuple tuple = {};
    struct remote_endpoint_info remote_info = {};
    struct iphdr ip4 = {
    .protocol = IPPROTO_TCP,
    };
    fraginfo_t fraginfo = 0;
    int l4_off = 0;
    int ret;

    test_init();

    /* Set up the tuple as if the packet is going to a remote node */
    tuple.daddr = bpf_htonl(0x02020202); /* 2.2.2.2 - remote node */
    tuple.saddr = bpf_htonl(0xDEADBEEF); /* Unlikely to be a local endpoint */
    tuple.nexthdr = IPPROTO_TCP;
    tuple.sport = bpf_htons(12345);
    tuple.dport = bpf_htons(443);
    tuple.flags = NAT_DIR_EGRESS;

    /* Setup NAT target structure */
    struct ipv4_nat_target target = {
    .min_port            = NODEPORT_PORT_MIN_NAT, /* Standard min port */
    .max_port            = NODEPORT_PORT_MAX_NAT, /* Standard max port */
    .addr                = 0,
    .from_local_endpoint = false,
    .egress_gateway      = false,
    .cluster_id          = 0,
    .needs_ct            = false,
    .ifindex             = 0,
    };

    /* Setup remote endpoint mock data */
    remote_info.sec_identity = REMOTE_NODE_ID; /* Mark as remote node */

    /* Point the global mock to our data */
    mocked_remote_endpoint = &remote_info;

    /*
     * Test: With enable_remote_node_masquerade configured as true via ASSIGN_CONFIG.
     * Expect NAT_NEEDED and target.addr to be set.
     */
    ret = snat_v4_needs_masquerade(ctx, &tuple, &ip4, fraginfo, l4_off, &target);
    assert(ret == NAT_NEEDED);
    assert(target.addr == IPV4_MASQUERADE); /* Masquerade address set */

    /* Clean up */
    mocked_remote_endpoint = NULL;

    test_finish();
    return 0;
}

BPF_LICENSE("Dual BSD/GPL");
