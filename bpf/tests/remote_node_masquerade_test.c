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

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/nat.h>
#include <lib/time.h>

#include "bpf_nat_tuples.h"


static struct remote_endpoint_info *remote_endpoint_mock = NULL;
#undef lookup_ip4_remote_endpoint
#define lookup_ip4_remote_endpoint(addr, cluster_id) \
  (remote_endpoint_mock && remote_endpoint_mock->sec_identity == REMOTE_NODE_ID ? remote_endpoint_mock : NULL)

CHECK("tc", "nat4_remote_node_masquerade")
int test_nat4_remote_node_masquerade(__maybe_unused struct __ctx_buff *ctx)
{
    test_init();
    
	#ifndef IPV4_MASQUERADE
	// For testing purposes only - in production this would come from the configuration
	#define IPV4_MASQUERADE bpf_htonl(0x0A000001) // 10.0.0.1 as an example masquerade address
	#endif
	
    struct ipv4_ct_tuple tuple = {};
    struct remote_endpoint_info remote_info = {};
    struct iphdr ip4 = {
        .protocol = IPPROTO_TCP,
    };
    fraginfo_t fraginfo = 0;
    int l4_off = 0;
    int ret;

    /* Set up the tuple as if the packet is going to a remote node */
    tuple.daddr = bpf_htonl(0x02020202); /* 2.2.2.2 - remote node */
    tuple.saddr = bpf_htonl(0x01010101); /* 1.1.1.1 - local pod */
    tuple.nexthdr = IPPROTO_TCP;
    tuple.sport = bpf_htons(12345);
    tuple.dport = bpf_htons(443);
    tuple.flags = NAT_DIR_EGRESS;

    /* Setup the remote endpoint as a node */
    remote_info.sec_identity = REMOTE_NODE_ID;

    /* Define target properly */
    struct ipv4_nat_target target = {
        .min_port = NODEPORT_PORT_MIN_NAT,
        .max_port = NODEPORT_PORT_MAX_NAT,
        .addr = 0
    };

    /* Use a simplified mock approach instead of map operations */
    remote_endpoint_mock = &remote_info;
    
    /* Test 1: Without ENABLE_REMOTE_NODE_MASQUERADE in native routing mode */
    #undef ENABLE_REMOTE_NODE_MASQUERADE
    #undef TUNNEL_MODE

    ret = snat_v4_needs_masquerade(ctx, &tuple, &ip4, fraginfo, l4_off, &target);

    /* Without the flag enabled, traffic to remote nodes should not be masqueraded in native routing mode */
    assert(ret == NAT_PUNT_TO_STACK);
    assert(target.addr == 0); /* No masquerade address should be set */

    /* Test 2: With ENABLE_REMOTE_NODE_MASQUERADE in native routing mode */
    #define ENABLE_REMOTE_NODE_MASQUERADE 1

    /* Reset target before the second test */
    target.addr = 0;

    ret = snat_v4_needs_masquerade(ctx, &tuple, &ip4, fraginfo, l4_off, &target);

    /* When flag is enabled, packet to remote node should be masqueraded */
    assert(ret == NAT_NEEDED);
    assert(target.addr == IPV4_MASQUERADE);

    /* Test 3: With tunnel mode enabled, without ENABLE_REMOTE_NODE_MASQUERADE */
    #undef ENABLE_REMOTE_NODE_MASQUERADE
    #define TUNNEL_MODE 1

    /* Reset target before the third test */
    target.addr = 0;
    
    /* Set flag_skip_tunnel to false to test regular tunnel mode behavior */
    remote_info.flag_skip_tunnel = 0;
    
    ret = snat_v4_needs_masquerade(ctx, &tuple, &ip4, fraginfo, l4_off, &target);
    
    /* In tunnel mode, traffic to remote nodes should be masqueraded regardless of ENABLE_REMOTE_NODE_MASQUERADE */
    assert(ret == NAT_NEEDED);
    assert(target.addr != 0); /* Masquerade address should be set */
    
    /* Test 4: With tunnel mode enabled but skip_tunnel flag set */
    remote_info.flag_skip_tunnel = 1;
    
    /* Reset target before the fourth test */
    target.addr = 0;
    
    ret = snat_v4_needs_masquerade(ctx, &tuple, &ip4, fraginfo, l4_off, &target);
    
    /* When skip_tunnel is set, traffic should not be masqueraded */
    assert(ret == NAT_PUNT_TO_STACK);
    assert(target.addr == 0); /* No masquerade address should be set */
    
    /* Test 5: With both tunnel mode and ENABLE_REMOTE_NODE_MASQUERADE enabled */
    #define ENABLE_REMOTE_NODE_MASQUERADE 1
    
    /* Reset target and skip_tunnel flag before the fifth test */
    target.addr = 0;
    remote_info.flag_skip_tunnel = 0;
    
    ret = snat_v4_needs_masquerade(ctx, &tuple, &ip4, fraginfo, l4_off, &target);
    
    /* With both flags enabled, traffic should be masqueraded */
    assert(ret == NAT_NEEDED);
    assert(target.addr == IPV4_MASQUERADE);

    /* Clean up */
    remote_endpoint_mock = NULL;

    test_finish();
    return 0;
}

BPF_LICENSE("Dual BSD/GPL");