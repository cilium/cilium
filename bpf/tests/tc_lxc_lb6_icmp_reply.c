// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Test that verifies ICMPv6 echo replies work for pod-to-ClusterIP traffic */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define SERVICE_NO_BACKEND_RESPONSE
#define ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY

/* Test network and addresses */
#define POD_IP              v6_pod_one    /* Source pod IP */
#define CLUSTERIP_IP        v6_node_one   /* ClusterIP service IP */
#define LOADBALANCER_IP     v6_node_two   /* LoadBalancer service IP */
#define SERVICE_PORT        tcp_svc_one   /* Port with actual service */
#define BACKEND_IP          v6_pod_two    /* Backend pod IP */
#define BACKEND_PORT        __bpf_htons(8080)
#define ICMP_ID             __bpf_htons(0x5678)

/* MAC addresses for tests */
static volatile const __u8 *pod_mac = mac_one;
static volatile const __u8 *node_mac = mac_two;

#include <bpf_lxc.c>

/* Override LXC_ID after including bpf_lxc.c to avoid conflicts */
#undef LXC_ID
#define LXC_ID 107

/* Include test helpers */
#include "lib/ipcache.h"
#include "lib/lb.h"

/* Program array for tail calls */
#define FROM_CONTAINER 0
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(max_entries, 1);
    __array(values, int());
} entry_call_map __section(".maps") = {
    .values = {
        [FROM_CONTAINER] = &cil_from_container,
    },
};

/* Test 1: ClusterIP should reply to ICMPv6 echo requests from pods */
PKTGEN("tc", "test_lxc_clusterip_icmpv6_echo_request")
int lxc_clusterip_icmpv6_echo_request_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct icmp6hdr *icmp6hdr;
    struct ethhdr *l2;
    struct ipv6hdr *l3;
    void *data;

    /* Init packet builder */
    pktgen__init(&builder, ctx);

    /* Push ethernet header */
    l2 = pktgen__push_ethhdr(&builder);
    if (!l2)
        return TEST_ERROR;

    ethhdr__set_macs(l2, (__u8 *)pod_mac, (__u8 *)node_mac);

    /* Push IPv6 header */
    l3 = pktgen__push_default_ipv6hdr(&builder);
    if (!l3)
        return TEST_ERROR;

    memcpy(&l3->saddr, (__u8 *)&POD_IP, 16);
    memcpy(&l3->daddr, (__u8 *)&CLUSTERIP_IP, 16);

    /* Push ICMPv6 header */
    icmp6hdr = pktgen__push_icmp6hdr(&builder);
    if (!icmp6hdr)
        return TEST_ERROR;

    icmp6hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
    icmp6hdr->icmp6_code = 0;
    icmp6hdr->icmp6_identifier = ICMP_ID;
    icmp6hdr->icmp6_sequence = __bpf_htons(1);

    data = pktgen__push_data(&builder, default_data, sizeof(default_data));
    if (!data)
        return TEST_ERROR;

    /* Calc lengths, set protocol fields and calc checksums */
    pktgen__finish(&builder);

    return 0;
}

SETUP("tc", "test_lxc_clusterip_icmpv6_echo_request")
int lxc_clusterip_icmpv6_echo_request_setup(struct __ctx_buff *ctx)
{
    /* Create a ClusterIP service which will automatically get a wildcard entry
     * for ICMPv6 echo reply handling due to ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY
     */
    lb_v6_add_service_with_flags((union v6addr *)&CLUSTERIP_IP, SERVICE_PORT, IPPROTO_TCP, 1, 1, 0, 0);

    /* Add a backend for the service */
    lb_v6_add_backend((union v6addr *)&CLUSTERIP_IP, SERVICE_PORT, 1, 1, (union v6addr *)&BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

    /* Configure IPCache entries for source pod and service */
    ipcache_v6_add_entry((union v6addr *)&POD_IP, 0, 112233, 0, 0);        /* Source pod */
    ipcache_v6_add_entry((union v6addr *)&CLUSTERIP_IP, 0, WORLD_IPV6_ID, 0, 0);  /* Service IP */
    ipcache_v6_add_entry((union v6addr *)&BACKEND_IP, 0, 112244, 0, 0);    /* Backend pod */

    /* Jump into the LXC entrypoint (pod egress) */
    tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
    /* Fail if we didn't jump */
    return TEST_ERROR;
}

CHECK("tc", "test_lxc_clusterip_icmpv6_echo_request")
int lxc_clusterip_icmpv6_echo_request_check(const struct __ctx_buff *ctx)
{
    void *data, *data_end;
    __u32 *status_code;
    struct ethhdr *l2;
    struct ipv6hdr *l3;
    struct icmp6hdr *icmp6hdr;

    test_init();

    data = (void *)(long)ctx_data(ctx);
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");

    status_code = data;
    test_log("Status code: %d, expected: %d (CTX_ACT_REDIRECT)", *status_code, CTX_ACT_REDIRECT);
    assert(*status_code == CTX_ACT_REDIRECT);

    l2 = data + sizeof(__u32);
    if ((void *)l2 + sizeof(struct ethhdr) > data_end)
        test_fatal("l2 out of bounds");

    assert(l2->h_proto == bpf_htons(ETH_P_IPV6));

    l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
    if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
        test_fatal("l3 out of bounds");

    assert(l3->nexthdr == IPPROTO_ICMPV6);

    icmp6hdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    if ((void *)icmp6hdr + sizeof(struct icmp6hdr) > data_end)
        test_fatal("icmp6hdr out of bounds");

    /* Verify this is an ICMPv6 echo reply */
    test_log("ICMPv6 type: %d, expected: %d (ICMPV6_ECHO_REPLY)", icmp6hdr->icmp6_type, ICMPV6_ECHO_REPLY);
    assert(icmp6hdr->icmp6_type == ICMPV6_ECHO_REPLY);

    /* Verify the ICMP ID is preserved */
    assert(icmp6hdr->icmp6_identifier == ICMP_ID);

    /* Verify IPv6 addresses are swapped */
    test_log("Checking IPv6 address swapping: src should be CLUSTERIP_IP, dst should be POD_IP");
    assert(memcmp(&l3->saddr, (__u8 *)&CLUSTERIP_IP, 16) == 0);
    assert(memcmp(&l3->daddr, (__u8 *)&POD_IP, 16) == 0);
    test_log("IPv6 address swapping verified successfully");

    /* Verify MAC addresses are swapped */
    test_log("Checking MAC address swapping: src should be node_mac, dst should be pod_mac");
    assert(memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) == 0);
    assert(memcmp(l2->h_dest, (__u8 *)pod_mac, ETH_ALEN) == 0);
    test_log("MAC address swapping verified successfully");

    test_finish();
}

/* Test 2: LoadBalancer should reply to ICMPv6 echo requests from pods */
PKTGEN("tc", "test_lxc_loadbalancer_icmpv6_echo_request")
int lxc_loadbalancer_icmpv6_echo_request_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct icmp6hdr *icmp6hdr;
    struct ethhdr *l2;
    struct ipv6hdr *l3;
    void *data;

    /* Init packet builder */
    pktgen__init(&builder, ctx);

    /* Push ethernet header */
    l2 = pktgen__push_ethhdr(&builder);
    if (!l2)
        return TEST_ERROR;

    ethhdr__set_macs(l2, (__u8 *)pod_mac, (__u8 *)node_mac);

    /* Push IPv6 header */
    l3 = pktgen__push_default_ipv6hdr(&builder);
    if (!l3)
        return TEST_ERROR;

    memcpy(&l3->saddr, (__u8 *)&POD_IP, 16);
    memcpy(&l3->daddr, (__u8 *)&LOADBALANCER_IP, 16);

    /* Push ICMPv6 header */
    icmp6hdr = pktgen__push_icmp6hdr(&builder);
    if (!icmp6hdr)
        return TEST_ERROR;

    icmp6hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
    icmp6hdr->icmp6_code = 0;
    icmp6hdr->icmp6_identifier = ICMP_ID;
    icmp6hdr->icmp6_sequence = __bpf_htons(2);

    data = pktgen__push_data(&builder, default_data, sizeof(default_data));
    if (!data)
        return TEST_ERROR;

    /* Calc lengths, set protocol fields and calc checksums */
    pktgen__finish(&builder);

    return 0;
}

SETUP("tc", "test_lxc_loadbalancer_icmpv6_echo_request")
int lxc_loadbalancer_icmpv6_echo_request_setup(struct __ctx_buff *ctx)
{
    /* Create a LoadBalancer service which will automatically get a wildcard entry
     * for ICMPv6 echo reply handling due to ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY
     */
    lb_v6_add_service_with_flags((union v6addr *)&LOADBALANCER_IP, SERVICE_PORT, IPPROTO_TCP, 1, 2, SVC_FLAG_ROUTABLE, SVC_FLAG_LOADBALANCER);

    /* Add a backend for the service */
    lb_v6_add_backend((union v6addr *)&LOADBALANCER_IP, SERVICE_PORT, 1, 2, (union v6addr *)&BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

    /* Configure IPCache entries for source pod and service */
    ipcache_v6_add_entry((union v6addr *)&POD_IP, 0, 112233, 0, 0);        /* Source pod */
    ipcache_v6_add_entry((union v6addr *)&LOADBALANCER_IP, 0, WORLD_IPV6_ID, 0, 0);  /* Service IP */
    ipcache_v6_add_entry((union v6addr *)&BACKEND_IP, 0, 112244, 0, 0);    /* Backend pod */

    /* Jump into the LXC entrypoint (pod egress) */
    tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
    /* Fail if we didn't jump */
    return TEST_ERROR;
}

CHECK("tc", "test_lxc_loadbalancer_icmpv6_echo_request")
int lxc_loadbalancer_icmpv6_echo_request_check(const struct __ctx_buff *ctx)
{
    void *data, *data_end;
    __u32 *status_code;
    struct ethhdr *l2;
    struct ipv6hdr *l3;
    struct icmp6hdr *icmp6hdr;

    test_init();

    data = (void *)(long)ctx_data(ctx);
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");

    status_code = data;
    test_log("Status code: %d, expected: %d (CTX_ACT_REDIRECT)", *status_code, CTX_ACT_REDIRECT);
    assert(*status_code == CTX_ACT_REDIRECT);

    l2 = data + sizeof(__u32);
    if ((void *)l2 + sizeof(struct ethhdr) > data_end)
        test_fatal("l2 out of bounds");

    assert(l2->h_proto == bpf_htons(ETH_P_IPV6));

    l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
    if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
        test_fatal("l3 out of bounds");

    assert(l3->nexthdr == IPPROTO_ICMPV6);

    icmp6hdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    if ((void *)icmp6hdr + sizeof(struct icmp6hdr) > data_end)
        test_fatal("icmp6hdr out of bounds");

    /* Verify this is an ICMPv6 echo reply */
    test_log("ICMPv6 type: %d, expected: %d (ICMPV6_ECHO_REPLY)", icmp6hdr->icmp6_type, ICMPV6_ECHO_REPLY);
    assert(icmp6hdr->icmp6_type == ICMPV6_ECHO_REPLY);

    /* Verify the ICMP ID is preserved */
    assert(icmp6hdr->icmp6_identifier == ICMP_ID);

    /* Verify IPv6 addresses are swapped */
    test_log("Checking IPv6 address swapping: src should be LOADBALANCER_IP, dst should be POD_IP");
    assert(memcmp(&l3->saddr, (__u8 *)&LOADBALANCER_IP, 16) == 0);
    assert(memcmp(&l3->daddr, (__u8 *)&POD_IP, 16) == 0);
    test_log("IPv6 address swapping verified successfully");

    /* Verify MAC addresses are swapped */
    test_log("Checking MAC address swapping: src should be node_mac, dst should be pod_mac");
    assert(memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) == 0);
    assert(memcmp(l2->h_dest, (__u8 *)pod_mac, ETH_ALEN) == 0);
    test_log("MAC address swapping verified successfully");

    test_finish();
}

/* Test 3: Non-echo ICMPv6 packets should NOT be handled by echo reply logic */
PKTGEN("tc", "test_lxc_icmpv6_other")
int lxc_icmpv6_other_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct icmp6hdr *icmp6hdr;
    struct ethhdr *l2;
    struct ipv6hdr *l3;
    void *data;

    /* Init packet builder */
    pktgen__init(&builder, ctx);

    /* Push ethernet header */
    l2 = pktgen__push_ethhdr(&builder);
    if (!l2)
        return TEST_ERROR;

    ethhdr__set_macs(l2, (__u8 *)pod_mac, (__u8 *)node_mac);

    /* Push IPv6 header */
    l3 = pktgen__push_default_ipv6hdr(&builder);
    if (!l3)
        return TEST_ERROR;

    memcpy(&l3->saddr, (__u8 *)&POD_IP, 16);
    memcpy(&l3->daddr, (__u8 *)&CLUSTERIP_IP, 16);

    /* Push ICMPv6 header with destination unreachable type */
    icmp6hdr = pktgen__push_icmp6hdr(&builder);
    if (!icmp6hdr)
        return TEST_ERROR;

    icmp6hdr->icmp6_type = ICMPV6_DEST_UNREACH;
    icmp6hdr->icmp6_code = ICMPV6_PORT_UNREACH;
    icmp6hdr->icmp6_dataun.un_data32[0] = 0;

    data = pktgen__push_data(&builder, default_data, sizeof(default_data));
    if (!data)
        return TEST_ERROR;

    /* Calc lengths, set protocol fields and calc checksums */
    pktgen__finish(&builder);

    return 0;
}

SETUP("tc", "test_lxc_icmpv6_other")
int lxc_icmpv6_other_setup(struct __ctx_buff *ctx)
{
    /* Create a ClusterIP service for the non-echo ICMPv6 test */
    lb_v6_add_service_with_flags((union v6addr *)&CLUSTERIP_IP, SERVICE_PORT, IPPROTO_TCP, 1, 1, 0, 0);

    /* Add a backend for the service */
    lb_v6_add_backend((union v6addr *)&CLUSTERIP_IP, SERVICE_PORT, 1, 1, (union v6addr *)&BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

    /* Configure IPCache entries */
    ipcache_v6_add_entry((union v6addr *)&POD_IP, 0, 112233, 0, 0);        /* Source pod */
    ipcache_v6_add_entry((union v6addr *)&CLUSTERIP_IP, 0, WORLD_IPV6_ID, 0, 0);  /* Service IP */
    ipcache_v6_add_entry((union v6addr *)&BACKEND_IP, 0, 112244, 0, 0);    /* Backend pod */

    /* Jump into the LXC entrypoint (pod egress) */
    tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
    /* Fail if we didn't jump */
    return TEST_ERROR;
}

CHECK("tc", "test_lxc_icmpv6_other")
int lxc_icmpv6_other_check(const struct __ctx_buff *ctx)
{
    void *data, *data_end;
    __u32 *status_code;
    struct ethhdr *l2;
    struct ipv6hdr *l3;
    struct icmp6hdr *icmp6hdr;

    test_init();

    data = (void *)(long)ctx_data(ctx);
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");

    status_code = data;
    /* Non-echo ICMPv6 should be dropped as they are error packets not suitable for load balancing */
    test_log("Status code: %d, expected: %d (CTX_ACT_DROP)", *status_code, CTX_ACT_DROP);
    assert(*status_code == CTX_ACT_DROP);

    l2 = data + sizeof(__u32);
    if ((void *)l2 + sizeof(struct ethhdr) > data_end)
        test_fatal("l2 out of bounds");

    assert(l2->h_proto == bpf_htons(ETH_P_IPV6));

    l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
    if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
        test_fatal("l3 out of bounds");

    assert(l3->nexthdr == IPPROTO_ICMPV6);

    icmp6hdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    if ((void *)icmp6hdr + sizeof(struct icmp6hdr) > data_end)
        test_fatal("icmp6hdr out of bounds");

    /* Verify this is NOT an ICMPv6 echo reply - other ICMP types should not be handled */
    test_log("ICMPv6 type: %d, should NOT be: %d (ICMPV6_ECHO_REPLY)", icmp6hdr->icmp6_type, ICMPV6_ECHO_REPLY);
    assert(icmp6hdr->icmp6_type != ICMPV6_ECHO_REPLY);

    /* Verify this is the expected ICMPv6 type that was dropped */
    assert(icmp6hdr->icmp6_type == ICMPV6_DEST_UNREACH);

    test_finish();
}

