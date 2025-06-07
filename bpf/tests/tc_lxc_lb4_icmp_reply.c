// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Test that verifies ICMP echo replies work for pod-to-ClusterIP traffic */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define SERVICE_NO_BACKEND_RESPONSE
#define ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY

/* Test network and addresses */
#define POD_IP              v4_pod_one    /* Source pod IP */
#define CLUSTERIP_IP        v4_svc_two    /* ClusterIP service IP */
#define LOADBALANCER_IP     v4_svc_three  /* LoadBalancer service IP */
#define SERVICE_PORT        tcp_svc_one   /* Port with actual service */
#define BACKEND_IP          v4_pod_two    /* Backend pod IP */
#define BACKEND_PORT        __bpf_htons(8080)
#define ICMP_ID             __bpf_htons(0x1234)

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

/* Test 1: ClusterIP should reply to ICMP echo requests from pods */
PKTGEN("tc", "test_lxc_clusterip_icmp_echo_request")
int lxc_clusterip_icmp_echo_request_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct icmphdr *icmphdr;
    struct ethhdr *l2;
    struct iphdr *l3;
    void *data;

    /* Init packet builder */
    pktgen__init(&builder, ctx);

    /* Push ethernet header */
    l2 = pktgen__push_ethhdr(&builder);
    if (!l2)
        return TEST_ERROR;

    ethhdr__set_macs(l2, (__u8 *)pod_mac, (__u8 *)node_mac);

    /* Push IPv4 header */
    l3 = pktgen__push_default_iphdr(&builder);
    if (!l3)
        return TEST_ERROR;

    l3->saddr = POD_IP;
    l3->daddr = CLUSTERIP_IP;

    /* Push ICMP header */
    icmphdr = pktgen__push_icmphdr(&builder);
    if (!icmphdr)
        return TEST_ERROR;

    icmphdr->type = ICMP_ECHO;
    icmphdr->code = 0;
    icmphdr->un.echo.id = ICMP_ID;
    icmphdr->un.echo.sequence = __bpf_htons(1);

    data = pktgen__push_data(&builder, default_data, sizeof(default_data));
    if (!data)
        return TEST_ERROR;

    /* Calc lengths, set protocol fields and calc checksums */
    pktgen__finish(&builder);

    return 0;
}

SETUP("tc", "test_lxc_clusterip_icmp_echo_request")
int lxc_clusterip_icmp_echo_request_setup(struct __ctx_buff *ctx)
{
    /* Create a ClusterIP service which will automatically get a wildcard entry
     * for ICMP echo reply handling due to ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY
     */
    lb_v4_add_service_with_flags(CLUSTERIP_IP, SERVICE_PORT, IPPROTO_TCP, 1, 1, 0, 0);

    /* Add a backend for the service */
    lb_v4_add_backend(CLUSTERIP_IP, SERVICE_PORT, 1, 1, BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

    /* Configure IPCache entries for source pod and service */
    ipcache_v4_add_entry(POD_IP, 0, 112233, 0, 0);        /* Source pod */
    ipcache_v4_add_entry(CLUSTERIP_IP, 0, WORLD_IPV4_ID, 0, 0);  /* Service IP */
    ipcache_v4_add_entry(BACKEND_IP, 0, 112244, 0, 0);    /* Backend pod */

    /* Jump into the LXC entrypoint (pod egress) */
    tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
    /* Fail if we didn't jump */
    return TEST_ERROR;
}

CHECK("tc", "test_lxc_clusterip_icmp_echo_request")
int lxc_clusterip_icmp_echo_request_check(const struct __ctx_buff *ctx)
{
    void *data, *data_end;
    __u32 *status_code;
    struct ethhdr *l2;
    struct iphdr *l3;
    struct icmphdr *icmphdr;

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

    assert(l2->h_proto == bpf_htons(ETH_P_IP));

    l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
    if ((void *)l3 + sizeof(struct iphdr) > data_end)
        test_fatal("l3 out of bounds");

    assert(l3->protocol == IPPROTO_ICMP);

    icmphdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)icmphdr + sizeof(struct icmphdr) > data_end)
        test_fatal("icmphdr out of bounds");

    /* Verify this is an ICMP echo reply */
    test_log("ICMP type: %d, expected: %d (ICMP_ECHOREPLY)", icmphdr->type, ICMP_ECHOREPLY);
    assert(icmphdr->type == ICMP_ECHOREPLY);

    /* Verify the ICMP ID is preserved */
    assert(icmphdr->un.echo.id == ICMP_ID);

    /* Verify IP addresses are swapped */
    test_log("Reply src IP: 0x%x, expected: 0x%x (CLUSTERIP_IP)", bpf_ntohl(l3->saddr), bpf_ntohl(CLUSTERIP_IP));
    test_log("Reply dst IP: 0x%x, expected: 0x%x (POD_IP)", bpf_ntohl(l3->daddr), bpf_ntohl(POD_IP));
    assert(l3->saddr == CLUSTERIP_IP);
    assert(l3->daddr == POD_IP);

    /* Verify MAC addresses are swapped */
    test_log("Checking MAC address swapping: src should be node_mac, dst should be pod_mac");
    assert(memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) == 0);
    assert(memcmp(l2->h_dest, (__u8 *)pod_mac, ETH_ALEN) == 0);
    test_log("MAC address swapping verified successfully");

    test_finish();
}

/* Test 2: LoadBalancer should reply to ICMP echo requests from pods */
PKTGEN("tc", "test_lxc_loadbalancer_icmp_echo_request")
int lxc_loadbalancer_icmp_echo_request_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct icmphdr *icmphdr;
    struct ethhdr *l2;
    struct iphdr *l3;
    void *data;

    /* Init packet builder */
    pktgen__init(&builder, ctx);

    /* Push ethernet header */
    l2 = pktgen__push_ethhdr(&builder);
    if (!l2)
        return TEST_ERROR;

    ethhdr__set_macs(l2, (__u8 *)pod_mac, (__u8 *)node_mac);

    /* Push IPv4 header */
    l3 = pktgen__push_default_iphdr(&builder);
    if (!l3)
        return TEST_ERROR;

    l3->saddr = POD_IP;
    l3->daddr = LOADBALANCER_IP;

    /* Push ICMP header */
    icmphdr = pktgen__push_icmphdr(&builder);
    if (!icmphdr)
        return TEST_ERROR;

    icmphdr->type = ICMP_ECHO;
    icmphdr->code = 0;
    icmphdr->un.echo.id = ICMP_ID;
    icmphdr->un.echo.sequence = __bpf_htons(2);

    data = pktgen__push_data(&builder, default_data, sizeof(default_data));
    if (!data)
        return TEST_ERROR;

    /* Calc lengths, set protocol fields and calc checksums */
    pktgen__finish(&builder);

    return 0;
}

SETUP("tc", "test_lxc_loadbalancer_icmp_echo_request")
int lxc_loadbalancer_icmp_echo_request_setup(struct __ctx_buff *ctx)
{
    /* Create a LoadBalancer service which will automatically get a wildcard entry
     * for ICMP echo reply handling due to ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY
     */
    lb_v4_add_service_with_flags(LOADBALANCER_IP, SERVICE_PORT, IPPROTO_TCP, 1, 2, SVC_FLAG_ROUTABLE, SVC_FLAG_LOADBALANCER);

    /* Add a backend for the service */
    lb_v4_add_backend(LOADBALANCER_IP, SERVICE_PORT, 1, 2, BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

    /* Configure IPCache entries for source pod and service */
    ipcache_v4_add_entry(POD_IP, 0, 112233, 0, 0);        /* Source pod */
    ipcache_v4_add_entry(LOADBALANCER_IP, 0, WORLD_IPV4_ID, 0, 0);  /* Service IP */
    ipcache_v4_add_entry(BACKEND_IP, 0, 112244, 0, 0);    /* Backend pod */

    /* Jump into the LXC entrypoint (pod egress) */
    tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
    /* Fail if we didn't jump */
    return TEST_ERROR;
}

CHECK("tc", "test_lxc_loadbalancer_icmp_echo_request")
int lxc_loadbalancer_icmp_echo_request_check(const struct __ctx_buff *ctx)
{
    void *data, *data_end;
    __u32 *status_code;
    struct ethhdr *l2;
    struct iphdr *l3;
    struct icmphdr *icmphdr;

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

    assert(l2->h_proto == bpf_htons(ETH_P_IP));

    l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
    if ((void *)l3 + sizeof(struct iphdr) > data_end)
        test_fatal("l3 out of bounds");

    assert(l3->protocol == IPPROTO_ICMP);

    icmphdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)icmphdr + sizeof(struct icmphdr) > data_end)
        test_fatal("icmphdr out of bounds");

    /* Verify this is an ICMP echo reply */
    test_log("ICMP type: %d, expected: %d (ICMP_ECHOREPLY)", icmphdr->type, ICMP_ECHOREPLY);
    assert(icmphdr->type == ICMP_ECHOREPLY);

    /* Verify the ICMP ID is preserved */
    assert(icmphdr->un.echo.id == ICMP_ID);

    /* Verify IP addresses are swapped */
    test_log("Reply src IP: 0x%x, expected: 0x%x (LOADBALANCER_IP)", bpf_ntohl(l3->saddr), bpf_ntohl(LOADBALANCER_IP));
    test_log("Reply dst IP: 0x%x, expected: 0x%x (POD_IP)", bpf_ntohl(l3->daddr), bpf_ntohl(POD_IP));
    assert(l3->saddr == LOADBALANCER_IP);
    assert(l3->daddr == POD_IP);

    /* Verify MAC addresses are swapped */
    test_log("Checking MAC address swapping: src should be node_mac, dst should be pod_mac");
    assert(memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) == 0);
    assert(memcmp(l2->h_dest, (__u8 *)pod_mac, ETH_ALEN) == 0);
    test_log("MAC address swapping verified successfully");

    test_finish();
}

/* Test 3: Non-echo ICMP packets should NOT be handled by echo reply logic */
PKTGEN("tc", "test_lxc_icmp_other")
int lxc_icmp_other_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct icmphdr *icmphdr;
    struct ethhdr *l2;
    struct iphdr *l3;
    void *data;

    /* Init packet builder */
    pktgen__init(&builder, ctx);

    /* Push ethernet header */
    l2 = pktgen__push_ethhdr(&builder);
    if (!l2)
        return TEST_ERROR;

    ethhdr__set_macs(l2, (__u8 *)pod_mac, (__u8 *)node_mac);

    /* Push IPv4 header */
    l3 = pktgen__push_default_iphdr(&builder);
    if (!l3)
        return TEST_ERROR;

    l3->saddr = POD_IP;
    l3->daddr = CLUSTERIP_IP;

    /* Push ICMP header with destination unreachable type */
    icmphdr = pktgen__push_icmphdr(&builder);
    if (!icmphdr)
        return TEST_ERROR;

    icmphdr->type = ICMP_DEST_UNREACH;
    icmphdr->code = ICMP_PORT_UNREACH;
    icmphdr->un.gateway = 0;

    data = pktgen__push_data(&builder, default_data, sizeof(default_data));
    if (!data)
        return TEST_ERROR;

    /* Calc lengths, set protocol fields and calc checksums */
    pktgen__finish(&builder);

    return 0;
}

SETUP("tc", "test_lxc_icmp_other")
int lxc_icmp_other_setup(struct __ctx_buff *ctx)
{
    /* Create a ClusterIP service for the non-echo ICMP test */
    lb_v4_add_service_with_flags(CLUSTERIP_IP, SERVICE_PORT, IPPROTO_TCP, 1, 1, 0, 0);

    /* Add a backend for the service */
    lb_v4_add_backend(CLUSTERIP_IP, SERVICE_PORT, 1, 1, BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

    /* Configure IPCache entries */
    ipcache_v4_add_entry(POD_IP, 0, 112233, 0, 0);        /* Source pod */
    ipcache_v4_add_entry(CLUSTERIP_IP, 0, WORLD_IPV4_ID, 0, 0);  /* Service IP */
    ipcache_v4_add_entry(BACKEND_IP, 0, 112244, 0, 0);    /* Backend pod */

    /* Jump into the LXC entrypoint (pod egress) */
    tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
    /* Fail if we didn't jump */
    return TEST_ERROR;
}

CHECK("tc", "test_lxc_icmp_other")
int lxc_icmp_other_check(const struct __ctx_buff *ctx)
{
    void *data, *data_end;
    __u32 *status_code;
    struct ethhdr *l2;
    struct iphdr *l3;
    struct icmphdr *icmphdr;

    test_init();

    data = (void *)(long)ctx_data(ctx);
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");

    status_code = data;
    /* Non-echo ICMP should be dropped as they are error packets not suitable for load balancing */
    test_log("Status code: %d, expected: %d (CTX_ACT_DROP)", *status_code, CTX_ACT_DROP);
    assert(*status_code == CTX_ACT_DROP);

    l2 = data + sizeof(__u32);
    if ((void *)l2 + sizeof(struct ethhdr) > data_end)
        test_fatal("l2 out of bounds");

    assert(l2->h_proto == bpf_htons(ETH_P_IP));

    l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
    if ((void *)l3 + sizeof(struct iphdr) > data_end)
        test_fatal("l3 out of bounds");

    assert(l3->protocol == IPPROTO_ICMP);

    icmphdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)icmphdr + sizeof(struct icmphdr) > data_end)
        test_fatal("icmphdr out of bounds");

    /* Verify this is NOT an ICMP echo reply - other ICMP types should not be handled */
    test_log("ICMP type: %d, should NOT be: %d (ICMP_ECHOREPLY)", icmphdr->type, ICMP_ECHOREPLY);
    assert(icmphdr->type != ICMP_ECHOREPLY);

    /* Verify this is the expected ICMP type that was dropped */
    assert(icmphdr->type == ICMP_DEST_UNREACH);

    test_finish();
}

