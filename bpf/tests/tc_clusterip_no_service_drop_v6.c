// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Test that verifies ClusterIP/LoadBalancer virtual IPs drop traffic on ports 
 * without services instead of forwarding them (IPv6 version) */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_LOADBALANCER
#define ENABLE_DROP_VIRTUAL_IP_TRAFFIC
#define ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY

/* Test network and addresses */
/* IPv6 addresses for external hosts */
#define v6_ext_one_addr {0xfd, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
volatile const __u8 v6_ext_one[] = v6_ext_one_addr;

/* IPv6 addresses for services */
#define v6_svc_one_addr {0xfd, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
#define v6_svc_two_addr {0xfd, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
volatile const __u8 v6_svc_one[] = v6_svc_one_addr;
volatile const __u8 v6_svc_two[] = v6_svc_two_addr;

#define CLIENT_IP           v6_ext_one   /* External client IPv6 */
#define CLIENT_PORT         __bpf_htons(1234)
#define CLUSTERIP           v6_svc_one   /* Virtual service IPv6 (ClusterIP) */
#define LOADBALANCER_IP     v6_svc_two   /* Virtual service IPv6 (LoadBalancer) */
#define NODE_IP             v6_node_one  /* Actual node IPv6 */
#define SERVICE_PORT        tcp_svc_one  /* Port with service */
#define NO_SERVICE_PORT     __bpf_htons(9999) /* Port without service */
#define BACKEND_IP          v6_pod_one
#define BACKEND_PORT        __bpf_htons(8080)

/* MAC addresses for tests */
static volatile const __u8 *src_mac = mac_one;
static volatile const __u8 *dst_mac = mac_two;

/* Include the datapath code */
#include <bpf_host.c>

/* Include test helpers */
#include "lib/lb.h"
#include "lib/ipcache.h"

/* Program array for tail calls */
#define FROM_NETDEV 0
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(max_entries, 1);
    __array(values, int());
} entry_call_map __section(".maps") = {
    .values = {
        [FROM_NETDEV] = &cil_from_netdev,
    },
};

/* Test 1: ClusterIP should drop traffic on non-service ports */
PKTGEN("tc", "test_clusterip_no_service_drop_v6")
int clusterip_no_service_drop_v6_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct tcphdr *l4;
    
    pktgen__init(&builder, ctx);
    
    /* Generate packet to ClusterIP on a port without service */
    l4 = pktgen__push_ipv6_tcp_packet(&builder,
                                      (__u8 *)src_mac, (__u8 *)dst_mac,
                                      (__u8 *)CLIENT_IP, (__u8 *)CLUSTERIP,
                                      CLIENT_PORT, NO_SERVICE_PORT);
    if (!l4)
        return TEST_ERROR;
        
    if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
        return TEST_ERROR;
    pktgen__finish(&builder);
    
    return 0;
}

SETUP("tc", "test_clusterip_no_service_drop_v6")
int clusterip_no_service_drop_v6_setup(struct __ctx_buff *ctx)
{
    union v6addr cluster_ip, backend_ip;
    
    memcpy(&cluster_ip, (void *)CLUSTERIP, sizeof(cluster_ip));
    memcpy(&backend_ip, (void *)BACKEND_IP, sizeof(backend_ip));
    
    /* Add a ClusterIP service on SERVICE_PORT but not on NO_SERVICE_PORT */
    /* ClusterIP services should NOT have SVC_FLAG_ROUTABLE */
    /* Wildcard entry will be created automatically by the test harness */
    lb_v6_add_service_with_flags(&cluster_ip, SERVICE_PORT, IPPROTO_TCP, 1, 1, 0, 0);
    lb_v6_add_backend(&cluster_ip, SERVICE_PORT, 1, 124,
                      &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);
    
    /* Configure IPCache entries */
    ipcache_v6_add_entry((union v6addr *)BACKEND_IP, 0, 112233, 0, 0);
    ipcache_v6_add_entry((union v6addr *)CLUSTERIP, 0, WORLD_IPV6_ID, 0, 0);
    
    /* Jump to BPF program */
    tail_call_static(ctx, entry_call_map, FROM_NETDEV);
    return TEST_ERROR;
}

CHECK("tc", "test_clusterip_no_service_drop_v6")
int clusterip_no_service_drop_v6_check(const struct __ctx_buff *ctx)
{
    void *data = (void *)(long)ctx_data(ctx);
    void *data_end = (void *)(long)ctx->data_end;
    __u32 *status_code;
    
    test_init();
    
    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");
        
    status_code = data;
    test_log("ClusterIP v6 no service port status: %d", *status_code);
    
    /* This test should currently fail as packets are forwarded, not dropped */
    /* Once the fix is implemented, packets should be dropped */
    assert(*status_code == CTX_ACT_DROP);
    
    test_finish();
}

/* Test 2: LoadBalancer IP should drop traffic on non-service ports */
PKTGEN("tc", "test_loadbalancer_no_service_drop_v6")
int loadbalancer_no_service_drop_v6_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct tcphdr *l4;
    
    pktgen__init(&builder, ctx);
    
    /* Generate packet to LoadBalancer IP on a port without service */
    l4 = pktgen__push_ipv6_tcp_packet(&builder,
                                      (__u8 *)src_mac, (__u8 *)dst_mac,
                                      (__u8 *)CLIENT_IP, (__u8 *)LOADBALANCER_IP,
                                      CLIENT_PORT, NO_SERVICE_PORT);
    if (!l4)
        return TEST_ERROR;
        
    if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
        return TEST_ERROR;
    pktgen__finish(&builder);
    
    return 0;
}

SETUP("tc", "test_loadbalancer_no_service_drop_v6")
int loadbalancer_no_service_drop_v6_setup(struct __ctx_buff *ctx)
{
    union v6addr lb_ip, backend_ip;
    
    memcpy(&lb_ip, (void *)LOADBALANCER_IP, sizeof(lb_ip));
    memcpy(&backend_ip, (void *)BACKEND_IP, sizeof(backend_ip));
    
    /* Add a LoadBalancer service on SERVICE_PORT but not on NO_SERVICE_PORT */
    /* Wildcard entry will be created automatically by the test harness */
    lb_v6_add_service_with_flags(&lb_ip, SERVICE_PORT, IPPROTO_TCP, 
                                 1, 2, SVC_FLAG_LOADBALANCER, 0);
    lb_v6_add_backend(&lb_ip, SERVICE_PORT, 1, 125,
                      &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);
    
    /* Configure IPCache entries */
    ipcache_v6_add_entry((union v6addr *)BACKEND_IP, 0, 112233, 0, 0);
    ipcache_v6_add_entry((union v6addr *)LOADBALANCER_IP, 0, WORLD_IPV6_ID, 0, 0);
    
    /* Jump to BPF program */
    tail_call_static(ctx, entry_call_map, FROM_NETDEV);
    return TEST_ERROR;
}

CHECK("tc", "test_loadbalancer_no_service_drop_v6")
int loadbalancer_no_service_drop_v6_check(const struct __ctx_buff *ctx)
{
    void *data = (void *)(long)ctx_data(ctx);
    void *data_end = (void *)(long)ctx->data_end;
    __u32 *status_code;
    
    test_init();
    
    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");
        
    status_code = data;
    test_log("LoadBalancer v6 no service port status: %d", *status_code);
    
    /* This test should currently fail as packets are forwarded, not dropped */
    /* Once the fix is implemented, packets should be dropped */
    assert(*status_code == CTX_ACT_DROP);
    
    test_finish();
}

/* Test 3: Node IP should forward traffic on non-service ports */
PKTGEN("tc", "test_nodeip_no_service_forward_v6")
int nodeip_no_service_forward_v6_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct tcphdr *l4;
    
    pktgen__init(&builder, ctx);
    
    /* Generate packet to Node IP on a port without service */
    l4 = pktgen__push_ipv6_tcp_packet(&builder,
                                      (__u8 *)src_mac, (__u8 *)dst_mac,
                                      (__u8 *)CLIENT_IP, (__u8 *)NODE_IP,
                                      CLIENT_PORT, NO_SERVICE_PORT);
    if (!l4)
        return TEST_ERROR;
        
    if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
        return TEST_ERROR;
    pktgen__finish(&builder);
    
    return 0;
}

SETUP("tc", "test_nodeip_no_service_forward_v6")
int nodeip_no_service_forward_v6_setup(struct __ctx_buff *ctx)
{
    union v6addr node_ip, backend_ip;
    
    memcpy(&node_ip, (void *)NODE_IP, sizeof(node_ip));
    memcpy(&backend_ip, (void *)BACKEND_IP, sizeof(backend_ip));
    
    /* Add a NodePort service on SERVICE_PORT but not on NO_SERVICE_PORT */
    /* NodePort services should have SVC_FLAG_ROUTABLE since they use real node IPs */
    lb_v6_add_service_with_flags(&node_ip, SERVICE_PORT, IPPROTO_TCP, 
                                 1, 3, SVC_FLAG_NODEPORT | SVC_FLAG_ROUTABLE, 0);
    lb_v6_add_backend(&node_ip, SERVICE_PORT, 1, 126,
                      &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);
    
    /* Configure IPCache entries */
    ipcache_v6_add_entry((union v6addr *)BACKEND_IP, 0, 112233, 0, 0);
    ipcache_v6_add_entry((union v6addr *)NODE_IP, 0, WORLD_IPV6_ID, 0, 0);
    
    /* Jump to BPF program */
    tail_call_static(ctx, entry_call_map, FROM_NETDEV);
    return TEST_ERROR;
}

CHECK("tc", "test_nodeip_no_service_forward_v6")
int nodeip_no_service_forward_v6_check(const struct __ctx_buff *ctx)
{
    void *data = (void *)(long)ctx_data(ctx);
    void *data_end = (void *)(long)ctx->data_end;
    __u32 *status_code;
    
    test_init();
    
    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");
        
    status_code = data;
    test_log("Node IP v6 no service port status: %d", *status_code);
    
    /* Node IP packets should be forwarded, not dropped */
    assert(*status_code == CTX_ACT_OK);
    
    test_finish();
}

/* Test 4: ICMPv6 echo request to ClusterIP should get a reply */
PKTGEN("tc", "test_clusterip_icmpv6_echo")
int clusterip_icmpv6_echo_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct icmp6hdr *icmp;
    __u8 payload[] = {0, 1, 2, 3, 4, 5, 6, 7};
    
    pktgen__init(&builder, ctx);
    
    /* Generate ICMPv6 echo request to ClusterIP */
    icmp = pktgen__push_ipv6_icmp6_packet(&builder,
                                         (__u8 *)src_mac, (__u8 *)dst_mac,
                                         (__u8 *)CLIENT_IP, (__u8 *)CLUSTERIP,
                                         ICMPV6_ECHO_REQUEST);
    if (!icmp)
        return TEST_ERROR;
        
    /* Set ICMPv6 echo request fields */
    icmp->icmp6_code = 0;
    icmp->icmp6_dataun.u_echo.identifier = __bpf_htons(123);
    icmp->icmp6_dataun.u_echo.sequence = __bpf_htons(456);
    
    /* Add payload */
    if (!pktgen__push_data(&builder, payload, sizeof(payload)))
        return TEST_ERROR;
        
    pktgen__finish(&builder);
    
    return 0;
}

SETUP("tc", "test_clusterip_icmpv6_echo")
int clusterip_icmpv6_echo_setup(struct __ctx_buff *ctx)
{
    union v6addr cluster_ip, backend_ip;
    
    memcpy(&cluster_ip, (void *)CLUSTERIP, sizeof(cluster_ip));
    memcpy(&backend_ip, (void *)BACKEND_IP, sizeof(backend_ip));
    
    /* Add a ClusterIP service */
    /* ClusterIP services should NOT have SVC_FLAG_ROUTABLE */
    /* Wildcard entry will be created automatically by the test harness */
    lb_v6_add_service_with_flags(&cluster_ip, SERVICE_PORT, IPPROTO_TCP, 1, 4, 0, 0);
    lb_v6_add_backend(&cluster_ip, SERVICE_PORT, 1, 127,
                      &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);
    
    /* Also add an ICMPv6 service for echo requests */
    lb_v6_add_service_with_flags(&cluster_ip, 0, IPPROTO_ICMPV6, 0, 4, 0, 0);
    
    /* Configure IPCache entries */
    ipcache_v6_add_entry((union v6addr *)BACKEND_IP, 0, 112233, 0, 0);
    ipcache_v6_add_entry((union v6addr *)CLUSTERIP, 0, WORLD_IPV6_ID, 0, 0);
    
    /* Jump to BPF program */
    tail_call_static(ctx, entry_call_map, FROM_NETDEV);
    return TEST_ERROR;
}

CHECK("tc", "test_clusterip_icmpv6_echo")
int clusterip_icmpv6_echo_check(const struct __ctx_buff *ctx)
{
    void *data = (void *)(long)ctx_data(ctx);
    void *data_end = (void *)(long)ctx->data_end;
    __u32 *status_code;
    
    test_init();
    
    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");
        
    status_code = data;
    test_log("ClusterIP ICMPv6 echo status: %d", *status_code);
    
    /* Should get a redirect for ICMPv6 reply */
    assert(*status_code == CTX_ACT_REDIRECT);
    
    /* The ICMPv6 reply is generated internally and redirected back,
     * so we just need to verify the redirect happened */
    
    test_finish();
}
