// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Test that verifies ClusterIP/LoadBalancer virtual IPs drop traffic on ports 
 * without services instead of forwarding them */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_LOADBALANCER
#define ENABLE_DROP_VIRTUAL_IP_TRAFFIC
#define ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY

/* Test network and addresses */
#define CLIENT_IP           v4_ext_one   /* External client IP */
#define CLIENT_PORT         __bpf_htons(1234)
#define CLUSTERIP           v4_svc_one   /* Virtual service IP (ClusterIP) */
#define LOADBALANCER_IP     v4_svc_two   /* Virtual service IP (LoadBalancer) */
#define NODE_IP             v4_node_one  /* Actual node IP */
#define SERVICE_PORT        tcp_svc_one  /* Port with service */
#define NO_SERVICE_PORT     __bpf_htons(9999) /* Port without service */
#define BACKEND_IP          v4_pod_one
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
PKTGEN("tc", "test_clusterip_no_service_drop")
int clusterip_no_service_drop_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct tcphdr *l4;
    
    pktgen__init(&builder, ctx);
    
    /* Generate packet to ClusterIP on a port without service */
    l4 = pktgen__push_ipv4_tcp_packet(&builder,
                                      (__u8 *)src_mac, (__u8 *)dst_mac,
                                      CLIENT_IP, CLUSTERIP,
                                      CLIENT_PORT, NO_SERVICE_PORT);
    if (!l4)
        return TEST_ERROR;
        
    if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
        return TEST_ERROR;
    pktgen__finish(&builder);
    
    return 0;
}

SETUP("tc", "test_clusterip_no_service_drop")
int clusterip_no_service_drop_setup(struct __ctx_buff *ctx)
{
    /* Add a ClusterIP service on SERVICE_PORT but not on NO_SERVICE_PORT */
    /* ClusterIP services should NOT have SVC_FLAG_ROUTABLE */
    /* Wildcard entry will be created automatically by the test harness */
    lb_v4_add_service_with_flags(CLUSTERIP, SERVICE_PORT, IPPROTO_TCP, 1, 1, 0, 0);
    lb_v4_add_backend(CLUSTERIP, SERVICE_PORT, 1, 124,
                      BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);
    
    /* Configure IPCache entries */
    ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);
    ipcache_v4_add_entry(CLUSTERIP, 0, WORLD_IPV4_ID, 0, 0);
    
    /* Jump to BPF program */
    tail_call_static(ctx, entry_call_map, FROM_NETDEV);
    return TEST_ERROR;
}

CHECK("tc", "test_clusterip_no_service_drop")
int clusterip_no_service_drop_check(const struct __ctx_buff *ctx)
{
    void *data = (void *)(long)ctx_data(ctx);
    void *data_end = (void *)(long)ctx->data_end;
    __u32 *status_code;
    
    test_init();
    
    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");
        
    status_code = data;
    test_log("ClusterIP no service port status: %d", *status_code);
    
    /* This test should currently fail as packets are forwarded, not dropped */
    /* Once the fix is implemented, packets should be dropped */
    assert(*status_code == CTX_ACT_DROP);
    
    test_finish();
}

/* Test 2: LoadBalancer IP should drop traffic on non-service ports */
PKTGEN("tc", "test_loadbalancer_no_service_drop")
int loadbalancer_no_service_drop_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct tcphdr *l4;
    
    pktgen__init(&builder, ctx);
    
    /* Generate packet to LoadBalancer IP on a port without service */
    l4 = pktgen__push_ipv4_tcp_packet(&builder,
                                      (__u8 *)src_mac, (__u8 *)dst_mac,
                                      CLIENT_IP, LOADBALANCER_IP,
                                      CLIENT_PORT, NO_SERVICE_PORT);
    if (!l4)
        return TEST_ERROR;
        
    if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
        return TEST_ERROR;
    pktgen__finish(&builder);
    
    return 0;
}

SETUP("tc", "test_loadbalancer_no_service_drop")
int loadbalancer_no_service_drop_setup(struct __ctx_buff *ctx)
{
    /* Add a LoadBalancer service on SERVICE_PORT but not on NO_SERVICE_PORT */
    /* Wildcard entry will be created automatically by the test harness */
    lb_v4_add_service_with_flags(LOADBALANCER_IP, SERVICE_PORT, IPPROTO_TCP, 
                                 1, 2, SVC_FLAG_LOADBALANCER, 0);
    lb_v4_add_backend(LOADBALANCER_IP, SERVICE_PORT, 1, 125,
                      BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);
    
    /* Configure IPCache entries */
    ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);
    ipcache_v4_add_entry(LOADBALANCER_IP, 0, WORLD_IPV4_ID, 0, 0);
    
    /* Jump to BPF program */
    tail_call_static(ctx, entry_call_map, FROM_NETDEV);
    return TEST_ERROR;
}

CHECK("tc", "test_loadbalancer_no_service_drop")
int loadbalancer_no_service_drop_check(const struct __ctx_buff *ctx)
{
    void *data = (void *)(long)ctx_data(ctx);
    void *data_end = (void *)(long)ctx->data_end;
    __u32 *status_code;
    
    test_init();
    
    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");
        
    status_code = data;
    test_log("LoadBalancer no service port status: %d", *status_code);
    
    /* This test should currently fail as packets are forwarded, not dropped */
    /* Once the fix is implemented, packets should be dropped */
    assert(*status_code == CTX_ACT_DROP);
    
    test_finish();
}

/* Test 3: Node IP should forward traffic on non-service ports */
PKTGEN("tc", "test_nodeip_no_service_forward")
int nodeip_no_service_forward_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct tcphdr *l4;
    
    pktgen__init(&builder, ctx);
    
    /* Generate packet to Node IP on a port without service */
    l4 = pktgen__push_ipv4_tcp_packet(&builder,
                                      (__u8 *)src_mac, (__u8 *)dst_mac,
                                      CLIENT_IP, NODE_IP,
                                      CLIENT_PORT, NO_SERVICE_PORT);
    if (!l4)
        return TEST_ERROR;
        
    if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
        return TEST_ERROR;
    pktgen__finish(&builder);
    
    return 0;
}

SETUP("tc", "test_nodeip_no_service_forward")
int nodeip_no_service_forward_setup(struct __ctx_buff *ctx)
{
    /* Add a NodePort service on SERVICE_PORT but not on NO_SERVICE_PORT */
    /* NodePort services should have SVC_FLAG_ROUTABLE since they use real node IPs */
    lb_v4_add_service_with_flags(NODE_IP, SERVICE_PORT, IPPROTO_TCP, 
                                 1, 3, SVC_FLAG_NODEPORT | SVC_FLAG_ROUTABLE, 0);
    lb_v4_add_backend(NODE_IP, SERVICE_PORT, 1, 126,
                      BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);
    
    /* Configure IPCache entries */
    ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);
    ipcache_v4_add_entry(NODE_IP, 0, WORLD_IPV4_ID, 0, 0);
    
    /* Jump to BPF program */
    tail_call_static(ctx, entry_call_map, FROM_NETDEV);
    return TEST_ERROR;
}

CHECK("tc", "test_nodeip_no_service_forward")
int nodeip_no_service_forward_check(const struct __ctx_buff *ctx)
{
    void *data = (void *)(long)ctx_data(ctx);
    void *data_end = (void *)(long)ctx->data_end;
    __u32 *status_code;
    
    test_init();
    
    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");
        
    status_code = data;
    test_log("Node IP no service port status: %d", *status_code);
    
    /* Node IP packets should be forwarded, not dropped */
    assert(*status_code == CTX_ACT_OK);
    
    test_finish();
}

/* Test 4: ICMP echo request to ClusterIP should get a reply */
PKTGEN("tc", "test_clusterip_icmp_echo")
int clusterip_icmp_echo_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct icmphdr *icmp;
    __u8 payload[] = {0, 1, 2, 3, 4, 5, 6, 7};
    
    pktgen__init(&builder, ctx);
    
    /* Generate ICMP echo request to ClusterIP */
    icmp = pktgen__push_ipv4_icmp_packet(&builder,
                                         (__u8 *)src_mac, (__u8 *)dst_mac,
                                         CLIENT_IP, CLUSTERIP,
                                         ICMP_ECHO);
    if (!icmp)
        return TEST_ERROR;
        
    /* Set ICMP echo request fields */
    icmp->code = 0;
    icmp->un.echo.id = __bpf_htons(123);
    icmp->un.echo.sequence = __bpf_htons(456);
    
    /* Add payload */
    if (!pktgen__push_data(&builder, payload, sizeof(payload)))
        return TEST_ERROR;
        
    pktgen__finish(&builder);
    
    return 0;
}

SETUP("tc", "test_clusterip_icmp_echo")
int clusterip_icmp_echo_setup(struct __ctx_buff *ctx)
{
    /* Add a ClusterIP service */
    /* ClusterIP services should NOT have SVC_FLAG_ROUTABLE */
    /* Wildcard entry will be created automatically by the test harness */
    lb_v4_add_service_with_flags(CLUSTERIP, SERVICE_PORT, IPPROTO_TCP, 1, 4, 0, 0);
    lb_v4_add_backend(CLUSTERIP, SERVICE_PORT, 1, 127,
                      BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);
    
    /* Also add an ICMP service for echo requests */
    lb_v4_add_service_with_flags(CLUSTERIP, 0, IPPROTO_ICMP, 1, 4, 0, 0);
    /* Add a dummy backend for ICMP */
    lb_v4_add_backend(CLUSTERIP, 0, 1, 128, CLUSTERIP, 0, IPPROTO_ICMP, 0);
    
    /* Configure IPCache entries */
    ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);
    ipcache_v4_add_entry(CLUSTERIP, 0, WORLD_IPV4_ID, 0, 0);
    
    /* Jump to BPF program */
    tail_call_static(ctx, entry_call_map, FROM_NETDEV);
    return TEST_ERROR;
}

CHECK("tc", "test_clusterip_icmp_echo")
int clusterip_icmp_echo_check(const struct __ctx_buff *ctx)
{
    void *data = (void *)(long)ctx_data(ctx);
    void *data_end = (void *)(long)ctx->data_end;
    __u32 *status_code;
    
    test_init();
    
    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");
        
    status_code = data;
    test_log("ClusterIP ICMP echo status: %d", *status_code);
    
    /* Should get a redirect for ICMP reply */
    assert(*status_code == CTX_ACT_REDIRECT);
    
    /* The ICMP reply is generated internally and redirected back,
     * so we just need to verify the redirect happened */
    
    test_finish();
}
