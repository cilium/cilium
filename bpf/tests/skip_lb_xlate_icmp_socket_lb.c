// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include "common.h"
#include "pktgen.h"

#define TEST_BPF_SOCK 1

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#undef ENABLE_HEALTH_CHECK
#define ENABLE_SOCKET_LB_FULL 1

#define POD_IP v4_pod_one
#define POD_IPV6 v6_pod_one
#define CLUSTERIP_IP v4_svc_one
#define CLUSTERIP_IPV6 v6_node_one
#define SERVICE_PORT tcp_svc_one
#define BACKEND_IP v4_pod_two
#define BACKEND_IPV6 v6_pod_two
#define BACKEND_PORT __bpf_htons(8080)
#define NETNS_COOKIE 5000ULL

#define get_netns_cookie(ctx) test_get_netns_cookie(ctx)
/* Set netns_cookie based on the source ip in the addr */
static __always_inline __u64
test_get_netns_cookie(__maybe_unused const struct bpf_sock_addr *addr)
{
	return NETNS_COOKIE;
}

#include "bpf_sock.c"
#include "lib/common.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

/* Enable ICMP echo reply on virtual IPs for testing */
ASSIGN_CONFIG(bool, reply_to_icmp_echo_on_virtual_ips, true);

/* Test that ICMP to ClusterIP should skip socket layer load balancing */
CHECK("xdp", "sock4_xlate_fwd_icmp_skip")
int test_sock4_xlate_fwd_icmp_skip(__maybe_unused struct xdp_md *ctx)
{
	int ret;
	__u16 revnat_id = 1;
	struct bpf_sock sk = {
		.src_ip4 = POD_IP
	};
	struct bpf_sock_addr addr = {
		.user_ip4 = CLUSTERIP_IP,
		.user_port = SERVICE_PORT,
		.protocol = IPPROTO_ICMP,
		.sk = &sk,
	};

	/* Set up service and backend */
	lb_v4_add_service(CLUSTERIP_IP, SERVICE_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(CLUSTERIP_IP, SERVICE_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	/* Add IPCache entries */
	ipcache_v4_add_entry(POD_IP, 0, 112233, 0, 0);
	ipcache_v4_add_entry(CLUSTERIP_IP, 0, WORLD_IPV4_ID, 0, 0);
	ipcache_v4_add_entry(BACKEND_IP, 0, 112244, 0, 0);

	test_init();

	/* ICMP to ClusterIP should skip load balancing (return -ENXIO) */
	ret = __sock4_xlate_fwd(&addr, &addr, false);
	test_log("ICMP xlate ret: %d", ret);
	test_log("ICMP dest IP: %x (should remain %x)", addr.user_ip4, CLUSTERIP_IP);
	test_log("ICMP dest port: %d (should remain %d)", addr.user_port, SERVICE_PORT);
	
	/* We expect -ENXIO to indicate that socket layer should skip this */
	assert(ret == -ENXIO);
	/* IP and port should remain unchanged */
	assert(addr.user_ip4 == CLUSTERIP_IP);
	assert(addr.user_port == SERVICE_PORT);

	/* For comparison: TCP to the same ClusterIP should do load balancing */
	addr.protocol = IPPROTO_TCP;
	addr.user_ip4 = CLUSTERIP_IP;
	addr.user_port = SERVICE_PORT;
	ret = __sock4_xlate_fwd(&addr, &addr, false);
	test_log("TCP xlate ret: %d", ret);
	test_log("TCP dest IP: %x (should be %x)", addr.user_ip4, BACKEND_IP);
	test_log("TCP dest port: %d (should be %d)", addr.user_port, BACKEND_PORT);
	
	/* TCP should succeed and translate to backend */
	assert(ret == 0);
	assert(addr.user_ip4 == BACKEND_IP);
	assert(addr.user_port == BACKEND_PORT);

	test_finish();
}

/* Test that ICMPv6 to ClusterIP should skip socket layer load balancing */
CHECK("xdp", "sock6_xlate_fwd_icmp_skip")
int test_sock6_xlate_fwd_icmp_skip(__maybe_unused struct xdp_md *ctx)
{
	int ret;
	__u16 revnat_id = 1;
	union v6addr frontend_ip = {};
	union v6addr backend_ip = {};
	struct bpf_sock sk = {};
	struct bpf_sock_addr addr = {
		.user_port = SERVICE_PORT,
		.protocol = IPPROTO_ICMPV6,
		.sk = &sk,
	};

	/* Set up IPv6 addresses */
	memcpy(frontend_ip.addr, (void *)&CLUSTERIP_IPV6, 16);
	memcpy(backend_ip.addr, (void *)&BACKEND_IPV6, 16);
	memcpy(addr.user_ip6, (void *)&CLUSTERIP_IPV6, 16);
	memcpy(sk.src_ip6, (void *)&POD_IPV6, 16);

	/* Set up service and backend */
	lb_v6_add_service(&frontend_ip, SERVICE_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip, SERVICE_PORT, 1, 124,
			  &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);

	/* Add IPCache entries */
	ipcache_v6_add_entry((union v6addr *)&POD_IPV6, 0, 112233, 0, 0);
	ipcache_v6_add_entry(&frontend_ip, 0, WORLD_IPV6_ID, 0, 0);
	ipcache_v6_add_entry(&backend_ip, 0, 112244, 0, 0);

	test_init();

	/* ICMPv6 to ClusterIP should skip load balancing (return -ENXIO) */
	ret = __sock6_xlate_fwd(&addr, false);
	test_log("ICMPv6 xlate ret: %d", ret);
	test_log("ICMPv6 dest IP: %x (should remain %x)", addr.user_ip6[0], ((union v6addr *)&CLUSTERIP_IPV6)->addr[0]);
	test_log("ICMPv6 dest port: %d (should remain %d)", addr.user_port, SERVICE_PORT);
	
	/* We expect -ENXIO to indicate that socket layer should skip this */
	assert(ret == -ENXIO);
	/* IP and port should remain unchanged */
	assert(memcmp(addr.user_ip6, (void *)&CLUSTERIP_IPV6, 16) == 0);
	assert(addr.user_port == SERVICE_PORT);

	/* For comparison: TCP to the same ClusterIP should do load balancing */
	addr.protocol = IPPROTO_TCP;
	memcpy(addr.user_ip6, (void *)&CLUSTERIP_IPV6, 16);
	addr.user_port = SERVICE_PORT;
	ret = __sock6_xlate_fwd(&addr, false);
	test_log("TCP xlate ret: %d", ret);
	test_log("TCP dest IP: %x (should be %x)", addr.user_ip6[0], ((union v6addr *)&BACKEND_IPV6)->addr[0]);
	test_log("TCP dest port: %d (should be %d)", addr.user_port, BACKEND_PORT);
	
	/* TCP should succeed and translate to backend */
	assert(ret == 0);
	assert(memcmp(addr.user_ip6, (void *)&BACKEND_IPV6, 16) == 0);
	assert(addr.user_port == BACKEND_PORT);

	test_finish();
}