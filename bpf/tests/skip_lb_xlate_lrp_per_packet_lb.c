// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/unspec.h>
#include <bpf/api.h>
#include "pktgen.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#undef ENABLE_HEALTH_CHECK
#define ENABLE_LOCAL_REDIRECT_POLICY 1
#define ENABLE_SOCKET_LB_HOST_ONLY 1
#define HAVE_NETNS_COOKIE 1

/* Set a dummy value for netns cookie*/
#ifdef ENDPOINT_NETNS_COOKIE
    #undef ENDPOINT_NETNS_COOKIE
#endif
#define ENDPOINT_NETNS_COOKIE 5000

#include <bpf_lxc.c>
#include "lib/lb.h"
#include "lib/ipcache.h"
#include "lib/endpoint.h"

#define FROM_CONTAINER 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_CONTAINER] = &cil_from_container,
	},
};

#define V4_SERVICE_IP		v4_svc_one
#define SERVICE_PORT		tcp_svc_one
#define V4_BACKEND_IP		v4_pod_one
#define BACKEND_PORT		__bpf_htons(8080)
#define V6_SERVICE_IP		v6_pod_one
#define V6_BACKEND_IP		v6_pod_two

PKTGEN("tc", "v4_local_redirect")
int  v4_local_backend_to_service_packetgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;
	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder, (__u8 *)mac_one,
					  (__u8 *)mac_two, V4_BACKEND_IP, V4_SERVICE_IP,
					  tcp_src_one, SERVICE_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;
	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "v4_local_redirect")
int v4_local_backend_to_service_setup(struct __ctx_buff *ctx)
{
	lb_v4_add_service_with_flags(V4_SERVICE_IP, SERVICE_PORT, 1, 1,
				     SVC_FLAG_ROUTABLE, SVC_FLAG_LOCALREDIRECT);
	lb_v4_add_backend(V4_SERVICE_IP, SERVICE_PORT, 1, 124,
			  V4_BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	/* Add the service in LB4_SKIP_MAP to skip service translation for request originating from the local backend */
	struct skip_lb4_key key = {
		.netns_cookie = ENDPOINT_NETNS_COOKIE,
		.address = V4_SERVICE_IP,
		.port = SERVICE_PORT,
	};
	__u8 val = 0;
	map_update_elem(&LB4_SKIP_MAP, &key, &val, BPF_ANY);

	/* Add an IPCache entry for the backend pod */
	ipcache_v4_add_entry(V4_BACKEND_IP, 0, 112233, 0, 0);
	endpoint_v4_add_entry(V4_BACKEND_IP, 0, 0, 0, 0, NULL, NULL);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

/* Test that sending a packet from a backend pod to its own service does not
 * get sent back to the backend due to local redirect policy
 */
CHECK("tc", "v4_local_redirect")
int v4_local_backend_to_service_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	/* We should not trigger re-direction to backend */
	assert(*status_code != TC_ACT_REDIRECT);
	assert(*status_code == TC_ACT_SHOT);
	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");
	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");
	test_log("l3->saddr: %d l3->daddr: %d", l3->saddr, l3->daddr);
	test_log("V4_BACKEND_IP: %d V4_SERVICE_IP: %d", V4_BACKEND_IP, V4_SERVICE_IP);
	if (l3->saddr != V4_BACKEND_IP)
		test_fatal("src IP has been changed");
	if (l3->daddr != V4_SERVICE_IP)
		test_fatal("dest IP has been changed");
	if (l3->daddr == V4_BACKEND_IP)
		test_fatal("dest IP has been NAT'ed creating a loopback");
	if (l4->source != tcp_src_one)
		test_fatal("src TCP port has been changed");
	if (l4->dest != SERVICE_PORT)
		test_fatal("dst TCP port has been changed");
	test_finish();
}

PKTGEN("tc", "v6_local_redirect")
int  v6_local_backend_to_service_packetgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;
	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder, (__u8 *)mac_one,
					  (__u8 *)mac_two, (__u8 *)V6_BACKEND_IP,
					  (__u8 *)V6_SERVICE_IP, tcp_src_one, SERVICE_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;
	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "v6_local_redirect")
int v6_local_backend_to_service_setup(struct __ctx_buff *ctx)
{
	union v6addr service_ip = {};
	union v6addr backend_ip = {};

	memcpy(service_ip.addr, (void *)V6_SERVICE_IP, 16);
	memcpy(backend_ip.addr, (void *)V6_BACKEND_IP, 16);

	lb_v6_add_service_with_flags(&service_ip, SERVICE_PORT, 1, 1,
				     SVC_FLAG_ROUTABLE, SVC_FLAG_LOCALREDIRECT);
	lb_v6_add_backend(&service_ip, SERVICE_PORT, 1, 124, &backend_ip,
			  BACKEND_PORT, IPPROTO_TCP, 0);


	/* Add the service in LB6_SKIP_MAP to skip service translation for request originating from the local backend */
	struct skip_lb6_key key = {
		.netns_cookie = ENDPOINT_NETNS_COOKIE,
		.port = SERVICE_PORT,
	};
	__u8 val = 0;

	memcpy(&key.address, (__u8 *)V6_SERVICE_IP, sizeof(V6_SERVICE_IP));
	map_update_elem(&LB6_SKIP_MAP, &key, &val, BPF_ANY);

	/* Add an IPCache entry for the backend pod */
	ipcache_v6_add_entry(&backend_ip, 0, 112233, 0, 0);
	endpoint_v6_add_entry(&backend_ip, 0, 0, 0, 0, NULL, NULL);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "v6_local_redirect")
int v6_local_backend_to_service_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	/* We should not trigger re-direction to backend */
	assert(*status_code != TC_ACT_REDIRECT);
	assert(*status_code == TC_ACT_SHOT);
	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");
	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l3->saddr.in6_u.u6_addr8, (__u8 *)V6_BACKEND_IP, sizeof(V6_BACKEND_IP)) != 0)
		test_fatal("src IP has been changed");
	if (memcmp(l3->daddr.in6_u.u6_addr8, (__u8 *)V6_SERVICE_IP, sizeof(V6_SERVICE_IP)) != 0)
		test_fatal("dest IP has been changed");
	if (memcmp(l3->daddr.in6_u.u6_addr8, (__u8 *)V6_BACKEND_IP, sizeof(V6_BACKEND_IP)) == 0)
		test_fatal("dest IP has been NAT'ed creating a loopback");
	if (l4->source != tcp_src_one)
		test_fatal("src TCP port has been changed");
	if (l4->dest != SERVICE_PORT)
		test_fatal("dst TCP port has been changed");
	test_finish();
}
