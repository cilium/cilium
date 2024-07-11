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
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;
	void *data;
	/* Init packet builder */
	pktgen__init(&builder, ctx);
	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)src, (__u8 *)dst);
	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;
	l3->saddr = V4_BACKEND_IP;
	l3->daddr = V4_SERVICE_IP;
	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = tcp_src_one;
	l4->dest = SERVICE_PORT;
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
	__u16 revnat_id = 1;
	struct lb4_key lb_svc_key = {};
	struct lb4_service lb_svc_value = {};
	struct lb4_reverse_nat revnat_value = {};
	struct lb4_backend backend = {};
	struct ipcache_key cache_key = {};
	struct remote_endpoint_info cache_value = {};
	struct endpoint_key ep_key = {};
	struct endpoint_info ep_value = {};
	/* Register a fake LB backend for our local redirect service */
	lb_svc_key.address = V4_SERVICE_IP;
	lb_svc_key.dport = SERVICE_PORT;
	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;
	/* Create a LRP service with one backend */
	lb_svc_value.count = 1;
	lb_svc_value.flags = SVC_FLAG_ROUTABLE;
	lb_svc_value.flags2 = SVC_FLAG_LOCALREDIRECT;
	lb_svc_value.rev_nat_index = revnat_id;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);
	/* Insert a reverse NAT entry for the above service */
	revnat_value.address = V4_SERVICE_IP;
	revnat_value.port = SERVICE_PORT;
	map_update_elem(&LB4_REVERSE_NAT_MAP, &revnat_id, &revnat_value, BPF_ANY);
	/* A backend between 1 and .count is chosen, since we have only one backend
	 * it is always backend_slot 1. Point it to backend_id 124.
	 */
	lb_svc_key.backend_slot = 1;
	lb_svc_value.backend_id = 124;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* Add the service in LB4_SKIP_MAP to skip service translation for request originating from the local backend */
	struct skip_lb4_key key = {
		.netns_cookie = ENDPOINT_NETNS_COOKIE,
		.address = V4_SERVICE_IP,
		.port = SERVICE_PORT,
	};
	__u8 val = 0;

	map_update_elem(&LB4_SKIP_MAP, &key, &val, BPF_ANY);

	/* Create backend id 124 which contains the IP and port to send the
	 * packet to.
	 */
	backend.address = V4_BACKEND_IP;
	backend.port = BACKEND_PORT;
	backend.proto = IPPROTO_TCP;
	backend.flags = 0;
	map_update_elem(&LB4_BACKEND_MAP, &lb_svc_value.backend_id, &backend, BPF_ANY);
	/* Add an IPCache entry for pod 1 */
	cache_key.lpm_key.prefixlen = 32;
	cache_key.family = ENDPOINT_KEY_IPV4;
	cache_key.ip4 = V4_BACKEND_IP;
	/* a random sec id for the pod */
	cache_value.sec_identity = 112233;
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);
	ep_key.ip4 = V4_BACKEND_IP;
	ep_key.family = ENDPOINT_KEY_IPV4;
	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

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
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	void *data;
	/* Init packet builder */
	pktgen__init(&builder, ctx);
	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)src, (__u8 *)dst);
	/* Push IPv4 header */
	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;
	memcpy(&l3->saddr, (__u8 *)V6_BACKEND_IP, sizeof(l3->saddr));
	memcpy(&l3->daddr, (__u8 *)V6_SERVICE_IP, sizeof(l3->daddr));

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = tcp_src_one;
	l4->dest = SERVICE_PORT;
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
	__u16 revnat_id = 1;
	struct lb6_key lb_svc_key = {};
	struct lb6_service lb_svc_value = {};
	struct lb6_reverse_nat revnat_value = {};
	struct lb6_backend backend = {};
	struct ipcache_key cache_key = {};
	struct remote_endpoint_info cache_value = {};
	struct endpoint_key ep_key = {};
	struct endpoint_info ep_value = {};
	/* Register a fake LB backend for our local redirect service */
	memcpy(&lb_svc_key.address, (__u8 *)V6_SERVICE_IP, sizeof(V6_SERVICE_IP));
	lb_svc_key.dport = SERVICE_PORT;
	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;
	/* Create a LRP service with one backend */
	lb_svc_value.count = 1;
	lb_svc_value.flags = SVC_FLAG_ROUTABLE;
	lb_svc_value.flags2 = SVC_FLAG_LOCALREDIRECT;
	lb_svc_value.rev_nat_index = revnat_id;
	map_update_elem(&LB6_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);
	/* Insert a reverse NAT entry for the above service */
	memcpy(&revnat_value.address, (__u8 *)V6_SERVICE_IP, sizeof(V6_SERVICE_IP));
	revnat_value.port = SERVICE_PORT;
	map_update_elem(&LB6_REVERSE_NAT_MAP, &revnat_id, &revnat_value, BPF_ANY);
	/* A backend between 1 and .count is chosen, since we have only one backend
	 * it is always backend_slot 1. Point it to backend_id 124.
	 */
	lb_svc_key.backend_slot = 1;
	lb_svc_value.backend_id = 124;
	map_update_elem(&LB6_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* Add the service in LB6_SKIP_MAP to skip service translation for request originating from the local backend */
	struct skip_lb6_key key = {
		.netns_cookie = ENDPOINT_NETNS_COOKIE,
		.port = SERVICE_PORT,
	};
	__u8 val = 0;

	memcpy(&key.address, (__u8 *)V6_SERVICE_IP, sizeof(V6_SERVICE_IP));
	map_update_elem(&LB6_SKIP_MAP, &key, &val, BPF_ANY);

	/* Create backend id 124 which contains the IP and port to send the
	 * packet to.
	 */
	memcpy(&backend.address, (__u8 *)V6_BACKEND_IP, sizeof(V6_BACKEND_IP));
	backend.port = BACKEND_PORT;
	backend.proto = IPPROTO_TCP;
	backend.flags = 0;
	map_update_elem(&LB6_BACKEND_MAP, &lb_svc_value.backend_id, &backend, BPF_ANY);
	/* Add an IPCache entry for pod 1 */
	cache_key.lpm_key.prefixlen = 32;
	cache_key.family = ENDPOINT_KEY_IPV6;
	memcpy(&cache_key.ip6, (__u8 *)V6_BACKEND_IP, sizeof(V6_BACKEND_IP));
	/* a random sec id for the pod */
	cache_value.sec_identity = 112233;
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);
	memcpy(&ep_key.ip6, (__u8 *)V6_BACKEND_IP, sizeof(V6_BACKEND_IP));
	ep_key.family = ENDPOINT_KEY_IPV6;
	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

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
