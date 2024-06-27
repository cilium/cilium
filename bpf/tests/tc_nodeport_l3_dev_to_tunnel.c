// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

#define ETH_HLEN		0
#define SECCTX_FROM_IPCACHE	1
#define ENABLE_IPV4
#define ENABLE_IPV6
#define TUNNEL_MODE	1
#define ENCAP_IFINDEX	42
#define ENABLE_NODEPORT	1

#define TEST_IP_LOCAL		v4_pod_one
#define TEST_IP_REMOTE		v4_pod_two
#define TEST_IPV6_LOCAL		v6_pod_one

#define CLIENT_IP		v4_ext_one
#define CLIENT_IPV6		{ .addr = { 0x1, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_IPV6		{ .addr = { 0x5, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v4_pod_one
#define BACKEND_IPV6		{ .addr = { 0x3, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define BACKEND_PORT		__bpf_htons(8080)

#include "bpf_host.c"

static volatile const __u8 *node_mac = mac_two;

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[0] = &cil_from_netdev,
	},
};

PKTGEN("tc", "ipv4_tc_nodeport_l3_to_remote_backend_via_tunnel")
int ipv4_tc_nodeport_l3_to_remote_backend_via_tunnel(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* We are building an L3 skb which doesn't have L2 header, so in theory
	 * we need to skip L2 header and set ctx->protocol = bpf_ntohs(ETH_P_IP),
	 * but bpf verifier doesn't allow us to do so, and kernel also doesn't
	 * handle an L3 skb properly (see https://elixir.bootlin.com/linux/v6.2.1/source/net/bpf/test_run.c#L1156).
	 * Therefore we workaround the issue by pushing L2 header in the PKTGEN
	 * and stripping it in the SETUP.
	 */

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)node_mac, (__u8 *)node_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = FRONTEND_IP;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = FRONTEND_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "ipv4_tc_nodeport_l3_to_remote_backend_via_tunnel")
int ipv4_tc_nodeport_l3_to_remote_backend_via_tunnel_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;
	__u16 revnat_id = 1;

	/* Register a fake LB backend matching our packet. */
	struct lb4_key lb_svc_key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	/* Create a service with only one backend */
	struct lb4_service lb_svc_value = {
		.count = 1,
		.flags = SVC_FLAG_ROUTABLE,
		.rev_nat_index = revnat_id,
	};
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);
	/* We need to register both in the external and internal scopes for the
	 * packet to be redirected to a neighboring node
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* A backend between 1 and .count is chosen, since we have only one backend
	 * it is always backend_slot 1. Point it to backend_id 124.
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;
	lb_svc_key.backend_slot = 1;
	lb_svc_value.backend_id = 124;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* Insert a reverse NAT entry for the above service */
	struct lb4_reverse_nat revnat_value = {
		.address = FRONTEND_IP,
		.port = FRONTEND_PORT,
	};
	map_update_elem(&LB4_REVERSE_NAT_MAP, &revnat_id, &revnat_value, BPF_ANY);

	/* Create backend id 124 which contains the IP and port to send the
	 * packet to.
	 */
	struct lb4_backend backend = {
		.address = BACKEND_IP,
		.port = BACKEND_PORT,
		.proto = IPPROTO_TCP,
		.flags = BE_STATE_ACTIVE,
	};
	map_update_elem(&LB4_BACKEND_MAP, &lb_svc_value.backend_id, &backend, BPF_ANY);

	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(V4_CACHE_KEY_LEN),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};
	struct remote_endpoint_info cache_value = {
		.sec_identity = 112233,
		.tunnel_endpoint = TEST_IP_REMOTE,
	};
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	/* As commented in PKTGEN, now we strip the L2 header. Bpf helper
	 * skb_adjust_room will use L2 header to overwrite L3 header, so we play
	 * a trick to memcpy(ethhdr, iphdr, ETH_HLEN) ahead of skb_adjust_room
	 * so as to guarantee L3 header keeps intact.
	 */
	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);

	tail_call_static(ctx, &entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "ipv4_tc_nodeport_l3_to_remote_backend_via_tunnel")
int ipv4_tc_nodeport_l3_to_remote_backend_via_tunnel_check(__maybe_unused
							   const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Check that LB request got redirected (to a tunnel iface) */
	assert(*status_code == TC_ACT_REDIRECT);

	/* Check that L2 hdr was added */
	l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 proto hasn't been set to ETH_P_IP");

	test_finish();
}

PKTGEN("tc", "ipv6_tc_nodeport_l3_to_remote_backend_via_tunnel")
int ipv6_tc_nodeport_l3_to_remote_backend_via_tunnel(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IPV6;
	union v6addr client_ip = CLIENT_IPV6;
	struct pktgen builder;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	struct ethhdr *l2;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* We are building an L3 skb which doesn't have L2 header, so in theory
	 * we need to skip L2 header and set ctx->protocol = bpf_ntohs(ETH_P_IP),
	 * but bpf verifier doesn't allow us to do so, and kernel also doesn't
	 * handle an L3 skb properly (see https://elixir.bootlin.com/linux/v6.2.1/source/net/bpf/test_run.c#L1156).
	 * Therefore we workaround the issue by pushing L2 header in the PKTGEN
	 * and stripping it in the SETUP.
	 */

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)node_mac, (__u8 *)node_mac);

	/* Push IPv6 header */
	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;

	ipv6_addr_copy((union v6addr *)&l3->saddr, &client_ip);
	ipv6_addr_copy((union v6addr *)&l3->daddr, &frontend_ip);

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = FRONTEND_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "ipv6_tc_nodeport_l3_to_remote_backend_via_tunnel")
int ipv6_tc_nodeport_l3_to_remote_backend_via_tunnel_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IPV6;
	union v6addr backend_ip = BACKEND_IPV6;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;
	__u16 revnat_id = 1;

	/* Register a fake LB backend matching our packet. */
	struct lb6_key lb_svc_key = {
		.dport = FRONTEND_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	ipv6_addr_copy((union v6addr *)&lb_svc_key.address, &frontend_ip);

	/* Create a service with only one backend */
	struct lb6_service lb_svc_value = {
		.count = 1,
		.flags = SVC_FLAG_ROUTABLE,
		.rev_nat_index = revnat_id,
	};
	map_update_elem(&LB6_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);
	/* We need to register both in the external and internal scopes for the
	 * packet to be redirected to a neighboring node
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_update_elem(&LB6_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* A backend between 1 and .count is chosen, since we have only one backend
	 * it is always backend_slot 1. Point it to backend_id 124.
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;
	lb_svc_key.backend_slot = 1;
	lb_svc_value.backend_id = 124;
	map_update_elem(&LB6_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* Insert a reverse NAT entry for the above service */
	struct lb6_reverse_nat revnat_value = {
		.port = FRONTEND_PORT,
	};
	ipv6_addr_copy((union v6addr *)&revnat_value.address, &frontend_ip);

	map_update_elem(&LB6_REVERSE_NAT_MAP, &revnat_id, &revnat_value, BPF_ANY);

	/* Create backend id 124 which contains the IP and port to send the
	 * packet to.
	 */
	struct lb6_backend backend = {
		.port = BACKEND_PORT,
		.proto = IPPROTO_TCP,
		.flags = BE_STATE_ACTIVE,
	};
	ipv6_addr_copy((union v6addr *)&backend.address, &backend_ip);

	map_update_elem(&LB6_BACKEND_MAP, &lb_svc_value.backend_id, &backend, BPF_ANY);

	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(V6_CACHE_KEY_LEN),
		.family = ENDPOINT_KEY_IPV6,
	};
	ipv6_addr_copy((union v6addr *)&cache_key.ip6, &backend_ip);

	struct remote_endpoint_info cache_value = {
		.sec_identity = 112233,
		.tunnel_endpoint = TEST_IP_REMOTE,
	};
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	/* As commented in PKTGEN, now we strip the L2 header. Bpf helper
	 * skb_adjust_room will use L2 header to overwrite L3 header, so we play
	 * a trick to memcpy(ethhdr, iphdr, ETH_HLEN) ahead of skb_adjust_room
	 * so as to guarantee L3 header keeps intact.
	 */
	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);

	tail_call_static(ctx, &entry_call_map, 0);
	return TEST_ERROR;
}

CHECK("tc", "ipv6_tc_nodeport_l3_to_remote_backend_via_tunnel")
int ipv6_tc_nodeport_l3_to_remote_backend_via_tunnel_check(__maybe_unused
							   const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Check that LB request got redirected (to a tunnel iface) */
	assert(*status_code == TC_ACT_REDIRECT);

	/* Check that L2 hdr was added */
	l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IPV6");

	test_finish();
}
