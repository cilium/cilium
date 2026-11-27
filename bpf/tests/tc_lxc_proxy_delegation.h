/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* With L7 LB disabled, delegated Services must retain their frontend address
 * and port on pod egress. Ordinary Services must still translate to a backend.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1

#define CLIENT_IP	v4_pod_one
#define CLIENT_IPV6	v6_pod_one
#define FRONTEND_IP	v4_svc_one
#define FRONTEND_IPV6	v6_svc_one
#define BACKEND_IP	v4_node_one
#define BACKEND_IPV6	v6_node_one
#define BACKEND_PORT	__bpf_htons(8080)

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(bool, enable_ipv4, true)
ASSIGN_CONFIG(bool, enable_ipv6, true)
ASSIGN_CONFIG(bool, enable_l7_lb, false)
ASSIGN_CONFIG(bool, enable_nodeport, true)
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = CLIENT_IP })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })

#include "lib/lb.h"
#include "lib/policy.h"

/* Separate ports keep the delegated and ordinary Service flows independent. */
static __always_inline int
proxy_delegation_pktgen(struct __ctx_buff *ctx, bool ipv4, bool delegated)
{
	__be16 source_port = delegated ? tcp_src_one : tcp_src_two;
	__be16 service_port = delegated ? tcp_svc_one : tcp_svc_two;
	struct pktgen builder;
	struct tcphdr *tcp;

	pktgen__init(&builder, ctx);
	if (ipv4)
		tcp = pktgen__push_ipv4_tcp_packet(&builder, (__u8 *)mac_one,
						 (__u8 *)mac_two, CLIENT_IP, FRONTEND_IP,
						 source_port, service_port);
	else
		tcp = pktgen__push_ipv6_tcp_packet(&builder, (__u8 *)mac_one,
						 (__u8 *)mac_two, (__u8 *)CLIENT_IPV6,
						 (__u8 *)FRONTEND_IPV6, source_port,
						 service_port);
	if (!tcp)
		return TEST_ERROR;
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;
	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
proxy_delegation_setup(struct __ctx_buff *ctx, bool ipv4, bool delegated)
{
	__be16 service_port = delegated ? tcp_svc_one : tcp_svc_two;
	__u8 flags2 = delegated ? SVC_FLAG_L7_DELEGATE : 0;
	__u16 revnat_id = delegated ? 1 : 2;

	policy_add_egress_allow_all_entry();
	if (ipv4) {
		lb_v4_add_service_with_flags(FRONTEND_IP, service_port, IPPROTO_TCP,
					     1, revnat_id,
					     SVC_FLAG_ROUTABLE | SVC_FLAG_LOADBALANCER,
					     flags2);
		lb_v4_add_backend(FRONTEND_IP, service_port, 1, revnat_id,
				  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);
	} else {
		lb_v6_add_service_with_flags((union v6addr *)FRONTEND_IPV6, service_port,
					     IPPROTO_TCP, 1, revnat_id,
					     SVC_FLAG_ROUTABLE | SVC_FLAG_LOADBALANCER,
					     flags2);
		lb_v6_add_backend((union v6addr *)FRONTEND_IPV6, service_port, 1, revnat_id,
				  (union v6addr *)BACKEND_IPV6, BACKEND_PORT, IPPROTO_TCP, 0);
	}

	return pod_send_packet(ctx);
}

static __always_inline int
proxy_delegation_check(const struct __ctx_buff *ctx, bool ipv4, bool delegated)
{
	__be16 source_port = delegated ? tcp_src_one : tcp_src_two;
	__be16 service_port = delegated ? tcp_svc_one : tcp_svc_two;
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	__u32 *status_code = data;
	struct ethhdr *eth;
	struct tcphdr *tcp;
	const void *payload;
	struct ct_entry *entry;

	test_init();

	assert((void *)(status_code + 1) <= data_end);
	assert(*status_code == CTX_ACT_OK);

	eth = (void *)(status_code + 1);
	assert((void *)(eth + 1) <= data_end);

	if (ipv4) {
		struct iphdr *ip4 = (void *)(eth + 1);
		struct ipv4_ct_tuple tuple = {
			.saddr = CLIENT_IP,
			.daddr = FRONTEND_IP,
			.sport = service_port,
			.dport = source_port,
			.nexthdr = IPPROTO_TCP,
			.flags = TUPLE_F_SERVICE,
		};

		assert(eth->h_proto == bpf_htons(ETH_P_IP));
		assert((void *)(ip4 + 1) <= data_end);
		assert(ip4->saddr == CLIENT_IP);
		assert(ip4->daddr == (delegated ? FRONTEND_IP : BACKEND_IP));
		tcp = (void *)(ip4 + 1);
		entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	} else {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		struct ipv6_ct_tuple tuple = {
			.sport = service_port,
			.dport = source_port,
			.nexthdr = IPPROTO_TCP,
			.flags = TUPLE_F_SERVICE,
		};

		assert(eth->h_proto == bpf_htons(ETH_P_IPV6));
		assert((void *)(ip6 + 1) <= data_end);
		assert(!memcmp(&ip6->saddr, (const __u8 *)CLIENT_IPV6, sizeof(ip6->saddr)));
		if (delegated) {
			assert(!memcmp(&ip6->daddr, (const __u8 *)FRONTEND_IPV6,
				       sizeof(ip6->daddr)));
		} else {
			assert(!memcmp(&ip6->daddr, (const __u8 *)BACKEND_IPV6,
				       sizeof(ip6->daddr)));
		}
		tcp = (void *)(ip6 + 1);
		memcpy(&tuple.saddr, (const __u8 *)CLIENT_IPV6, sizeof(tuple.saddr));
		memcpy(&tuple.daddr, (const __u8 *)FRONTEND_IPV6, sizeof(tuple.daddr));
		entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	}

	/* Delegation must skip backend selection and Service conntrack creation. */
	assert(!!entry == !delegated);
	assert((void *)(tcp + 1) <= data_end);
	assert(tcp->source == source_port);
	assert(tcp->dest == (delegated ? service_port : BACKEND_PORT));
	payload = tcp + 1;
	assert(payload + sizeof(default_data) <= data_end);
	assert(!memcmp(payload, default_data, sizeof(default_data)));

	test_finish();
}

PKTGEN(PROG_TYPE, "ipv4_proxy_delegation")
int ipv4_proxy_delegation_pktgen(struct __ctx_buff *ctx)
{
	return proxy_delegation_pktgen(ctx, true, true);
}

SETUP(PROG_TYPE, "ipv4_proxy_delegation")
int ipv4_proxy_delegation_setup(struct __ctx_buff *ctx)
{
	return proxy_delegation_setup(ctx, true, true);
}

CHECK(PROG_TYPE, "ipv4_proxy_delegation")
int ipv4_proxy_delegation_check(const struct __ctx_buff *ctx)
{
	return proxy_delegation_check(ctx, true, true);
}

PKTGEN(PROG_TYPE, "ipv4_service_translation")
int ipv4_service_translation_pktgen(struct __ctx_buff *ctx)
{
	return proxy_delegation_pktgen(ctx, true, false);
}

SETUP(PROG_TYPE, "ipv4_service_translation")
int ipv4_service_translation_setup(struct __ctx_buff *ctx)
{
	return proxy_delegation_setup(ctx, true, false);
}

CHECK(PROG_TYPE, "ipv4_service_translation")
int ipv4_service_translation_check(const struct __ctx_buff *ctx)
{
	return proxy_delegation_check(ctx, true, false);
}

PKTGEN(PROG_TYPE, "ipv6_proxy_delegation")
int ipv6_proxy_delegation_pktgen(struct __ctx_buff *ctx)
{
	return proxy_delegation_pktgen(ctx, false, true);
}

SETUP(PROG_TYPE, "ipv6_proxy_delegation")
int ipv6_proxy_delegation_setup(struct __ctx_buff *ctx)
{
	return proxy_delegation_setup(ctx, false, true);
}

CHECK(PROG_TYPE, "ipv6_proxy_delegation")
int ipv6_proxy_delegation_check(const struct __ctx_buff *ctx)
{
	return proxy_delegation_check(ctx, false, true);
}

PKTGEN(PROG_TYPE, "ipv6_service_translation")
int ipv6_service_translation_pktgen(struct __ctx_buff *ctx)
{
	return proxy_delegation_pktgen(ctx, false, false);
}

SETUP(PROG_TYPE, "ipv6_service_translation")
int ipv6_service_translation_setup(struct __ctx_buff *ctx)
{
	return proxy_delegation_setup(ctx, false, false);
}

CHECK(PROG_TYPE, "ipv6_service_translation")
int ipv6_service_translation_check(const struct __ctx_buff *ctx)
{
	return proxy_delegation_check(ctx, false, false);
}
