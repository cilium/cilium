// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test */
#define ENABLE_IPV4		1
#define ENABLE_NODEPORT		1
#define ENABLE_HOST_ROUTING	1

#define DISABLE_LOOPBACK_LB	1

/* Skip ingress policy checks, not needed to validate hairpin flow */
#define USE_BPF_PROG_FOR_INGRESS_POLICY
#undef FORCE_LOCAL_POLICY_EVAL_AT_SOURCE

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP_LOCAL	v4_svc_one
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_one
#define IPV4_DIRECT_ROUTING	LB_IP

#define BACKEND_IP_LOCAL	v4_pod_one
#define BACKEND_PORT		__bpf_htons(8080)

#define NATIVE_DEV_IFINDEX	24
#define DEFAULT_IFACE		NATIVE_DEV_IFINDEX
#define BACKEND_IFACE		25

#define SVC_REV_NAT_ID		2

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

static volatile const __u8 *client_mac = mac_one;
/* this matches the default node_config.h: */
static volatile const __u8 lb_mac[ETH_ALEN]	= { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 };
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *local_backend_mac = mac_four;

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip4;

	ip4 = data + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		return CTX_ACT_DROP;

	/* Forward to backend: */
	if (ip4->saddr == CLIENT_IP && ifindex == BACKEND_IFACE)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_DROP;
}

#define SECCTX_FROM_IPCACHE 1

#include "config_replacement.h"

#include "bpf_host.c"

#define FROM_NETDEV	0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
	},
};

/* Test that a SVC request (UDP) to a local backend
 * - gets DNATed (but not SNATed)
 * - gets redirected by TC (as ENABLE_HOST_ROUTING is set)
 */
PKTGEN("tc", "tc_nodeport_lb_terminating_backend_0")
int tc_nodeport_lb_terminating_backend_0_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = FRONTEND_IP_LOCAL;

	/* Push UDP header */
	l4 = pktgen__push_default_udphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = FRONTEND_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb_terminating_backend_0")
int tc_nodeport_lb_terminating_backend_0_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = SVC_REV_NAT_ID;
	__u32 backend_id = 125;

	struct lb4_key svc_key = {
		.address = FRONTEND_IP_LOCAL,
		.dport = FRONTEND_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	struct lb4_service svc_value = {
		.count = 1,
		.flags = SVC_FLAG_ROUTABLE,
		.rev_nat_index = revnat_id,
	};
	map_update_elem(&LB4_SERVICES_MAP_V2, &svc_key, &svc_value, BPF_ANY);
	/* Register with both scopes: */
	svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_update_elem(&LB4_SERVICES_MAP_V2, &svc_key, &svc_value, BPF_ANY);

	/* Insert a reverse NAT entry for the above service */
	struct lb4_reverse_nat revnat_value = {
		.address = FRONTEND_IP_LOCAL,
		.port = FRONTEND_PORT,
	};
	map_update_elem(&LB4_REVERSE_NAT_MAP, &revnat_id, &revnat_value, BPF_ANY);

	/* Create the actual backend: */
	struct lb4_backend backend = {
		.address = BACKEND_IP_LOCAL,
		.port = BACKEND_PORT,
		.proto = IPPROTO_UDP,
		.flags = BE_STATE_ACTIVE,
		.cluster_id = 0,
	};

	map_update_elem(&LB4_BACKEND_MAP, &backend_id, &backend, BPF_ANY);

	struct lb4_key backend_key = {
		.address = FRONTEND_IP_LOCAL,
		.dport = FRONTEND_PORT,
		.backend_slot = 1,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};

	struct lb4_service backend_value = {
		.backend_id = backend_id,
		.flags = SVC_FLAG_ROUTABLE,
	};
	/* Point the service's backend_slot at the created backend: */
	map_update_elem(&LB4_SERVICES_MAP_V2, &backend_key, &backend_value, BPF_ANY);

	/* add local backend */
	struct endpoint_key endpoint_key = {
		.ip4 = BACKEND_IP_LOCAL,
		.family = ENDPOINT_KEY_IPV4,
	};
	struct endpoint_info endpoint_value = {
		.ifindex = BACKEND_IFACE,
		.lxc_id = 0,
		.flags = 0,
	};

	memcpy(&endpoint_value.mac, (__u8 *)local_backend_mac, ETH_ALEN);
	memcpy(&endpoint_value.node_mac, (__u8 *)node_mac, ETH_ALEN);

	map_update_elem(&ENDPOINTS_MAP, &endpoint_key, &endpoint_value, BPF_ANY);

	struct ipcache_key ipcache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(V4_CACHE_KEY_LEN),
		.cluster_id = 0,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP_LOCAL,
	};
	struct remote_endpoint_info ipcache_value = {
		.sec_identity = 112233,
	};

	map_update_elem(&IPCACHE_MAP, &ipcache_key, &ipcache_value, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_lb_terminating_backend_0")
int tc_nodeport_lb_terminating_backend_0_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)local_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the endpoint MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP_LOCAL)
		test_fatal("dst IP hasn't been NATed to local backend IP");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	test_finish();
}

/* Test that a second request gets LBed to a terminating backend,
 * even when the service has no active backends remaining.
 */
PKTGEN("tc", "tc_nodeport_lb_terminating_backend_1")
int tc_nodeport_lb_terminating_backend_1_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);


	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = FRONTEND_IP_LOCAL;

	/* Push UDP header */
	l4 = pktgen__push_default_udphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = FRONTEND_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb_terminating_backend_1")
int tc_nodeport_lb_terminating_backend_1_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = SVC_REV_NAT_ID;
	__u32 backend_id = 125;

	/* Remove the service's last backend, and flip the backend to
	 * 'terminating' state.
	 */
	struct lb4_key svc_key = {
		.address = FRONTEND_IP_LOCAL,
		.dport = FRONTEND_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	struct lb4_service svc_value = {
		.count = 0,
		.flags = SVC_FLAG_ROUTABLE,
		.rev_nat_index = revnat_id,
	};
	map_update_elem(&LB4_SERVICES_MAP_V2, &svc_key, &svc_value, BPF_ANY);
	/* Register with both scopes: */
	svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_update_elem(&LB4_SERVICES_MAP_V2, &svc_key, &svc_value, BPF_ANY);

	struct lb4_backend backend = {
		.address = BACKEND_IP_LOCAL,
		.port = BACKEND_PORT,
		.proto = IPPROTO_UDP,
		.flags = BE_STATE_TERMINATING,
		.cluster_id = 0,
	};

	map_update_elem(&LB4_BACKEND_MAP, &backend_id, &backend, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_lb_terminating_backend_1")
int tc_nodeport_lb_terminating_backend_1_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)local_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the endpoint MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP_LOCAL)
		test_fatal("dst IP hasn't been NATed to local backend IP");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	test_finish();
}
