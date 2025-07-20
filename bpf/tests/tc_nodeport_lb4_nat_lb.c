// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_HOST_ROUTING
#define ENABLE_EGRESS_GATEWAY	1
#define ENABLE_MASQUERADE_IPV4	1

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)
#define CLIENT_IP_2		v4_ext_two
#define CLIENT_NODE_IP		v4_node_two

#define FRONTEND_IP_LOCAL	v4_svc_one
#define FRONTEND_IP_REMOTE	v4_svc_two
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_one
#define IPV4_DIRECT_ROUTING	LB_IP

#define BACKEND_IP_LOCAL	v4_pod_one
#define BACKEND_IP_REMOTE	v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define DEFAULT_IFACE		24
#define BACKEND_IFACE		25
#define SVC_EGRESS_IFACE	26
#define ENCAP_IFINDEX		42

#define BACKEND_EP_ID		127

#define fib_lookup mock_fib_lookup

static volatile const __u8 *client_mac = mac_one;
/* this matches the default node_config.h: */
static volatile const __u8 lb_mac[ETH_ALEN]	= { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 };
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *local_backend_mac = mac_four;
static volatile const __u8 *remote_backend_mac = mac_five;

__section_entry
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_REDIRECT;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[BACKEND_EP_ID] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

struct mock_settings {
	__be16 nat_source_port;
	bool fail_fib;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct mock_settings));
	__uint(max_entries, 1);
} settings_map __section_maps_btf;

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(__maybe_unused struct __ctx_buff * volatile ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	__u32 key = 0;
	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	/* Verifier doesn't know that params is not NULL when verifying this
	 * function separately (see btf_prepare_func_args in kernel/bpf/btf.c).
	 * There is no appropriate EINVAL-like error code in this helper, so
	 * return some arbitrary error.
	 */
	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;

	params->ifindex = DEFAULT_IFACE;

	if (params->ipv4_dst == BACKEND_IP_REMOTE) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)remote_backend_mac, ETH_ALEN);
	} else if (params->ipv4_src == FRONTEND_IP_LOCAL &&
		   params->ipv4_dst == CLIENT_IP_2) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
		params->ifindex = SVC_EGRESS_IFACE;
	} else {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
	}

	if (settings && settings->fail_fib)
		return BPF_FIB_LKUP_RET_NO_NEIGH;

	return 0;
}

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
	if (ip4->saddr == CLIENT_IP_2 && ifindex == BACKEND_IFACE)
		return CTX_ACT_REDIRECT;
	if (ip4->saddr == LB_IP && ifindex == DEFAULT_IFACE)
		return CTX_ACT_REDIRECT;

	/* Redirected reply: */
	if (ip4->daddr == CLIENT_IP_2 && ifindex == SVC_EGRESS_IFACE)
		return CTX_ACT_REDIRECT;
	if (ip4->saddr == FRONTEND_IP_REMOTE && ifindex == DEFAULT_IFACE)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_DROP;
}

#include "bpf_host.c"

#include "lib/egressgw_policy.h"
#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

#define FROM_NETDEV	0
#define TO_NETDEV	1

ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
		[TO_NETDEV] = &cil_to_netdev,
	},
};

/* Test that a SVC request to a local backend
 * - gets DNATed (but not SNATed)
 * - gets redirected by TC (as ENABLE_HOST_ROUTING is set)
 */
PKTGEN("tc", "tc_nodeport_local_backend")
int nodeport_local_backend_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP_LOCAL,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_local_backend")
int nodeport_local_backend_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP_LOCAL, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP_LOCAL, FRONTEND_PORT, 1, 124,
			  BACKEND_IP_LOCAL, BACKEND_PORT, IPPROTO_TCP, 0);

	/* add local backend */
	endpoint_v4_add_entry(BACKEND_IP_LOCAL, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)local_backend_mac, (__u8 *)node_mac);

	ipcache_v4_add_entry(BACKEND_IP_LOCAL, 0, 112233, 0, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_local_backend")
int nodeport_local_backend_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
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
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)local_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the endpoint MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP_LOCAL)
		test_fatal("dst IP hasn't been NATed to local backend IP");

	if (l3->check != bpf_htons(0x4212))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst TCP port hasn't been NATed to backend port");

	if (l4->check != bpf_htons(0xd7d0))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

/* Test that a reply by the local backend gets revDNATed at to-netdev. */
PKTGEN("tc", "tc_nodeport_local_backend_reply")
int nodeport_local_backend_reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)lb_mac, (__u8 *)client_mac,
					  BACKEND_IP_LOCAL, CLIENT_IP,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_local_backend_reply")
int nodeport_local_backend_reply_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_local_backend_reply")
int nodeport_local_backend_reply_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the client MAC")

	if (l3->saddr != FRONTEND_IP_LOCAL)
		test_fatal("src IP hasn't been revNATed to frontend IP");

	if (l3->daddr != CLIENT_IP)
		test_fatal("dst IP has changed");

	if (l3->check != bpf_htons(0x4baa))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source != FRONTEND_PORT)
		test_fatal("src port hasn't been revNATed to frontend port");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port has changed");

	if (l4->check != bpf_htons(0x01a9))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

/* Same scenario as above, but for a different CLIENT_IP_2. Here replies
 * should leave via a non-default interface.
 */
PKTGEN("tc", "tc_nodeport_local_backend_redirect")
int nodeport_local_backend_redirect_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP_2, FRONTEND_IP_LOCAL,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_local_backend_redirect")
int nodeport_local_backend_redirect_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_local_backend_redirect")
int nodeport_local_backend_redirect_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
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
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)local_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the endpoint MAC")

	if (l3->saddr != CLIENT_IP_2)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP_LOCAL)
		test_fatal("dst IP hasn't been NATed to local backend IP");

	if (l3->check != bpf_htons(0x3711))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst TCP port hasn't been NATed to backend port");

	if (l4->check != bpf_htons(0xcccf))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

/* Test that to-netdev respects the routing needed for CLIENT_IP_2,
 * and redirects the packet to the correct egress interface.
 */
PKTGEN("tc", "tc_nodeport_local_backend_redirect_reply")
int nodeport_local_backend_redirect_reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)lb_mac, (__u8 *)client_mac,
					  BACKEND_IP_LOCAL, CLIENT_IP_2,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_local_backend_redirect_reply")
int nodeport_local_backend_redirect_reply_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_local_backend_redirect_reply")
int nodeport_local_backend_redirect_reply_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
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
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the client MAC")

	if (l3->saddr != BACKEND_IP_LOCAL)
		test_fatal("src IP has changed");

	if (l3->daddr != CLIENT_IP_2)
		test_fatal("dst IP has changed");

	if (l3->check != bpf_htons(0x3611))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source != BACKEND_PORT)
		test_fatal("src port has changed");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port has changed");

	if (l4->check != bpf_htons(0xcccf))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

/* Test that a SVC request (UDP) to a local backend
 * - gets DNATed (but not SNATed)
 * - gets redirected by TC (as ENABLE_HOST_ROUTING is set)
 */
PKTGEN("tc", "tc_nodeport_udp_local_backend")
int nodeport_udp_local_backend_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP_LOCAL,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_udp_local_backend")
int nodeport_udp_local_backend_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	lb_v4_add_service(FRONTEND_IP_LOCAL, FRONTEND_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP_LOCAL, FRONTEND_PORT, 1, 125,
			  BACKEND_IP_LOCAL, BACKEND_PORT, IPPROTO_UDP, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_udp_local_backend")
int nodeport_udp_local_backend_check(const struct __ctx_buff *ctx)
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

	if (l3->check != bpf_htons(0x4213))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	if (l4->check != bpf_htons(0x699a))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

/* Test that a SVC request that is LBed to a NAT remote backend
 * - gets DNATed and SNATed,
 * - gets redirected back out by TC
 */
PKTGEN("tc", "tc_nodeport_nat_fwd")
int nodeport_nat_fwd_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP_REMOTE,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_nat_fwd")
int nodeport_nat_fwd_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP_REMOTE, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP_REMOTE, FRONTEND_PORT, 1, 124,
			  BACKEND_IP_REMOTE, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v4_add_entry(BACKEND_IP_REMOTE, 0, 112233, 0, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_nat_fwd")
int nodeport_nat_fwd_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 key = 0;

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
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)remote_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the remote backend MAC")

	if (l3->saddr != LB_IP)
		test_fatal("src IP hasn't been NATed to LB IP");

	if (l3->daddr != BACKEND_IP_REMOTE)
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (l3->check != bpf_htons(0xa711))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source == CLIENT_PORT)
		test_fatal("src port hasn't been NATed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		settings->nat_source_port = l4->source;

	test_finish();
}

static __always_inline int build_reply(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;
	__u16 nat_source_port = 0;
	__u32 key = 0;

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		nat_source_port = settings->nat_source_port;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)remote_backend_mac, (__u8 *)lb_mac,
					  BACKEND_IP_REMOTE, LB_IP,
					  BACKEND_PORT, nat_source_port);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

static __always_inline int check_reply(const struct __ctx_buff *ctx, bool check_l2)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
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
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (check_l2) {
		if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
			test_fatal("src MAC is not the LB MAC")
		if (memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) != 0)
			test_fatal("dst MAC is not the client MAC")
	}

	if (l3->saddr != FRONTEND_IP_REMOTE)
		test_fatal("src IP hasn't been RevNATed to frontend IP");

	if (l3->daddr != CLIENT_IP)
		test_fatal("dst IP hasn't been RevNATed to client IP");

	if (l4->source != FRONTEND_PORT)
		test_fatal("src port hasn't been RevNATed to frontend port");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port hasn't been RevNATed to client port");

	if (l4->check != bpf_htons(0x1a8))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

/* Test that the LB RevDNATs and RevSNATs a reply from the
 * NAT remote backend, and sends it back to the client.
 */
PKTGEN("tc", "tc_nodeport_nat_fwd_reply")
int nodeport_nat_fwd_reply_pktgen(struct __ctx_buff *ctx)
{
	return build_reply(ctx);
}

SETUP("tc", "tc_nodeport_nat_fwd_reply")
int nodeport_nat_fwd_reply_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_nat_fwd_reply")
int nodeport_nat_fwd_reply_check(const struct __ctx_buff *ctx)
{
	return check_reply(ctx, true);
}

/* Test that the LB RevDNATs and RevSNATs a reply from the
 * NAT remote backend, and sends it back to the client.
 * Even when there's a catch-all EGW policy configured.
 */
PKTGEN("tc", "tc_nodeport_nat_fwd_reply2_egw")
int nodeport_nat_fwd_reply2_egw_pktgen(struct __ctx_buff *ctx)
{
	return build_reply(ctx);
}

SETUP("tc", "tc_nodeport_nat_fwd_reply2_egw")
int nodeport_nat_fwd_reply2_egw_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(CLIENT_IP, 0, 112200, CLIENT_NODE_IP, 0);
	add_egressgw_policy_entry(CLIENT_IP, v4_all, 0, LB_IP, LB_IP);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_nat_fwd_reply2_egw")
int nodeport_nat_fwd_reply2_egw_check(const struct __ctx_buff *ctx)
{
	del_egressgw_policy_entry(CLIENT_IP, v4_all, 0);

	return check_reply(ctx, true);
}

/* Test that the LB RevDNATs and RevSNATs a reply from the
 * NAT remote backend, and sends it back to the client.
 * Even if the FIB lookup fails.
 */
PKTGEN("tc", "tc_nodeport_nat_fwd_reply_no_fib")
int nodepoirt_nat_fwd_reply_no_fib_pktgen(struct __ctx_buff *ctx)
{
	return build_reply(ctx);
}

SETUP("tc", "tc_nodeport_nat_fwd_reply_no_fib")
int nodeport_nat_fwd_reply_no_fib_setup(struct __ctx_buff *ctx)
{
	__u32 key = 0;
	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		settings->fail_fib = true;

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_nat_fwd_reply_no_fib")
int nodeport_nat_fwd_reply_no_fib_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Don't check L2 addresses, they get handled by redirect_neigh(). */
	return check_reply(ctx, false);
}

/* The following three tests are checking the scenario where a Rev NAT entry gets
 * deleted:
 * 1. The first reply gets punted to the kernel as its NAT lookup fails.
 * 2. The following request gets to the backend and restores the Rev NAT.
 * 3. The second reply gets back to the client normally.
 *
 *
 * Test that the LB fails to RevDNAT and RevSNAT a reply from the
 * NAT remote backend when its Rev NAT entry gets deleted
 */
PKTGEN("tc", "tc_nodeport_nat_fwd_reply_punt")
int nodeport_nat_fwd_reply_punt_pktgen(struct __ctx_buff *ctx)
{
	return build_reply(ctx);
}

SETUP("tc", "tc_nodeport_nat_fwd_reply_punt")
int nodeport_nat_fwd_reply_punt_setup(struct __ctx_buff *ctx)
{
	/* Delete the Rev NAT */
	__u16 nat_source_port = 0;
	__u32 key = 0;

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);
	struct ipv4_ct_tuple rtuple = {};

	if (settings)
		nat_source_port = settings->nat_source_port;

	rtuple.flags = TUPLE_F_IN;
	rtuple.saddr = BACKEND_IP_REMOTE;
	rtuple.daddr = LB_IP;
	rtuple.nexthdr = IPPROTO_TCP;
	rtuple.sport = BACKEND_PORT;
	rtuple.dport = nat_source_port;

	if IS_ERR(map_delete_elem(&cilium_snat_v4_external, &rtuple))
		return TEST_ERROR;

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_nat_fwd_reply_punt")
int nodeport_nat_fwd_reply_punt_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* On Rev NAT missing, the reply will be punted to the kernel */
	assert(*status_code == CTX_ACT_OK);

	test_finish();
}

/* Test that a SVC request that is LBed to a NAT remote backend
 * - gets DNATed and SNATed,
 * - gets redirected back out by TC
 */
PKTGEN("tc", "tc_nodeport_nat_fwd_restore")
int nodeport_nat_fwd_restore_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP_REMOTE,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_nat_fwd_restore")
int nodeport_nat_fwd_restore_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 3;
	__u32 key = 0;
	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	/* nodeport_nat_fwd_reply_no_fib set this to true which will cause
	 * the following forwarding path to fail, hence resetting it
	 */
	if (settings)
		settings->fail_fib = false;

	lb_v4_add_service(FRONTEND_IP_REMOTE, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP_REMOTE, FRONTEND_PORT, 1, 124,
			  BACKEND_IP_REMOTE, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v4_add_entry(BACKEND_IP_REMOTE, 0, 112233, 0, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_nat_fwd_restore")
int nodeport_nat_fwd_restore_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 key = 0;

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
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)remote_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the remote backend MAC")

	if (l3->saddr != LB_IP)
		test_fatal("src IP hasn't been NATed to LB IP");

	if (l3->daddr != BACKEND_IP_REMOTE)
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (l3->check != bpf_htons(0xa711))
		test_fatal("L3 checksum is invalid: %d", bpf_htons(l3->check));

	if (l4->source == CLIENT_PORT)
		test_fatal("src port hasn't been NATed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		settings->nat_source_port = l4->source;

	test_finish();
}

/* Test that the restored LB RevDNATs and RevSNATs a reply from the
 * NAT remote backend, and sends it back to the client.
 */
PKTGEN("tc", "tc_nodeport_nat_fwd_restore_reply")
int nodeport_nat_fwd_restore_reply_pktgen(struct __ctx_buff *ctx)
{
	return build_reply(ctx);
}

SETUP("tc", "tc_nodeport_nat_fwd_restore_reply")
int nodeport_nat_fwd_restore_reply_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_nat_fwd_restore_reply")
int nodeport_nat_fwd_restore_reply_check(const struct __ctx_buff *ctx)
{
	return check_reply(ctx, true);
}

 /* The following three tests are checking the scenario where a Original NAT entry gets deleted:
  * 1. The original packet gets ReSNATed when the entry is deleted.
  * 2. The reply packet restores the Original NAT entry if it is deleted.
  * 3. The original pakcket does not get ReSNATed. Because the Original NAT entry is restored.
  *
  *
  * Test that source port is changed when the Original NAT entry is deleted.(ReSNATed)
  */
PKTGEN("tc", "tc_nodeport_nat_fwd_original_renated")
int nodeport_nat_fwd_original_renated_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP_REMOTE,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_nat_fwd_original_renated")
int nodeport_nat_fwd_original_renated_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 4;
	struct ipv4_ct_tuple otuple = {};

	lb_v4_add_service(FRONTEND_IP_REMOTE, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP_REMOTE, FRONTEND_PORT, 1, 124,
			  BACKEND_IP_REMOTE, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v4_add_entry(BACKEND_IP_REMOTE, 0, 112233, 0, 0);

	otuple.flags = TUPLE_F_OUT;
	otuple.saddr = CLIENT_IP;
	otuple.daddr = BACKEND_IP_REMOTE;
	otuple.nexthdr = IPPROTO_TCP;
	otuple.sport = CLIENT_PORT;
	otuple.dport = BACKEND_PORT;

	/* Delete the Original NAT entry*/
	if IS_ERR(map_delete_elem(&cilium_snat_v4_external, &otuple))
		return TEST_ERROR;

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_nat_fwd_original_renated")
int nodeport_nat_fwd_original_renated_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 key = 0;
	__u16 nat_source_port = 0;

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
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)remote_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the remote backend MAC")

	if (l3->saddr != LB_IP)
		test_fatal("src IP hasn't been NATed to LB IP");

	if (l3->daddr != BACKEND_IP_REMOTE)
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (l3->check != bpf_htons(0xa711))
		test_fatal("L3 checksum is invalid: %d", bpf_htons(l3->check));

	if (l4->source == CLIENT_PORT)
		test_fatal("src port hasn't been NATed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		nat_source_port = settings->nat_source_port;

	if (l4->source == nat_source_port)
		test_fatal("src port hasn't been changed though original entry was deleted");

	if (settings)
		settings->nat_source_port = l4->source;

	test_finish();
}

/* Test that the restored LB RevDNATs and RevSNATs a reply from the
 * NAT remote backend, and sends it back to the client. And expects
 * the Original NAT entry to be restored.
 */
PKTGEN("tc", "tc_nodeport_nat_fwd_restore_original_entry")
int nodeport_nat_fwd_restore_original_entry_pktgen(struct __ctx_buff *ctx)
{
	return build_reply(ctx);
}

SETUP("tc", "tc_nodeport_nat_fwd_restore_original_entry")
int nodeport_nat_fwd_restore_original_entry_setup(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple otuple = {};

	otuple.flags = TUPLE_F_OUT;
	otuple.saddr = CLIENT_IP;
	otuple.daddr = BACKEND_IP_REMOTE;
	otuple.nexthdr = IPPROTO_TCP;
	otuple.sport = CLIENT_PORT;
	otuple.dport = BACKEND_PORT;

	/* Delete the Original NAT entry*/
	if IS_ERR(map_delete_elem(&cilium_snat_v4_external, &otuple))
		return TEST_ERROR;

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_nat_fwd_restore_original_entry")
int nodeport_nat_fwd_restore_original_entry_check(struct __ctx_buff *ctx)
{
	return check_reply(ctx, true);
}

/* Test that a SVC request that is LBed to a NAT remote backend
 * - gets DNATed and SNATed,
 * - gets redirected back out by TC
 * - verifies that the Original NAT entry is restored.
 */
PKTGEN("tc", "tc_nodeport_nat_fwd_verify_restored_original_entry")
int nodeport_nat_fwd_verify_restored_original_entry_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP_REMOTE,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_nat_fwd_verify_restored_original_entry")
int nodeport_nat_fwd_verify_restored_original_entry_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 5;

	lb_v4_add_service(FRONTEND_IP_REMOTE, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP_REMOTE, FRONTEND_PORT, 1, 124,
			  BACKEND_IP_REMOTE, BACKEND_PORT, IPPROTO_TCP, 0);
	ipcache_v4_add_entry(BACKEND_IP_REMOTE, 0, 112233, 0, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_nat_fwd_verify_restored_original_entry")
int nodeport_nat_fwd_verify_restored_original_entry_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 key = 0;
	__u16 nat_source_port = 0;

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
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)remote_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the remote backend MAC")

	if (l3->saddr != LB_IP)
		test_fatal("src IP hasn't been NATed to LB IP");

	if (l3->daddr != BACKEND_IP_REMOTE)
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (l3->check != bpf_htons(0xa711))
		test_fatal("L3 checksum is invalid: %d", bpf_htons(l3->check));

	if (l4->source == CLIENT_PORT)
		test_fatal("src port hasn't been NATed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		nat_source_port = settings->nat_source_port;

	if (l4->source != nat_source_port)
		test_fatal("Original NAT entry hasn't been restored");

	test_finish();
}
