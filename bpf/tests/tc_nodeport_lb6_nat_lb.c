// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_HOST_ROUTING

#define CLIENT_IP		{ .addr = v6_ext_node_one_addr }
#define CLIENT_PORT		__bpf_htons(111)
#define CLIENT_IP_2		{ .addr = v6_ext_node_two_addr }

#define FRONTEND_IP_LOCAL	{ .addr = v6_svc_one_addr }
#define FRONTEND_IP_REMOTE	{ .addr = v6_svc_two_addr }
#define FRONTEND_IP_REMOTE_2	{ .addr = v6_svc_three_addr }
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			{ .addr = v6_node_one_addr }
#define IPV6_DIRECT_ROUTING	LB_IP

#define BACKEND_IP_LOCAL	{ .addr = v6_pod_one_addr }
#define BACKEND_IP_REMOTE	{ .addr = v6_pod_two_addr }
#define BACKEND_PORT		__bpf_htons(8080)

#define DEFAULT_IFACE		24
#define BACKEND_IFACE		25
#define SVC_EGRESS_IFACE	26

#define BACKEND_EP_ID		127

#define fib_lookup mock_fib_lookup

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;
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
	const union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	const union v6addr frontend_ip_local = FRONTEND_IP_LOCAL;
	const union v6addr client_ip_2 = CLIENT_IP_2;
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

	if (memcmp(params->ipv6_dst, &backend_ip_remote, sizeof(backend_ip_remote)) == 0) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)remote_backend_mac, ETH_ALEN);
	} else if (memcmp(params->ipv6_src, &frontend_ip_local, sizeof(frontend_ip_local)) == 0 &&
		   memcmp(params->ipv6_dst, &client_ip_2, sizeof(client_ip_2)) == 0) {
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
	const union v6addr client_ip = CLIENT_IP;
	const union v6addr client_ip_2 = CLIENT_IP_2;
	const union v6addr lb_ip = LB_IP;
	const union v6addr frontend_ip_remote = FRONTEND_IP_REMOTE;
	const union v6addr frontend_ip_remote_2 = FRONTEND_IP_REMOTE_2;
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ip6;

	ip6 = data + sizeof(struct ethhdr);
	if ((void *)ip6 + sizeof(*ip6) > data_end)
		return CTX_ACT_DROP;

	/* Forward to backend: */
	if (memcmp(&ip6->saddr, &client_ip, sizeof(client_ip)) == 0 && ifindex == BACKEND_IFACE)
		return CTX_ACT_REDIRECT;
	if (memcmp(&ip6->saddr, &client_ip_2, sizeof(client_ip_2)) == 0 && ifindex == BACKEND_IFACE)
		return CTX_ACT_REDIRECT;
	if (memcmp(&ip6->saddr, &lb_ip, sizeof(lb_ip)) == 0 && ifindex == DEFAULT_IFACE)
		return CTX_ACT_REDIRECT;

	/* Redirected reply: */
	if (memcmp(&ip6->daddr, &client_ip_2, sizeof(client_ip_2)) == 0 && ifindex == SVC_EGRESS_IFACE)
		return CTX_ACT_REDIRECT;
	if (memcmp(&ip6->saddr, &frontend_ip_remote, sizeof(frontend_ip_remote)) == 0 && ifindex == DEFAULT_IFACE)
		return CTX_ACT_REDIRECT;
	if (memcmp(&ip6->saddr, &frontend_ip_remote_2, sizeof(frontend_ip_remote_2)) == 0 && ifindex == DEFAULT_IFACE)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_DROP;
}

#include "lib/bpf_host.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)

/* Set port ranges to have deterministic source port selection */
#include "nodeport_defaults.h"

/* Test that a SVC request to a local backend
 * - gets DNATed (but not SNATed)
 * - gets redirected by TC (as ENABLE_HOST_ROUTING is set)
 */
PKTGEN("tc", "tc_nodeport_local_backend")
int nodeport_local_backend_pktgen(struct __ctx_buff *ctx)
{
	union v6addr client_ip = CLIENT_IP;
	union v6addr frontend_ip_local = FRONTEND_IP_LOCAL;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)&client_ip, (__u8 *)&frontend_ip_local,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_local_backend")
int nodeport_local_backend_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip_local = FRONTEND_IP_LOCAL;
	union v6addr backend_ip_local = BACKEND_IP_LOCAL;
	__u16 revnat_id = 1;

	lb_v6_add_service(&frontend_ip_local, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip_local, FRONTEND_PORT, 1, 124,
			  &backend_ip_local, BACKEND_PORT, IPPROTO_TCP, 0);

	endpoint_v6_add_entry(&backend_ip_local, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)local_backend_mac, (__u8 *)node_mac);

	ipcache_v6_add_entry(&backend_ip_local, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_local_backend")
int nodeport_local_backend_check(const struct __ctx_buff *ctx)
{
	union v6addr client_ip = CLIENT_IP;
	union v6addr backend_ip_local = BACKEND_IP_LOCAL;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	struct ethhdr *l2;

	test_init();

	endpoint_v6_del_entry(&backend_ip_local);

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
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)local_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the endpoint MAC")

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip))
		test_fatal("src IP has changed");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip_local))
		test_fatal("dst IP hasn't been NATed to local backend IP");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst TCP port hasn't been NATed to backend port");

	if (l4->check != bpf_htons(0x5414))
		test_fatal("L4 checksum is invalid: %x != %x", l4->check, bpf_htons(0x5414));

	test_finish();
}

/* Test that a reply by the local backend gets revDNATed at to-netdev. */
PKTGEN("tc", "tc_nodeport_local_backend_reply")
int nodeport_local_backend_reply_pktgen(struct __ctx_buff *ctx)
{
	union v6addr backend_ip_local = BACKEND_IP_LOCAL;
	union v6addr client_ip = CLIENT_IP;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)lb_mac, (__u8 *)client_mac,
					  (__u8 *)&backend_ip_local, (__u8 *)&client_ip,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_local_backend_reply")
int nodeport_local_backend_reply_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_nodeport_local_backend_reply")
int nodeport_local_backend_reply_check(const struct __ctx_buff *ctx)
{
	union v6addr frontend_ip_local = FRONTEND_IP_LOCAL;
	union v6addr client_ip = CLIENT_IP;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	struct ethhdr *l2;

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
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the client MAC")

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &frontend_ip_local))
		test_fatal("src IP hasn't been RevNATed to frontend IP");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &client_ip))
		test_fatal("dst IP has changed");

	if (l4->source != FRONTEND_PORT)
		test_fatal("src port hasn't been RevNATed to frontend port");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port has changed");

	if (l4->check != bpf_htons(0x7348))
		test_fatal("L4 checksum is invalid: %x != %x", l4->check, bpf_htons(0x7348));

	test_finish();
}

/* Same scenario as above, but for a different CLIENT_IP_2. Here replies
 * should leave via a non-default interface.
 */
PKTGEN("tc", "tc_nodeport_local_backend_redirect")
int nodeport_local_backend_redirect_pktgen(struct __ctx_buff *ctx)
{
	union v6addr client_ip_2 = CLIENT_IP_2;
	union v6addr frontend_ip_local = FRONTEND_IP_LOCAL;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)&client_ip_2, (__u8 *)&frontend_ip_local,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_local_backend_redirect")
int nodeport_local_backend_redirect_setup(struct __ctx_buff *ctx)
{
	union v6addr backend_ip_local = BACKEND_IP_LOCAL;

	endpoint_v6_add_entry(&backend_ip_local, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)local_backend_mac, (__u8 *)node_mac);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_local_backend_redirect")
int nodeport_local_backend_redirect_check(const struct __ctx_buff *ctx)
{
	union v6addr client_ip_2 = CLIENT_IP_2;
	union v6addr backend_ip_local = BACKEND_IP_LOCAL;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	struct ethhdr *l2;

	test_init();

	endpoint_v6_del_entry(&backend_ip_local);

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
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)local_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the endpoint MAC")

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip_2))
		test_fatal("src IP has changed");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip_local))
		test_fatal("dst IP hasn't been NATed to local backend IP");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst TCP port hasn't been NATed to backend port");

	if (l4->check != bpf_htons(0x5413))
		test_fatal("L4 checksum is invalid: %x != %x", l4->check, bpf_htons(0x5413));

	test_finish();
}

/* Test that to-netdev respects the routing needed for CLIENT_IP_2,
 * and redirects the packet to the correct egress interface.
 */
PKTGEN("tc", "tc_nodeport_local_backend_redirect_reply")
int nodeport_local_backend_redirect_reply_pktgen(struct __ctx_buff *ctx)
{
	union v6addr backend_ip_local = BACKEND_IP_LOCAL;
	union v6addr client_ip_2 = CLIENT_IP_2;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)lb_mac, (__u8 *)client_mac,
					  (__u8 *)&backend_ip_local, (__u8 *)&client_ip_2,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_local_backend_redirect_reply")
int nodeport_local_backend_redirect_reply_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_nodeport_local_backend_redirect_reply")
int nodeport_local_backend_redirect_reply_check(const struct __ctx_buff *ctx)
{
	union v6addr backend_ip_local = BACKEND_IP_LOCAL;
	union v6addr client_ip_2 = CLIENT_IP_2;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	struct ethhdr *l2;

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
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the client MAC")

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &backend_ip_local))
		test_fatal("src IP has changed");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &client_ip_2))
		test_fatal("dst IP has changed");

	if (l4->source != BACKEND_PORT)
		test_fatal("src port has changed");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port has changed");

	if (l4->check != bpf_htons(0x5413))
		test_fatal("L4 checksum is invalid: %x != %x", l4->check, bpf_htons(0x5413));

	test_finish();
}

/* Test that a SVC request (UDP) to a local backend
 * - gets DNATed (but not SNATed)
 * - gets redirected by TC (as ENABLE_HOST_ROUTING is set)
 */
PKTGEN("tc", "tc_nodeport_udp_local_backend")
int nodeport_udp_local_backend_pktgen(struct __ctx_buff *ctx)
{
	union v6addr client_ip = CLIENT_IP;
	union v6addr frontend_ip_local = FRONTEND_IP_LOCAL;
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_udp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)&client_ip, (__u8 *)&frontend_ip_local,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_udp_local_backend")
int nodeport_udp_local_backend_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip_local = FRONTEND_IP_LOCAL;
	union v6addr backend_ip_local = BACKEND_IP_LOCAL;
	__u16 revnat_id = 2;

	endpoint_v6_add_entry(&backend_ip_local, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)local_backend_mac, (__u8 *)node_mac);

	lb_v6_add_service(&frontend_ip_local, FRONTEND_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip_local, FRONTEND_PORT, 1, 125,
			  &backend_ip_local, BACKEND_PORT, IPPROTO_UDP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_udp_local_backend")
int nodeport_udp_local_backend_check(const struct __ctx_buff *ctx)
{
	union v6addr client_ip = CLIENT_IP;
	union v6addr backend_ip_local = BACKEND_IP_LOCAL;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct udphdr *l4;
	struct ethhdr *l2;

	test_init();

	endpoint_v6_del_entry(&backend_ip_local);

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
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)local_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the endpoint MAC")

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip))
		test_fatal("src IP has changed");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip_local))
		test_fatal("dst IP hasn't been NATed to local backend IP");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	if (l4->check != bpf_htons(0x863d))
		test_fatal("L4 checksum is invalid: %x != %x", l4->check, bpf_htons(0x863d));

	test_finish();
}

/* Test that a SVC request that is LBed to a NAT remote backend
 * - gets DNATed and SNATed,
 * - gets redirected back out by TC
 */
PKTGEN("tc", "tc_nodeport_nat_fwd")
int nodeport_nat_fwd_pktgen(struct __ctx_buff *ctx)
{
	union v6addr client_ip = CLIENT_IP;
	union v6addr frontend_ip_remote = FRONTEND_IP_REMOTE;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)&client_ip, (__u8 *)&frontend_ip_remote,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_nat_fwd")
int nodeport_nat_fwd_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip_remote = FRONTEND_IP_REMOTE;
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	__u16 revnat_id = 1;

	lb_v6_add_service(&frontend_ip_remote, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip_remote, FRONTEND_PORT, 1, 124,
			  &backend_ip_remote, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v6_add_entry(&backend_ip_remote, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_nat_fwd")
int nodeport_nat_fwd_check(__maybe_unused const struct __ctx_buff *ctx)
{
	union v6addr lb_ip = LB_IP;
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	__u32 key = 0;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &lb_ip))
		test_fatal("src IP hasn't been NATed to LB IP");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip_remote))
		test_fatal("dst IP hasn't been NATed to remote backend IP");

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
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	union v6addr lb_ip = LB_IP;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;
	__be16 nat_source_port = 0;
	__u32 key = 0;

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		nat_source_port = settings->nat_source_port;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)remote_backend_mac, (__u8 *)lb_mac,
					  (__u8 *)&backend_ip_remote, (__u8 *)&lb_ip,
					  BACKEND_PORT, nat_source_port);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int check_reply(const struct __ctx_buff *ctx)
{
	union v6addr frontend_ip_remote = FRONTEND_IP_REMOTE;
	union v6addr client_ip = CLIENT_IP;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &frontend_ip_remote))
		test_fatal("src IP hasn't been RevNATed to frontend IP");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &client_ip))
		test_fatal("dst IP hasn't been RevNATed to client IP");

	if (l4->source != FRONTEND_PORT)
		test_fatal("src port hasn't been RevNATed to frontend port");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port hasn't been RevNATed to client port");

	if (l4->check != bpf_htons(0x7347))
		test_fatal("L4 checksum is invalid: %x != %x", l4->check, bpf_htons(0x7347));

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
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_nat_fwd_reply")
int nodeport_nat_fwd_reply_check(const struct __ctx_buff *ctx)
{
	return check_reply(ctx);
}

/* Test that the LB RevDNATs and RevSNATs a reply from the
 * NAT remote backend, and sends it back to the client.
 * Even if the FIB lookup fails.
 */
PKTGEN("tc", "tc_nodeport_nat_fwd_reply_no_fib")
int nodeport_nat_fwd_reply_no_fib_pktgen(struct __ctx_buff *ctx)
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

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_nat_fwd_reply_no_fib")
int nodeport_nat_fwd_reply_no_fib_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_reply(ctx);
}

/* The following three tests check the scenario where a Rev NAT entry gets
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
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	union v6addr lb_ip = LB_IP;
	struct ipv6_ct_tuple rtuple __align_stack_8 = {};
	__be16 nat_source_port = 0;
	__u32 key = 0;

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		nat_source_port = settings->nat_source_port;

	/* Delete the Rev NAT entry, resetting fail_fib first */
	if (settings)
		settings->fail_fib = false;

	rtuple.flags = TUPLE_F_IN;
	ipv6_addr_copy(&rtuple.saddr, &backend_ip_remote);
	ipv6_addr_copy(&rtuple.daddr, &lb_ip);
	rtuple.nexthdr = IPPROTO_TCP;
	rtuple.sport = BACKEND_PORT;
	rtuple.dport = nat_source_port;

	if IS_ERR(map_delete_elem(&cilium_snat_v6_external, &rtuple))
		return TEST_ERROR;

	return netdev_receive_packet(ctx);
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
	union v6addr client_ip = CLIENT_IP;
	union v6addr frontend_ip_remote = FRONTEND_IP_REMOTE;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)&client_ip, (__u8 *)&frontend_ip_remote,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_nat_fwd_restore")
int nodeport_nat_fwd_restore_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip_remote = FRONTEND_IP_REMOTE;
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	__u16 revnat_id = 3;

	lb_v6_add_service(&frontend_ip_remote, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip_remote, FRONTEND_PORT, 1, 124,
			  &backend_ip_remote, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v6_add_entry(&backend_ip_remote, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_nat_fwd_restore")
int nodeport_nat_fwd_restore_check(__maybe_unused const struct __ctx_buff *ctx)
{
	union v6addr lb_ip = LB_IP;
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	__u32 key = 0;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &lb_ip))
		test_fatal("src IP hasn't been NATed to LB IP");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip_remote))
		test_fatal("dst IP hasn't been NATed to remote backend IP");

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
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_nat_fwd_restore_reply")
int nodeport_nat_fwd_restore_reply_check(const struct __ctx_buff *ctx)
{
	return check_reply(ctx);
}

/* The following three tests check the scenario where the Original NAT entry
 * gets deleted:
 * 1. The original packet gets ReSNATed when the entry is deleted.
 * 2. The reply packet restores the Original NAT entry if it is deleted.
 * 3. The original packet does not get ReSNATed because the Original NAT entry
 *    is restored.
 *
 *
 * Test that source port is changed when the Original NAT entry is deleted.
 * (ReSNATed)
 */
PKTGEN("tc", "tc_nodeport_nat_fwd_original_renated")
int nodeport_nat_fwd_original_renated_pktgen(struct __ctx_buff *ctx)
{
	union v6addr client_ip = CLIENT_IP;
	union v6addr frontend_ip_remote = FRONTEND_IP_REMOTE;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)&client_ip, (__u8 *)&frontend_ip_remote,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_nat_fwd_original_renated")
int nodeport_nat_fwd_original_renated_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip_remote = FRONTEND_IP_REMOTE;
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	union v6addr client_ip = CLIENT_IP;
	struct ipv6_ct_tuple otuple __align_stack_8 = {};
	__u16 revnat_id = 4;

	lb_v6_add_service(&frontend_ip_remote, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip_remote, FRONTEND_PORT, 1, 124,
			  &backend_ip_remote, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v6_add_entry(&backend_ip_remote, 0, 112233, 0, 0);

	otuple.flags = TUPLE_F_OUT;
	ipv6_addr_copy(&otuple.saddr, &client_ip);
	ipv6_addr_copy(&otuple.daddr, &backend_ip_remote);
	otuple.nexthdr = IPPROTO_TCP;
	otuple.sport = CLIENT_PORT;
	otuple.dport = BACKEND_PORT;

	/* Delete the Original NAT entry */
	if IS_ERR(map_delete_elem(&cilium_snat_v6_external, &otuple))
		return TEST_ERROR;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_nat_fwd_original_renated")
int nodeport_nat_fwd_original_renated_check(const struct __ctx_buff *ctx)
{
	union v6addr lb_ip = LB_IP;
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	__u32 key = 0;
	__be16 nat_source_port = 0;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &lb_ip))
		test_fatal("src IP hasn't been NATed to LB IP");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip_remote))
		test_fatal("dst IP hasn't been NATed to remote backend IP");

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
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	union v6addr client_ip = CLIENT_IP;
	struct ipv6_ct_tuple otuple __align_stack_8 = {};

	otuple.flags = TUPLE_F_OUT;
	ipv6_addr_copy(&otuple.saddr, &client_ip);
	ipv6_addr_copy(&otuple.daddr, &backend_ip_remote);
	otuple.nexthdr = IPPROTO_TCP;
	otuple.sport = CLIENT_PORT;
	otuple.dport = BACKEND_PORT;

	/* Delete the Original NAT entry */
	if IS_ERR(map_delete_elem(&cilium_snat_v6_external, &otuple))
		return TEST_ERROR;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_nat_fwd_restore_original_entry")
int nodeport_nat_fwd_restore_original_entry_check(struct __ctx_buff *ctx)
{
	return check_reply(ctx);
}

/* Test that a SVC request that is LBed to a NAT remote backend
 * - gets DNATed and SNATed,
 * - gets redirected back out by TC
 * - verifies that the Original NAT entry is restored.
 */
PKTGEN("tc", "tc_nodeport_nat_fwd_verify_restored_original_entry")
int nodeport_nat_fwd_verify_restored_original_entry_pktgen(struct __ctx_buff *ctx)
{
	union v6addr client_ip = CLIENT_IP;
	union v6addr frontend_ip_remote = FRONTEND_IP_REMOTE;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)&client_ip, (__u8 *)&frontend_ip_remote,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_nat_fwd_verify_restored_original_entry")
int nodeport_nat_fwd_verify_restored_original_entry_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip_remote = FRONTEND_IP_REMOTE;
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	__u16 revnat_id = 5;

	lb_v6_add_service(&frontend_ip_remote, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip_remote, FRONTEND_PORT, 1, 124,
			  &backend_ip_remote, BACKEND_PORT, IPPROTO_TCP, 0);
	ipcache_v6_add_entry(&backend_ip_remote, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_nat_fwd_verify_restored_original_entry")
int nodeport_nat_fwd_verify_restored_original_entry_check(struct __ctx_buff *ctx)
{
	union v6addr lb_ip = LB_IP;
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	__u32 key = 0;
	__be16 nat_source_port = 0;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &lb_ip))
		test_fatal("src IP hasn't been NATed to LB IP");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip_remote))
		test_fatal("dst IP hasn't been NATed to remote backend IP");

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

/* The following two tests cover GH#10983: two NodePort services sharing the
 * same backend pod. The same client 5-tuple is reused across both services.
 * Make sure that the CT entry's rev_nat_index is correctly updated to svc2's
 * index, so the reply is rev-NATed back to svc2 fronted, not svc1.
 */

/* Test that a request to svc2 (FRONTEND_IP_REMOTE_2), which shares the same
 * backend as svc1, is correctly forwarded.
 */
PKTGEN("tc", "tc_nodeport_nat_shared_backend_fwd")
int gh10983_svc2_fwd_pktgen(struct __ctx_buff *ctx)
{
	union v6addr client_ip = CLIENT_IP;
	union v6addr frontend_ip_remote_2 = FRONTEND_IP_REMOTE_2;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)&client_ip, (__u8 *)&frontend_ip_remote_2,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_nat_shared_backend_fwd")
int gh10983_svc2_fwd_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip_remote_2 = FRONTEND_IP_REMOTE_2;
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	__u16 revnat_id = 6;

	lb_v6_add_service(&frontend_ip_remote_2, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	/* Reuse the same backend_id=124 / BACKEND_IP_REMOTE as svc1. */
	lb_v6_add_backend(&frontend_ip_remote_2, FRONTEND_PORT, 1, 124,
			  &backend_ip_remote, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v6_add_entry(&backend_ip_remote, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_nat_shared_backend_fwd")
int gh10983_svc2_fwd_check(__maybe_unused const struct __ctx_buff *ctx)
{
	union v6addr lb_ip = LB_IP;
	union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	__u32 key = 0;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &lb_ip))
		test_fatal("src IP hasn't been NATed to LB IP");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip_remote))
		test_fatal("dst IP hasn't been NATed to backend IP");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		settings->nat_source_port = l4->source;

	test_finish();
}

/* Test that the reply from the shared backend is rev-NATed to svc2
 * (FRONTEND_IP_REMOTE_2), not svc1.
 */
PKTGEN("tc", "tc_nodeport_nat_shared_backend_reply")
int gh10983_svc2_reply_pktgen(struct __ctx_buff *ctx)
{
	return build_reply(ctx);
}

SETUP("tc", "tc_nodeport_nat_shared_backend_reply")
int gh10983_svc2_reply_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_nat_shared_backend_reply")
int gh10983_svc2_reply_check(const struct __ctx_buff *ctx)
{
	union v6addr frontend_ip_remote_2 = FRONTEND_IP_REMOTE_2;
	union v6addr client_ip = CLIENT_IP;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &frontend_ip_remote_2))
		test_fatal("src IP hasn't been RevNATed to svc2 frontend IP");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &client_ip))
		test_fatal("dst IP hasn't been RevNATed to client IP");

	if (l4->source != FRONTEND_PORT)
		test_fatal("src port hasn't been RevNATed to frontend port");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port hasn't been RevNATed to client port");

	test_finish();
}
