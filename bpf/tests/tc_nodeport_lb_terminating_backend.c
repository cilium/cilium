// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Enable code paths under test */
#define ENABLE_IPV4		1
#define ENABLE_NODEPORT		1

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP_LOCAL	v4_svc_one
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_one

#define BACKEND_IP_LOCAL	v4_pod_one
#define BACKEND_PORT		__bpf_htons(8080)

#define BACKEND_IP_LOCAL_2	v4_pod_two
#define BACKEND_IFACE_2		26
#define BACKEND_EP_ID_2		128

#define DEFAULT_IFACE		24
#define BACKEND_IFACE		25

#define SVC_REV_NAT_ID		2

#define BACKEND_EP_ID		127

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *local_backend_mac = mac_four;

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
		[BACKEND_EP_ID_2] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
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
	if (ip4->saddr == CLIENT_IP && (ifindex == BACKEND_IFACE || ifindex == BACKEND_IFACE_2))
		return TC_ACT_REDIRECT;

	return CTX_ACT_DROP;
}

#include "lib/bpf_host.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(bool, enable_bpf_host_routing, true)
ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = LB_IP })

/* Test that a SVC request (TCP) to a local backend
 * - gets DNATed (but not SNATed)
 * - gets redirected by TC (as BPF Host Routing is enabled)
 */
PKTGEN(PROG_TYPE, "tc_nodeport_lb_terminating_backend_0")
int tc_nodeport_lb_terminating_backend_0_pktgen(struct __ctx_buff *ctx)
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

SETUP(PROG_TYPE, "tc_nodeport_lb_terminating_backend_0")
int tc_nodeport_lb_terminating_backend_0_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = SVC_REV_NAT_ID;

	lb_v4_add_service(FRONTEND_IP_LOCAL, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP_LOCAL, FRONTEND_PORT, 1, 125,
			  BACKEND_IP_LOCAL, BACKEND_PORT, IPPROTO_TCP, 0);

	/* add local backend */
	endpoint_v4_add_entry(BACKEND_IP_LOCAL, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)local_backend_mac, (__u8 *)node_mac);

	ipcache_v4_add_entry(BACKEND_IP_LOCAL, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_lb_terminating_backend_0")
int tc_nodeport_lb_terminating_backend_0_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	endpoint_v4_del_entry(BACKEND_IP_LOCAL);

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
PKTGEN(PROG_TYPE, "tc_nodeport_lb_terminating_backend_1")
int tc_nodeport_lb_terminating_backend_1_pktgen(struct __ctx_buff *ctx)
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

	l4->syn = 0;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "tc_nodeport_lb_terminating_backend_1")
int tc_nodeport_lb_terminating_backend_1_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = SVC_REV_NAT_ID;

	endpoint_v4_add_entry(BACKEND_IP_LOCAL, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)local_backend_mac, (__u8 *)node_mac);

	/* Remove the service's last backend, and flip the backend to
	 * 'terminating' state.
	 */
	lb_v4_upsert_service(FRONTEND_IP_LOCAL, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_upsert_backend(125, BACKEND_IP_LOCAL, BACKEND_PORT, IPPROTO_TCP,
			     BE_STATE_TERMINATING, 0);

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_lb_terminating_backend_1")
int tc_nodeport_lb_terminating_backend_1_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	endpoint_v4_del_entry(BACKEND_IP_LOCAL);

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

/* Test that an established TCP connection continues draining to the
 * terminating backend even when an active backend exists.
 */
PKTGEN(PROG_TYPE, "tc_nodeport_lb_terminating_backend_2")
int tc_nodeport_lb_terminating_backend_2_pktgen(struct __ctx_buff *ctx)
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

	l4->syn = 0;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "tc_nodeport_lb_terminating_backend_2")
int tc_nodeport_lb_terminating_backend_2_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = SVC_REV_NAT_ID;

	endpoint_v4_add_entry(BACKEND_IP_LOCAL, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)local_backend_mac, (__u8 *)node_mac);
	endpoint_v4_add_entry(BACKEND_IP_LOCAL_2, BACKEND_IFACE_2, BACKEND_EP_ID_2, 0, 0, 0,
			      (__u8 *)local_backend_mac, (__u8 *)node_mac);

	ipcache_v4_add_entry(BACKEND_IP_LOCAL_2, 0, 112233, 0, 0);

	/* Service has 1 active backend (126) and 1 terminating backend (125). */
	lb_v4_upsert_service(FRONTEND_IP_LOCAL, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP_LOCAL, FRONTEND_PORT, 1, 126,
			  BACKEND_IP_LOCAL_2, BACKEND_PORT, IPPROTO_TCP, 0);
	lb_v4_upsert_backend(125, BACKEND_IP_LOCAL, BACKEND_PORT, IPPROTO_TCP,
			     BE_STATE_TERMINATING, 0);

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_lb_terminating_backend_2")
int tc_nodeport_lb_terminating_backend_2_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	endpoint_v4_del_entry(BACKEND_IP_LOCAL);
	endpoint_v4_del_entry(BACKEND_IP_LOCAL_2);

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

	/* For TCP, existing connections continue draining to the terminating
	 * backend (BACKEND_IP_LOCAL).
	 */
	if (l3->daddr != BACKEND_IP_LOCAL)
		test_fatal("dst IP was not drained to terminating backend IP");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	test_finish();
}

/* Test that a new TCP SYN request does NOT get LBed to a terminating backend
 * when the service has no active backends remaining, and instead is rejected (no_service).
 */
PKTGEN(PROG_TYPE, "tc_nodeport_lb_terminating_backend_3")
int tc_nodeport_lb_terminating_backend_3_pktgen(struct __ctx_buff *ctx)
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

	l4->syn = 1;
	l4->ack = 0;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "tc_nodeport_lb_terminating_backend_3")
int tc_nodeport_lb_terminating_backend_3_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = SVC_REV_NAT_ID;

	endpoint_v4_add_entry(BACKEND_IP_LOCAL, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)local_backend_mac, (__u8 *)node_mac);

	/* Service has 0 active backends, and 1 terminating backend (125). */
	lb_v4_upsert_service(FRONTEND_IP_LOCAL, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_upsert_backend(125, BACKEND_IP_LOCAL, BACKEND_PORT, IPPROTO_TCP,
			     BE_STATE_TERMINATING, 0);

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_lb_terminating_backend_3")
int tc_nodeport_lb_terminating_backend_3_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v4_del_entry(BACKEND_IP_LOCAL);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* When count == 0 and syn == 1, packet hits no_service and is dropped (CTX_ACT_DROP) */
	assert(*status_code == CTX_ACT_DROP);

	test_finish();
}

