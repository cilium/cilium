// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ETH_HLEN		0
#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define ENABLE_NODEPORT		1
#define ENABLE_DSR		1
#define DSR_ENCAP_IPIP		2
#define DSR_ENCAP_GENEVE	3
#define DSR_ENCAP_MODE		DSR_ENCAP_GENEVE
#define ENCAP_IFINDEX		42

#define CLIENT_IP		v4_ext_one
#define CLIENT_IPV6		{ .addr = { 0x1, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_IPV6		{ .addr = { 0x5, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v4_pod_one
#define BACKEND_IPV6		{ .addr = { 0x3, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define BACKEND_PORT		__bpf_htons(8080)

#define REMOTE_NODE_IP		v4_node_one

static volatile const __u8 *client_mac = mac_one;
/* this matches the default node_config.h: */
static volatile const __u8 lb_mac[ETH_ALEN] = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 };

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if (ifindex != ENCAP_IFINDEX)
		return -1;

	return CTX_ACT_REDIRECT;
}

#include <bpf_host.c>

#include "lib/ipcache.h"
#include "lib/lb.h"

#define FROM_NETDEV	0
#define TO_NETDEV	1

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

/* Test that a SVC request that is LBed to a DSR remote backend
 * - gets DNATed,
 * - has IP Option inserted,
 * - gets redirected back out by TC
 */
PKTGEN("tc", "ipv4_tc_nodeport_l3_dev_dsr_geneve_fwd")
int ipv4_tc_nodeport_l3_dev_dsr_geneve_fwd_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP,
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

SETUP("tc", "ipv4_tc_nodeport_l3_dev_dsr_geneve_fwd")
int ipv4_tc_nodeport_l3_dev_dsr_geneve_fwd_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, REMOTE_NODE_IP, 0);

	/* Strip L2 header to emulate L3 packet: */
	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "ipv4_tc_nodeport_l3_dev_dsr_geneve_fwd")
int ipv4_tc_nodeport_l3_dev_dsr_geneve_fwd_check(__maybe_unused struct __ctx_buff *ctx)
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

	l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	test_finish();
}

/* Test that a SVC request that is LBed to a DSR remote backend
 * - gets DNATed,
 * - has IPv6 Extension inserted,
 * - gets redirected back out by TC
 */
PKTGEN("tc", "ipv6_tc_nodeport_l3_dev_dsr_geneve_fwd")
int ipv6_tc_nodeport_l3_dev_dsr_geneve_fwd_pktgen(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IPV6;
	union v6addr client_ip = CLIENT_IPV6;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)&client_ip, (__u8 *)&frontend_ip,
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

SETUP("tc", "ipv6_tc_nodeport_l3_dev_dsr_geneve_fwd")
int ipv6_tc_nodeport_l3_dev_dsr_geneve_fwd_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;
	union v6addr frontend_ip = FRONTEND_IPV6;
	union v6addr backend_ip = BACKEND_IPV6;
	__u16 revnat_id = 1;

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip, FRONTEND_PORT, 1, 124,
			  &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v6_add_entry(&backend_ip, 0, 112233, REMOTE_NODE_IP, 0);

	/* Strip L2 header to emulate L3 packet: */
	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "ipv6_tc_nodeport_l3_dev_dsr_geneve_fwd")
int ipv6_tc_nodeport_l3_dev_dsr_geneve_fwd_check(__maybe_unused struct __ctx_buff *ctx)
{
	union v6addr backend_ip = BACKEND_IPV6;
	union v6addr client_ip = CLIENT_IPV6;
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

	l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip))
		test_fatal("src IP has changed");
	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip))
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	test_finish();
}
