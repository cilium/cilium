// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include "common.h"
#include "pktgen.h"
#include "lib/ipv6_core.h"

/* Enable code paths under test */
#define ENABLE_IPV4			1
#define ENABLE_IPV6			1
#define ENABLE_NODEPORT			1
#define ENABLE_NODEPORT_ACCELERATION	1
#define ENABLE_DSR			1
#define DSR_ENCAP_IPIP			2
#define DSR_ENCAP_MODE			DSR_ENCAP_IPIP

/* Skip ingress policy checks */
#define USE_BPF_PROG_FOR_INGRESS_POLICY	1

#define CLIENT_IP		v4_ext_one
#define CLIENT_IPV6		{ .addr = { 0x1 } }
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		v4_svc_two
#define FRONTEND_IPV6		{ .addr = { 0x2 } }
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_one
#define LB_IPV6			{ .addr = { 0x5 } }
#define IPV4_DIRECT_ROUTING	LB_IP
#define IPV6_DIRECT_ROUTING	LB_IPV6

#define BACKEND_IP		v4_pod_two
#define BACKEND_IPV6		{ .addr = { 0x3 } }
#define BACKEND_PORT		__bpf_htons(8080)

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;
static volatile const __u8 *remote_backend_mac = mac_five;

#define fib_lookup mock_fib_lookup
static __always_inline __maybe_unused long
mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		__maybe_unused int plen, __maybe_unused __u32 flags);

#include "lib/bpf_xdp.h"

ASSIGN_CONFIG(bool, enable_endpoint_routes, true)

long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	params->ifindex = 0;

	if (params->family == AF_INET) {
		if (params->ipv4_dst == BACKEND_IP) {
			__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
			__bpf_memcpy_builtin(params->dmac, (__u8 *)remote_backend_mac, ETH_ALEN);
		} else {
			__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
			__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
		}
	} else {
		union v6addr backend_ip = BACKEND_IPV6;

		if (params->ipv6_dst[0] == backend_ip.p1 &&
		    params->ipv6_dst[1] == backend_ip.p2 &&
		    params->ipv6_dst[2] == backend_ip.p3 &&
		    params->ipv6_dst[3] == backend_ip.p4) {
			__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
			__bpf_memcpy_builtin(params->dmac, (__u8 *)remote_backend_mac, ETH_ALEN);
		} else {
			__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
			__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
		}
	}

	return 0;
}

#include "lib/ipcache.h"
#include "lib/lb.h"

/* Test that a SVC request that is LBed to a DSR remote backend
 * - is IPIP encapsulated,
 * - keeps the inner destination as the service IP,
 * - gets redirected back out by XDP
 */
PKTGEN("xdp", "xdp_nodeport_dsr_ipip4_fwd")
int nodeport_dsr_ipip4_fwd_pktgen(struct __ctx_buff *ctx)
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

SETUP("xdp", "xdp_nodeport_dsr_ipip4_fwd")
int nodeport_dsr_ipip4_fwd_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);

	return xdp_receive_packet(ctx);
}

CHECK("xdp", "xdp_nodeport_dsr_ipip4_fwd")
int nodeport_dsr_ipip4_fwd_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *outer_l3;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(fib_ok(*status_code));

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	outer_l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)outer_l3 + sizeof(struct iphdr) > data_end)
		test_fatal("outer l3 out of bounds");

	l3 = (void *)outer_l3 + sizeof(struct iphdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("inner l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("inner l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC");
	if (memcmp(l2->h_dest, (__u8 *)remote_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the backend MAC");

	if (outer_l3->protocol != IPPROTO_IPIP)
		test_fatal("outer IP doesn't have correct L4 protocol");
	if (outer_l3->saddr != IPV4_DIRECT_ROUTING)
		test_fatal("outerSrcIP is not correct");
	if (outer_l3->daddr != BACKEND_IP)
		test_fatal("outerDstIP is not correct");
	if (outer_l3->tot_len != bpf_htons(sizeof(struct iphdr) +
					   sizeof(struct iphdr) +
					   sizeof(struct tcphdr) +
					   sizeof(default_data)))
		test_fatal("outer tot_len is not correct");
	if (outer_l3->check != bpf_htons(0xa6ff))
		test_fatal("outer L3 checksum is invalid: %x", bpf_htons(outer_l3->check));

	if (l3->protocol != IPPROTO_TCP)
		test_fatal("l3 header doesn't indicate TCP payload");
	if (l3->saddr != CLIENT_IP)
		test_fatal("innerSrcIP has changed");
	if (l3->daddr != FRONTEND_IP)
		test_fatal("innerDstIP has changed");
	if (l3->tot_len != bpf_htons(sizeof(struct iphdr) +
				     sizeof(struct tcphdr) +
				     sizeof(default_data)))
		test_fatal("inner tot_len has changed");
	if (l3->check != bpf_htons(0x4ba9))
		test_fatal("inner L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source != CLIENT_PORT)
		test_fatal("innerSrcPort has changed");
	if (l4->dest != FRONTEND_PORT)
		test_fatal("innerDstPort has changed");
	if (l4->check != bpf_htons(0x6148))
		test_fatal("inner L4 checksum is invalid: %x != %x", l4->check, bpf_ntohs(0x6148));

	test_finish();
}

/* Test that a SVC request that is LBed to a DSR remote backend
 * - is IPv6-in-IPv6 encapsulated,
 * - keeps the inner destination as the service IP,
 * - gets redirected back out by XDP
 */
PKTGEN("xdp", "xdp_nodeport_dsr_ipip6_fwd")
int nodeport_dsr_ipip6_fwd_pktgen(struct __ctx_buff *ctx)
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

SETUP("xdp", "xdp_nodeport_dsr_ipip6_fwd")
int nodeport_dsr_ipip6_fwd_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IPV6;
	union v6addr backend_ip = BACKEND_IPV6;
	__u16 revnat_id = 2;

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip, FRONTEND_PORT, 1, 124,
			  &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v6_add_entry(&backend_ip, 0, 112233, 0, 0);

	return xdp_receive_packet(ctx);
}

CHECK("xdp", "xdp_nodeport_dsr_ipip6_fwd")
int nodeport_dsr_ipip6_fwd_check(__maybe_unused const struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IPV6;
	union v6addr backend_ip = BACKEND_IPV6;
	union v6addr client_ip = CLIENT_IPV6;
	union v6addr lb_ip = LB_IPV6;
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct ipv6hdr *outer_l3;
	struct ipv6hdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(fib_ok(*status_code));

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	outer_l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)outer_l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("outer l3 out of bounds");

	l3 = (void *)outer_l3 + sizeof(struct ipv6hdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("inner l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("inner l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC");
	if (memcmp(l2->h_dest, (__u8 *)remote_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the backend MAC");

	if (outer_l3->nexthdr != IPPROTO_IPV6)
		test_fatal("outer IP doesn't have IPv6 payload");
	if (!ipv6_addr_equals((union v6addr *)&outer_l3->saddr, &lb_ip))
		test_fatal("outerSrcIP is not correct");
	if (!ipv6_addr_equals((union v6addr *)&outer_l3->daddr, &backend_ip))
		test_fatal("outerDstIP is not correct");
	if (outer_l3->payload_len !=
	    bpf_htons(sizeof(struct ipv6hdr) + sizeof(struct tcphdr) + sizeof(default_data)))
		test_fatal("outer payload_len is not correct");

	if (l3->nexthdr != IPPROTO_TCP)
		test_fatal("inner IP doesn't have correct L4 protocol");
	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip))
		test_fatal("innerSrcIP has changed");
	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &frontend_ip))
		test_fatal("innerDstIP has changed");
	if (l3->payload_len != bpf_htons(sizeof(struct tcphdr) + sizeof(default_data)))
		test_fatal("inner payload_len has changed");

	if (l4->source != CLIENT_PORT)
		test_fatal("innerSrcPort has changed");
	if (l4->dest != FRONTEND_PORT)
		test_fatal("innerDstPort has changed");
	if (l4->check != bpf_htons(0x8d5c))
		test_fatal("inner L4 checksum is invalid: %x != %x", l4->check, bpf_ntohs(0x8d5c));

	test_finish();
}
