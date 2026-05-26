// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4			1
#define ENABLE_IPV6			1
#define ENABLE_NODEPORT			1
#define ENABLE_NODEPORT_ACCELERATION	1
#define ENABLE_DSR			1

/* Skip ingress policy checks */
#define USE_BPF_PROG_FOR_INGRESS_POLICY	1

#define CLIENT_IP		v4_ext_one
#define CLIENT_IPV6		{ .addr = { 0x1, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		v4_svc_two
#define FRONTEND_IPV6		{ .addr = { 0x2, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_one
#define LB_IPV6			{ .addr = { 0x5, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define IPV4_DIRECT_ROUTING	LB_IP
#define IPV6_DIRECT_ROUTING	LB_IPV6

#define BACKEND_IP		v4_pod_two
#define BACKEND_IPV6		{ .addr = { 0x3, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define BACKEND_PORT		__bpf_htons(8080)

#define FRONTEND_PORT		tcp_svc_one

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;
static volatile const __u8 *remote_backend_mac = mac_five;

#define fib_lookup mock_fib_lookup
static __always_inline __maybe_unused long
mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		__maybe_unused int plen, __maybe_unused __u32 flags);

#include "lib/bpf_xdp.h"

ASSIGN_CONFIG(bool, enable_endpoint_routes, true)

static __always_inline __maybe_unused long
mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
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
		if (1 /*memcmp(&params->ipv6_dst, BACKEND_IP)*/) {
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
 * - gets DNATed,
 * - has IP Option inserted,
 * - gets redirected back out by XDP
 */
PKTGEN("xdp", "xdp_nodeport_dsr_fwd4")
int nodeport_dsr_fwd4_pktgen(struct __ctx_buff *ctx)
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

SETUP("xdp", "xdp_nodeport_dsr_fwd4")
int nodeport_dsr_fwd4_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);

	return xdp_receive_packet(ctx);
}

CHECK("xdp", "xdp_nodeport_dsr_fwd4")
int nodeport_dsr_fwd4_check(__maybe_unused const struct __ctx_buff *ctx)
{
	struct dsr_opt_v4 *opt;
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

	assert(fib_ok(*status_code));

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	opt = (void *)l3 + sizeof(struct iphdr);
	if ((void *)opt + 2 * sizeof(__u32) > data_end)
		test_fatal("l3 DSR option out of bounds");

	l4 = (void *)opt + sizeof(*opt);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)remote_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the backend MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (l3->check != bpf_htons(0x434a))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (opt->type != DSR_IPV4_OPT_TYPE)
		test_fatal("type in DSR IP option is bad")
	if (opt->len != 8)
		test_fatal("length in DSR IP option is bad")
	if (opt->port != __bpf_ntohs(FRONTEND_PORT))
		test_fatal("port in DSR IP option is bad")
	if (opt->addr != __bpf_ntohl(FRONTEND_IP))
		test_fatal("addr in DSR IP option is bad")

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	if (l4->check != bpf_htons(0x3770))
		test_fatal("L4 checksum is invalid: %x != %x", l4->check, bpf_ntohs(0x3770));

	test_finish();
}

/* Test that a SVC request that is LBed to a DSR remote backend
 * - gets DNATed,
 * - has IPv6 Extension inserted,
 * - gets redirected back out by XDP
 */
PKTGEN("xdp", "xdp_nodeport_dsr_fwd6")
int nodeport_dsr_fwd6_pktgen(struct __ctx_buff *ctx)
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

SETUP("xdp", "xdp_nodeport_dsr_fwd6")
int nodeport_dsr_fwd6_setup(struct __ctx_buff *ctx)
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

CHECK("xdp", "xdp_nodeport_dsr_fwd6")
int nodeport_dsr_fwd6_check(__maybe_unused const struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IPV6;
	union v6addr backend_ip = BACKEND_IPV6;
	union v6addr client_ip = CLIENT_IPV6;
	struct dsr_opt_v6 *opt;
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

	assert(fib_ok(*status_code));

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	opt = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)opt + sizeof(*opt) > data_end)
		test_fatal("l3 DSR extension out of bounds");

	l4 = (void *)opt + sizeof(*opt);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)remote_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the backend MAC")

	if (l3->nexthdr != NEXTHDR_DEST)
		test_fatal("l3 header doesn't indicate DSR extension");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip))
		test_fatal("src IP has changed");
	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip))
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (opt->hdr.nexthdr != IPPROTO_TCP)
		test_fatal("nexthdr in DSR extension is bad")
	if (opt->hdr.hdrlen != DSR_IPV6_EXT_LEN)
		test_fatal("length in DSR extension is bad")
	if (opt->opt_type != DSR_IPV6_OPT_TYPE)
		test_fatal("opt_type in DSR extension is bad")
	if (opt->opt_len != DSR_IPV6_OPT_LEN)
		test_fatal("opt_len in DSR extension is bad")

	if (opt->port != FRONTEND_PORT)
		test_fatal("port in DSR extension is bad")
	if (!ipv6_addr_equals((union v6addr *)&opt->addr, &frontend_ip))
		test_fatal("addr in DSR extension is bad")

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	if (l4->check != bpf_htons(0x6d1c))
		test_fatal("L4 checksum is invalid: %x != %x", l4->check, bpf_ntohs(0x6d1c));

	test_finish();
}
