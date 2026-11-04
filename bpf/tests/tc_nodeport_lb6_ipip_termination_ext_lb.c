// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "tc_nodeport_lb6_ipip_termination.h"

ASSIGN_CONFIG(bool, ipip_use_outer_dst, true)

/* IPv6 mirror of the external-L4LB tests in the IPv4 sibling file. */

#define EXT_BACKEND_PORT	tcp_svc_two

static const __u8 ext_vip6[16]     = v6_svc_three_addr;
static const __u8 ext_real_ip6[16] = {0xfd, 0x10, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0x99, 9};

static __always_inline int ext_lb6_setup(struct __ctx_buff *ctx)
{
	union v6addr vip, real, backend, host;

	memcpy(&vip, (void *)ext_vip6, 16);
	memcpy(&real, (void *)ext_real_ip6, 16);
	memcpy(&backend, (void *)v6_pod_two, 16);
	memcpy(&host, (void *)v6_node_one, 16);

	lb_v6_add_service_with_flags(&vip, FRONTEND_PORT, IPPROTO_TCP, 1, 3,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_EXTERNAL_IP, 0);
	lb_v6_add_backend(&vip, FRONTEND_PORT, 1, 300, &backend,
			  EXT_BACKEND_PORT, IPPROTO_TCP, 0);

	lb_v6_add_service_with_flags(&real, FRONTEND_PORT, IPPROTO_TCP, 1, 4,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_LOADBALANCER, 0);
	lb_v6_add_backend(&real, FRONTEND_PORT, 1, 300, &backend,
			  EXT_BACKEND_PORT, IPPROTO_TCP, 0);

	endpoint_v6_add_entry(&backend, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry(&backend, 0, 112233, 0, 0);

	endpoint_v6_add_entry(&host, 0, 0, ENDPOINT_F_HOST, HOST_ID, NULL, NULL);
	ipcache_v6_add_entry(&host, 0, HOST_ID, 0, 0);

	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	num_calls[RECORD_TAILCALL] = 0;
	xdp_xfer_flags = 0;

	return netdev_receive_packet(ctx);
}

static __always_inline void ext_lb6_teardown(void)
{
	endpoint_v6_del_entry((const union v6addr *)v6_pod_two);
	endpoint_v6_del_entry((const union v6addr *)v6_node_one);
}

static __always_inline int ext_lb6_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();

	ext_lb6_teardown();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	if (num_calls[RECORD_TAILCALL] != 1)
		test_fatal("want 1 policy tail-call, got %u",
			   num_calls[RECORD_TAILCALL]);
	if (num_calls[RECORD_REDIRECT_PEER] != 1)
		test_fatal("want 1 ctx_redirect_peer, got %u",
			   num_calls[RECORD_REDIRECT_PEER]);
	if (num_calls[RECORD_REDIRECT] != 0)
		test_fatal("want 0 plain ctx_redirect, got %u",
			   num_calls[RECORD_REDIRECT]);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->nexthdr != IPPROTO_TCP)
		test_fatal("nexthdr is %u, want TCP: outer not stripped",
			   l3->nexthdr);
	if (memcmp(&l3->saddr, (void *)v6_pod_one, 16) != 0)
		test_fatal("src IP is not CLIENT");
	if (memcmp(&l3->daddr, (void *)v6_pod_two, 16) != 0)
		test_fatal("dst IP is not BACKEND: outer dst was forced");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");
	if (l4->dest != EXT_BACKEND_PORT)
		test_fatal("dport %u, want backend port: forced path ran",
			   bpf_ntohs(l4->dest));
	if (!l4->syn)
		test_fatal("TCP flags lost the SYN");

	test_finish();
}

PKTGEN(PROG_TYPE, "tc_nodeport_ipip_term_v6_ext_lb_frontend")
int ipip_term_v6_ext_lb_frontend_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_ipip_v6(ctx, (void *)ext_real_ip6, (void *)ext_vip6);
}

SETUP(PROG_TYPE, "tc_nodeport_ipip_term_v6_ext_lb_frontend")
int ipip_term_v6_ext_lb_frontend_setup(struct __ctx_buff *ctx)
{
	return ext_lb6_setup(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_ipip_term_v6_ext_lb_frontend")
int ipip_term_v6_ext_lb_frontend_check(struct __ctx_buff *ctx)
{
	return ext_lb6_check(ctx);
}

PKTGEN(PROG_TYPE, "tc_nodeport_ipip_term_v6_ext_lb_node_ip")
int ipip_term_v6_ext_lb_node_ip_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_ipip_v6(ctx, (void *)v6_node_one, (void *)ext_vip6);
}

SETUP(PROG_TYPE, "tc_nodeport_ipip_term_v6_ext_lb_node_ip")
int ipip_term_v6_ext_lb_node_ip_setup(struct __ctx_buff *ctx)
{
	return ext_lb6_setup(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_ipip_term_v6_ext_lb_node_ip")
int ipip_term_v6_ext_lb_node_ip_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();

	ext_lb6_teardown();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_fatal("status is %u, want CTX_ACT_OK", *status_code);
	if (num_calls[RECORD_TAILCALL] != 0)
		test_fatal("want 0 policy tail-calls, got %u",
			   num_calls[RECORD_TAILCALL]);
	if (num_calls[RECORD_REDIRECT_PEER] != 0)
		test_fatal("redirected to a Pod, want the forced host path");
	if (num_calls[RECORD_REDIRECT] != 0)
		test_fatal("want 0 plain ctx_redirect, got %u",
			   num_calls[RECORD_REDIRECT]);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->nexthdr != IPPROTO_TCP)
		test_fatal("nexthdr is %u, want TCP: outer not stripped",
			   l3->nexthdr);
	if (memcmp(&l3->daddr, (void *)v6_node_one, 16) != 0)
		test_fatal("dst is not NODE_IP");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->dest != FRONTEND_PORT)
		test_fatal("dport %u, want frontend port", bpf_ntohs(l4->dest));

	test_finish();
}
