// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "tc_nodeport_lb4_ipip_termination.h"

ASSIGN_CONFIG(bool, ipip_use_outer_dst, true)

/* An external L4LB (Katran, IPVS, ...) encapsulates the client's packet to a
 * "real" from its own list. The real says where to deliver, not which backend
 * serves: the LB has no knowledge of this cluster's backend set. Decapsulation
 * must therefore leave backend selection to the inner service lookup.
 *
 * The backend port differs from the frontend port on purpose: the forced-
 * backend path cannot translate ports, so a translated port proves that the
 * outer destination was not forced as the backend.
 */

#define EXT_VIP			v4_svc_three
#define EXT_REAL_IP		IPV4(172, 16, 99, 9)
#define EXT_BACKEND_PORT	tcp_svc_two

static __always_inline int ext_lb_setup(struct __ctx_buff *ctx)
{
	lb_v4_add_service_with_flags(EXT_VIP, FRONTEND_PORT, IPPROTO_TCP, 1, 3,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_EXTERNAL_IP, 0);
	lb_v4_add_backend(EXT_VIP, FRONTEND_PORT, 1, 300,
			  BACKEND_IP, EXT_BACKEND_PORT, IPPROTO_TCP, 0);

	lb_v4_add_service_with_flags(EXT_REAL_IP, FRONTEND_PORT, IPPROTO_TCP, 1, 4,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_LOADBALANCER, 0);
	lb_v4_add_backend(EXT_REAL_IP, FRONTEND_PORT, 1, 300,
			  BACKEND_IP, EXT_BACKEND_PORT, IPPROTO_TCP, 0);

	endpoint_v4_add_entry(BACKEND_IP, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);

	endpoint_v4_add_entry(BACKEND_NODE_IP, 0, 0, ENDPOINT_F_HOST,
			      HOST_ID, 0, NULL, NULL);
	ipcache_v4_add_entry(BACKEND_NODE_IP, 0, HOST_ID, 0, 0);

	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	num_calls[RECORD_TAILCALL] = 0;
	xdp_xfer_flags = 0;

	return netdev_receive_packet(ctx);
}

static __always_inline void ext_lb_teardown(void)
{
	endpoint_v4_del_entry(BACKEND_IP);
	endpoint_v4_del_entry(BACKEND_NODE_IP);
}

static __always_inline int ext_lb_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();

	ext_lb_teardown();

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
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->protocol != IPPROTO_TCP)
		test_fatal("L3 proto is %u, want TCP: outer not stripped",
			   l3->protocol);
	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP is %x, want CLIENT", l3->saddr);
	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP is %x, want BACKEND: outer dst was forced",
			   l3->daddr);

	l4 = (void *)l3 + sizeof(struct iphdr);
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

PKTGEN(PROG_TYPE, "tc_nodeport_ipip_term_v4_ext_lb_frontend")
int ipip_term_v4_ext_lb_frontend_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_ipip_v4(ctx, EXT_REAL_IP, EXT_VIP);
}

SETUP(PROG_TYPE, "tc_nodeport_ipip_term_v4_ext_lb_frontend")
int ipip_term_v4_ext_lb_frontend_setup(struct __ctx_buff *ctx)
{
	return ext_lb_setup(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_ipip_term_v4_ext_lb_frontend")
int ipip_term_v4_ext_lb_frontend_check(struct __ctx_buff *ctx)
{
	return ext_lb_check(ctx);
}

/* A node IP is a host endpoint, so the pre-existing forced-backend path
 * applies: DNAT to the node without port translation.
 */
PKTGEN(PROG_TYPE, "tc_nodeport_ipip_term_v4_ext_lb_node_ip")
int ipip_term_v4_ext_lb_node_ip_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_ipip_v4(ctx, BACKEND_NODE_IP, EXT_VIP);
}

SETUP(PROG_TYPE, "tc_nodeport_ipip_term_v4_ext_lb_node_ip")
int ipip_term_v4_ext_lb_node_ip_setup(struct __ctx_buff *ctx)
{
	return ext_lb_setup(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_ipip_term_v4_ext_lb_node_ip")
int ipip_term_v4_ext_lb_node_ip_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();

	ext_lb_teardown();

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
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->protocol != IPPROTO_TCP)
		test_fatal("L3 proto is %u, want TCP: outer not stripped",
			   l3->protocol);
	if (l3->daddr != BACKEND_NODE_IP)
		test_fatal("dst IP is %x, want NODE_IP", l3->daddr);

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->dest != FRONTEND_PORT)
		test_fatal("dport %u, want frontend port", bpf_ntohs(l4->dest));

	test_finish();
}
