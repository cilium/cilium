// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define SERVICE_NO_BACKEND_RESPONSE

#define CLIENT_IP	v4_ext_one
#define CLIENT_PORT	tcp_src_one

#define FRONTEND_IP	v4_svc_two
#define FRONTEND_PORT	tcp_svc_two
#define UNKNOWN_PORT    __bpf_htons(444)

#define BACKEND_IP	v4_pod_three
#define BACKEND_PORT	tcp_svc_two

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;

#include "lib/bpf_host.h"

ASSIGN_CONFIG(bool, enable_no_service_endpoints_routable, true)

#include "lib/ipcache.h"
#include "lib/lb.h"

static __always_inline int build_packet(struct __ctx_buff *ctx,
					const __u16 fe_dport, const __u8 proto)
{
	struct pktgen builder;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	switch (proto) {
	case IPPROTO_TCP: {
		struct tcphdr *l4 = pktgen__push_ipv4_tcp_packet(&builder,
					(__u8 *)client_mac,
					(__u8 *)lb_mac,
					CLIENT_IP,
					FRONTEND_IP,
					CLIENT_PORT,
					fe_dport);
		if (!l4)
			return TEST_ERROR;
		break;
	}

	case IPPROTO_UDP: {
		struct udphdr *l4 = pktgen__push_ipv4_udp_packet(&builder,
					(__u8 *)client_mac,
					(__u8 *)lb_mac,
					CLIENT_IP,
					FRONTEND_IP,
					CLIENT_PORT,
					fe_dport);
		if (!l4)
			return TEST_ERROR;
		break;
	}

	default:
		return TEST_ERROR;
	}

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0; /* FIXME - TEST_ERROR == 0 ? */
}

static __always_inline void setup_services(struct __ctx_buff *ctx __maybe_unused)
{
	__u16 revnat_id = 1;

	/* Insert the real Load Balancer VIP */
	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);

	/* Insert the wildcard entry for the VIP */
	lb_v4_add_service(FRONTEND_IP, LB_SVC_WILDCARD_DPORT, LB_SVC_WILDCARD_PROTO, 0, revnat_id);

	/* Not sure if this is needed! */
	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);
}

static __always_inline int validate_packet(const struct __ctx_buff *ctx,
					   const __u8 *smac, const __u8 *dmac,
					   const __u32 saddr, const __u32 daddr,
					   const __u16 dport, const __u8 proto,
					   const __u32 exp_status)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Grab a pointer to the status code. We check this later, once we know the
	 * test payload is right.
	 */
	status_code = data;

	/* Verify Ethernet frame */
	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 header out of bounds");

	assert(memcmp(l2->h_source, smac, ETH_ALEN) == 0);
	assert(memcmp(l2->h_dest, dmac, ETH_ALEN) == 0);
	assert(l2->h_proto == __bpf_htons(ETH_P_IP));

	/* Verify IP packet */
	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	assert(l3->saddr == saddr);
	assert(l3->daddr == daddr);
	assert(l3->ihl == 5);
	assert(l3->version == 4);
	assert(l3->tos == 0);
	assert(l3->ttl == 64);
	assert(l3->protocol == proto);

	/* Verify L4 protocol header */
	switch (proto) {
	case IPPROTO_TCP: {
		struct tcphdr *l4 = (void *)l3 + sizeof(struct iphdr);

		if ((void *)l4 + sizeof(struct tcphdr) > data_end)
			test_fatal("l4 out of bounds (tcp)");

		assert(l4->source == CLIENT_PORT);
		assert(l4->dest == dport);
		assert(l4->syn == 1);
		assert(l4->seq == 123456);
		assert(l4->window == 65535);
		assert(l4->doff == 5);

		break;
	}

	case IPPROTO_UDP: {
		struct udphdr *l4 = (void *)l3 + sizeof(struct iphdr);

		if ((void *)l4 + sizeof(struct udphdr) > data_end)
			test_fatal("l4 out of bounds (udp)");

		assert(l4->source == CLIENT_PORT);
		assert(l4->dest == dport);

		break;
	}

	case IPPROTO_ICMP: {
		struct icmphdr *l4 = (void *)l3 + sizeof(struct iphdr);

		if ((void *)l4 + sizeof(struct icmphdr) > data_end)
			test_fatal("l4 out of bounds (icmp)");

		/* Chosen to only verify the ICMP type and code here, not the full ICMP
		 * payload, which is tested in lbXX_no_backend
		 */
		assert(l4->type == ICMP_DEST_UNREACH);
		assert(l4->code == ICMP_PORT_UNREACH);

		break;
	}

	default:
		test_fatal("Unhandled L4 header");
	}

	/* Now we've verified the packet, verify the action was drop */
	test_log("Status code: %u, exp %u", *status_code, exp_status);
	assert(*status_code == exp_status);

	test_finish();
}

/* Test wildcard drop for unknown destination port on TCP */

PKTGEN("tc", "tc_nodeport_lb4_wildcard_drop_unknown_dport")
int tc_nodeport_lb4_wildcard_drop_unknown_dport_pktgen(struct __ctx_buff *ctx)
{
	/* Generate a packet to the Frontend IP, but to an unknown TCP dest port. */
	return build_packet(ctx, UNKNOWN_PORT, IPPROTO_TCP);
}

SETUP("tc", "tc_nodeport_lb4_wildcard_drop_unknown_dport")
int tc_nodeport_lb4_wildcard_drop_unknown_dport_setup(struct __ctx_buff *ctx)
{
	setup_services(ctx);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb4_wildcard_drop_unknown_dport")
int tc_nodeport_lb4_wildcard_drop_unknown_dport_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return validate_packet(ctx, (__u8 *)client_mac, (__u8 *)lb_mac, CLIENT_IP, FRONTEND_IP,
			       UNKNOWN_PORT, IPPROTO_TCP, CTX_ACT_DROP);
}

/* Test wildcard drop for unknown protocol on a valid destination port */

PKTGEN("tc", "tc_nodeport_lb4_wildcard_drop_unknown_proto")
int tc_nodeport_lb4_wildcard_drop_unknown_proto_pktgen(struct __ctx_buff *ctx)
{
	/* Generate a packet to the Frontend IP and port, but on an unknown protocol */
	return build_packet(ctx, FRONTEND_PORT, IPPROTO_UDP);
}

SETUP("tc", "tc_nodeport_lb4_wildcard_drop_unknown_proto")
int tc_nodeport_lb4_wildcard_drop_unknown_proto_setup(struct __ctx_buff *ctx)
{
	setup_services(ctx);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb4_wildcard_drop_unknown_proto")
int tc_nodeport_lb4_wildcard_drop_unknown_proto_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return validate_packet(ctx,
		(__u8 *)client_mac, (__u8 *)lb_mac,
		CLIENT_IP, FRONTEND_IP,
		FRONTEND_PORT, IPPROTO_UDP, CTX_ACT_DROP);
}

/*
 * Test wildcard drop does not touch valid traffic. This is split over 2 tests as
 * per lbXX_no_backend testing.
 */

PKTGEN("tc", "tc_nodeport_lb4_wildcard_drop_not_unknown")
int tc_nodeport_lb4_wildcard_drop_not_unknown_pktgen(struct __ctx_buff *ctx)
{
	/* Generate a packet to the Frontend IP and port, on TCP */
	return build_packet(ctx, FRONTEND_PORT, IPPROTO_TCP);
}

SETUP("tc", "tc_nodeport_lb4_wildcard_drop_not_unknown")
int tc_nodeport_lb4_wildcard_drop_not_unknown_setup(struct __ctx_buff *ctx)
{
	setup_services(ctx);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb4_wildcard_drop_not_unknown")
int tc_nodeport_lb4_wildcard_drop_not_unknown_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* We should receive an ICMP Unreachable */
	return validate_packet(ctx, (__u8 *)lb_mac, (__u8 *)client_mac, FRONTEND_IP, CLIENT_IP,
			       FRONTEND_PORT, IPPROTO_ICMP, CTX_ACT_REDIRECT);
}

PKTGEN("tc", "tc_nodeport_lb4_wildcard_drop_not_unknown2")
int tc_nodeport_lb4_wildcard_drop_not_unknown2_pktgen(struct __ctx_buff *ctx)
{
	/* Generate a packet to the Frontend IP and port, on TCP */
	return build_packet(ctx, FRONTEND_PORT, IPPROTO_TCP);
}

SETUP("tc", "tc_nodeport_lb4_wildcard_drop_not_unknown2")
int tc_nodeport_lb4_wildcard_drop_not_unknown2_setup(struct __ctx_buff *ctx)
{
	if (tail_no_service_ipv4(ctx) != CTX_ACT_REDIRECT)
		return TEST_ERROR;

	setup_services(ctx);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb4_wildcard_drop_not_unknown2")
int tc_nodeport_lb4_wildcard_drop_not_unknown2_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* We should receive an ICMP Unreachable */
	return validate_packet(ctx, (__u8 *)lb_mac, (__u8 *)client_mac, FRONTEND_IP, CLIENT_IP,
			       FRONTEND_PORT, IPPROTO_ICMP, CTX_ACT_OK);
}
