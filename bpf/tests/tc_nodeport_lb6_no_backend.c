// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define SERVICE_NO_BACKEND_RESPONSE
#define ENABLE_MASQUERADE_IPV6		1

#define CLIENT_IP		v6_pod_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		v6_pod_two
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v6_node_two
#define BACKEND_PORT		__bpf_htons(8080)

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;

#include "lib/bpf_host.h"

ASSIGN_CONFIG(bool, enable_no_service_endpoints_routable, true)

#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/icmp.h"

/* Test that a SVC without backends returns a TCP RST or ICMP error */
PKTGEN("tc", "tc_nodeport_no_backend")
int nodeport_no_backend_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)CLIENT_IP,
					  (__u8 *)FRONTEND_IP,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_no_backend")
int nodeport_no_backend_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	union v6addr frontend_ip = {};

	memcpy(frontend_ip.addr, (void *)FRONTEND_IP, 16);

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);

	union v6addr backend_ip = {};

	memcpy(backend_ip.addr, (void *)BACKEND_IP, 16);

	ipcache_v6_add_entry(&backend_ip, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

static __always_inline int
validate_icmpv6_reply_return(const struct __ctx_buff *ctx, __u32 retval) {
	struct validate_icmpv6_reply_args args = {
		.ctx = ctx,
		.src_mac = (__u8 *)lb_mac,
		.dst_mac = (__u8 *)client_mac,
		.src_ip = (__u8 *)FRONTEND_IP,
		.dst_ip = (__u8 *)CLIENT_IP,
		.icmp_type = ICMPV6_DEST_UNREACH,
		.icmp_code = ICMPV6_PORT_UNREACH,
		.checksum = 0x9e14,
		.dst_idx = 1,
		.retval = retval,
	};
	return validate_icmpv6_reply(&args);
}

CHECK("tc", "tc_nodeport_no_backend")
int nodeport_no_backend_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return validate_icmpv6_reply_return(ctx, CTX_ACT_REDIRECT);
}

/* Test that the ICMP error message leaves the node */
PKTGEN("tc", "tc_nodeport_no_backend2_reply")
int nodeport_no_backend2_reply_pktgen(struct __ctx_buff *ctx)
{
	/* Start with the initial request, and let SETUP() below rebuild it. */
	return nodeport_no_backend_pktgen(ctx);
}

SETUP("tc", "tc_nodeport_no_backend2_reply")
int nodeport_no_backend2_reply_setup(struct __ctx_buff *ctx)
{
	if (generate_icmp6_reply(ctx, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH))
		return TEST_ERROR;

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_nodeport_no_backend2_reply")
int nodeport_no_backend2_reply_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return validate_icmpv6_reply_return(ctx, CTX_ACT_OK);
}
