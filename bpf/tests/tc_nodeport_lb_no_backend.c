// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

/* Enable code paths under test */
#define ENABLE_IPV4			1
#define ENABLE_IPV6			1
#define ENABLE_NODEPORT			1
#define SERVICE_NO_BACKEND_RESPONSE	1
#define ENABLE_MASQUERADE_IPV4		1
#define ENABLE_MASQUERADE_IPV6		1

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_IPV6		v6_svc_one
#define FRONTEND_PORT		tcp_svc_one

#include "lib/bpf_host.h"

ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, { .be32 = FRONTEND_IP})
ASSIGN_CONFIG(bool, enable_no_service_endpoints_routable, true)

#include "lib/icmp.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

const __u8 lb4_udp_clusterip[] = {
	SCAPY_BUF_BYTES(lb4_udp_clusterip)
};

const __u8 lb4_udp_clusterip_icmp_unreach[] = {
	SCAPY_BUF_BYTES(lb4_udp_clusterip_icmp_unreach)
};

const __u8 lb6_udp_clusterip[] = {
	SCAPY_BUF_BYTES(lb6_udp_clusterip)
};

const __u8 lb6_udp_clusterip_icmp_unreach[] = {
	SCAPY_BUF_BYTES(lb6_udp_clusterip_icmp_unreach)
};

/* Test that a SVC without backends returns an ICMP error */
PKTGEN(PROG_TYPE, "tc_nodeport_no_backend4")
int nodeport_no_backend4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, lb4_udp_clusterip,
			sizeof(lb4_udp_clusterip));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "tc_nodeport_no_backend4")
int nodeport_no_backend4_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_UDP, 0, revnat_id);

	return netdev_receive_packet(ctx);
}

static __always_inline int
validate_icmp_reply(const struct __ctx_buff *ctx, __u32 retval)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	test_log("Status code: %d", *status_code);
	assert(*status_code == retval);

	ASSERT_CTX_BUF_OFF("lb4_udp_clusterip_icmp_unreach",
			   "Ether", ctx, sizeof(__u32),
			   lb4_udp_clusterip_icmp_unreach,
			   sizeof(lb4_udp_clusterip_icmp_unreach));

	test_finish();
}

CHECK(PROG_TYPE, "tc_nodeport_no_backend4")
int nodeport_no_backend4_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return validate_icmp_reply(ctx, CTX_ACT_REDIRECT);
}

/* Test that the ICMP error message leaves the node */
PKTGEN(PROG_TYPE, "tc_nodeport_no_backend4_2_reply")
int nodeport_no_backend4_2_reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, lb4_udp_clusterip_icmp_unreach,
			sizeof(lb4_udp_clusterip_icmp_unreach));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "tc_nodeport_no_backend4_2_reply")
int nodeport_no_backend4_2_reply_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_no_backend4_2_reply")
int nodeport_no_backend4_2_reply_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return validate_icmp_reply(ctx, CTX_ACT_OK);
}

/* Test that a SVC without backends returns an ICMP error */
PKTGEN(PROG_TYPE, "tc_nodeport_no_backend6")
int nodeport_no_backend6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, lb6_udp_clusterip,
			sizeof(lb6_udp_clusterip));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "tc_nodeport_no_backend6")
int nodeport_no_backend6_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	union v6addr frontend_ip = {};

	memcpy(frontend_ip.addr, (void *)FRONTEND_IPV6, 16);

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_UDP, 0, revnat_id);

	return netdev_receive_packet(ctx);
}

static __always_inline int
validate_icmpv6_reply_return(const struct __ctx_buff *ctx, __u32 retval)
{
	struct validate_icmpv6_reply_args args = {
		.ctx = ctx,
		.buf_expected = lb6_udp_clusterip_icmp_unreach,
		.buf_len = sizeof(lb6_udp_clusterip_icmp_unreach),
		.dst_idx = 1,
		.retval = retval,
	};
	return validate_icmpv6_reply(&args);
}

CHECK(PROG_TYPE, "tc_nodeport_no_backend6")
int nodeport_no_backend6_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return validate_icmpv6_reply_return(ctx, CTX_ACT_REDIRECT);
}

/* Test that the ICMP error message leaves the node */
PKTGEN(PROG_TYPE, "tc_nodeport_no_backend6_2_reply")
int nodeport_no_backend6_2_reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, lb6_udp_clusterip_icmp_unreach,
			sizeof(lb6_udp_clusterip_icmp_unreach));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "tc_nodeport_no_backend6_2_reply")
int nodeport_no_backend6_2_reply_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "tc_nodeport_no_backend6_2_reply")
int nodeport_no_backend6_2_reply_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return validate_icmpv6_reply_return(ctx, CTX_ACT_OK);
}
