// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

/* Enable code paths under test */
#define ENABLE_IPV4			1
#define ENABLE_IPV6			1
#define SERVICE_NO_BACKEND_RESPONSE	1

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_IPV6		v6_svc_one
#define FRONTEND_PORT		tcp_svc_one

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(bool, enable_no_service_endpoints_routable, true)

#include "lib/ipcache.h"
#include "lib/lb.h"

const __u8 lb4_ew_udp_nodeport[] = {
	SCAPY_BUF_BYTES(lb4_ew_udp_nodeport)
};

const __u8 lb4_ew_udp_nodeport_icmp_unreach[] = {
	SCAPY_BUF_BYTES(lb4_ew_udp_nodeport_icmp_unreach)
};

const __u8 lb6_ew_udp_nodeport[] = {
	SCAPY_BUF_BYTES(lb6_ew_udp_nodeport)
};

const __u8 lb6_ew_udp_nodeport_icmp_unreach[] = {
	SCAPY_BUF_BYTES(lb6_ew_udp_nodeport_icmp_unreach)
};

/* Test that a SVC without backends returns an ICMP error */
PKTGEN(PROG_TYPE, "tc_lxc4_no_backend")
int lxc4_no_backend_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, lb4_ew_udp_nodeport,
			sizeof(lb4_ew_udp_nodeport));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "tc_lxc4_no_backend")
int lxc4_no_backend_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_UDP, 0, revnat_id);

	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "tc_lxc4_no_backend")
int lxc4_no_backend_check(__maybe_unused const struct __ctx_buff *ctx)
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
	assert(*status_code == CTX_ACT_REDIRECT);

	ASSERT_CTX_BUF_OFF("lb4_ew_udp_nodeport_icmp_unreach",
			   "Ether", ctx, sizeof(__u32),
			   lb4_ew_udp_nodeport_icmp_unreach,
			   sizeof(lb4_ew_udp_nodeport_icmp_unreach));

	test_finish();
}

/* Test that a SVC without backends returns an ICMP error */
PKTGEN(PROG_TYPE, "tc_lxc6_no_backend")
int lxc6_no_backend_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, lb6_ew_udp_nodeport,
			sizeof(lb6_ew_udp_nodeport));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "tc_lxc6_no_backend")
int lxc6_no_backend_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	union v6addr frontend_ip = {};

	memcpy(frontend_ip.addr, (void *)FRONTEND_IPV6, 16);

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_UDP, 0, revnat_id);

	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "tc_lxc6_no_backend")
int lxc6_no_backend_check(__maybe_unused const struct __ctx_buff *ctx)
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
	assert(*status_code == CTX_ACT_REDIRECT);

	ASSERT_CTX_BUF_OFF("lb6_ew_udp_nodeport_icmp_unreach",
			   "Ether", ctx, sizeof(__u32),
			   lb6_ew_udp_nodeport_icmp_unreach,
			   sizeof(lb6_ew_udp_nodeport_icmp_unreach));

	test_finish();
}
