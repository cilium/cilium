// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define SERVICE_NO_BACKEND_RESPONSE

#define SERVICE_IP	v4_svc_one
#define SERVICE_PORT	tcp_svc_three

#include "lib/bpf_host.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/nodeport.h"

static __always_inline void setup_services(struct __ctx_buff *ctx __maybe_unused)
{
	lb_v4_add_service(SERVICE_IP, SERVICE_PORT, IPPROTO_TCP, 1, 1);
	lb_v4_add_service(SERVICE_IP, SERVICE_PORT, IPPROTO_UDP, 1, 1);
	lb_v4_add_service(SERVICE_IP, LB_SVC_WILDCARD_DPORT, LB_SVC_WILDCARD_PROTO, 1, 1);
}

#define __assert_status(__ctx, __expected) do {			\
	void *__data = (void *)(long)(__ctx)->data;		\
	void *__data_end = (void *)(long)(__ctx)->data_end;	\
	if (__data + sizeof(__u32) > __data_end) {		\
		test_fatal("status code out of bounds");	\
	}							\
	assert(*(__u32 *)__data == (__expected));		\
} while (0)

/* Test UNKNOWN_L4 with GRE */
PKTGEN("tc", "tc_nodeport_lb4_unknownl4_drop_gre")
int tc_nodeport_lb4_unknownl4_drop_gre_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(GRE_PKT, v4_gre_v4_udp);
	BUILDER_PUSH_BUF(builder, GRE_PKT);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_lb4_unknownl4_drop_gre")
int tc_nodeport_lb4_unknownl4_drop_gre_setup(struct __ctx_buff *ctx)
{
	setup_services(ctx);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb4_unknownl4_drop_gre")
int tc_nodeport_lb4_unknownl4_drop_gre_check(const struct __ctx_buff *ctx)
{
	test_init();

	BUF_DECL(GRE_EXP, v4_gre_v4_udp);
	ASSERT_CTX_BUF_OFF("gre_ok", "Ether", ctx, sizeof(__u32),
			   GRE_EXP, sizeof(BUF(GRE_EXP)));
	__assert_status(ctx, CTX_ACT_DROP);

	test_finish();
	return 0;
}

/* Test UNKNOWN_L4 with ESP */
PKTGEN("tc", "tc_nodeport_lb4_unknownl4_drop_esp")
int tc_nodeport_lb4_unknownl4_drop_esp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(ESP_PKT, v4_esp);
	BUILDER_PUSH_BUF(builder, ESP_PKT);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_lb4_unknownl4_drop_esp")
int tc_nodeport_lb4_unknownl4_drop_esp_setup(struct __ctx_buff *ctx)
{
	setup_services(ctx);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb4_unknownl4_drop_esp")
int tc_nodeport_lb4_unknownl4_drop_esp_check(const struct __ctx_buff *ctx)
{
	test_init();

	BUF_DECL(ESP_EXP, v4_esp);
	ASSERT_CTX_BUF_OFF("esp_ok", "Ether", ctx, sizeof(__u32),
			   ESP_EXP, sizeof(BUF(ESP_EXP)));
	__assert_status(ctx, CTX_ACT_DROP);

	test_finish();
	return 0;
}

/* Test UNKNOWN_L4 with RSVP */
PKTGEN("tc", "tc_nodeport_lb4_unknownl4_drop_rsvp")
int tc_nodeport_lb4_unknownl4_drop_rsvp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(RSVP_PKT, v4_rsvp);
	BUILDER_PUSH_BUF(builder, RSVP_PKT);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_lb4_unknownl4_drop_rsvp")
int tc_nodeport_lb4_unknownl4_drop_rsvp_setup(struct __ctx_buff *ctx)
{
	setup_services(ctx);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb4_unknownl4_drop_rsvp")
int tc_nodeport_lb4_unknownl4_drop_rsvp_check(const struct __ctx_buff *ctx)
{
	test_init();

	BUF_DECL(RSVP_EXP, v4_rsvp);
	ASSERT_CTX_BUF_OFF("rsvp_ok", "Ether", ctx, sizeof(__u32),
			   RSVP_EXP, sizeof(BUF(RSVP_EXP)));
	__assert_status(ctx, CTX_ACT_DROP);

	test_finish();
	return 0;
}
