// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */
#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "lib/sip.h"

/* Enable code paths under test */
#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define ENABLE_NODEPORT		1
#define ENABLE_EGRESS_GATEWAY	1
#define ENABLE_MASQUERADE_IPV4	1
#define ENABLE_MASQUERADE_IPV6	1
#define ENABLE_HOST_FIREWALL	1
#define ENCAP_IFINDEX		42
#define SECONDARY_IFACE_IFINDEX 44

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(5060)
#define CLIENT_NODE_IP		v4_node_one
#define CLIENT_IDENTITY		123456
#define GATEWAY_NODE_IP		v4_node_two
#define EXTERNAL_SVC_IP		v4_ext_one
#define EXTERNAL_SVC_PORT	__bpf_htons(5060)
#define EGRESS_IP		IPV4(1, 2, 3, 4)

#define SIP_CALL_ID		"a84b4c76e66710@pc33.atlanta.com"
#define SIP_CALL_ID_HASH	0xb93dd48c

#define sip_register                              \
	"REGISTER sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"            \
	"CSeq: 314159 INVITE\r\n"                 \
	"Content-Length: 0\r\n"                   \
	"\r\n"

#define sip_subscribe                              \
	"SUBSCRIBE sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"             \
	"CSeq: 314159 INVITE\r\n"                  \
	"Content-Length: 0\r\n"                    \
	"\r\n"

#define sip_options                              \
	"OPTIONS sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"           \
	"CSeq: 314159 INVITE\r\n"                \
	"Content-Length: 0\r\n"                  \
	"\r\n"

#define sip_message                              \
	"MESSAGE sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"           \
	"CSeq: 314159 INVITE\r\n"                \
	"Content-Length: 0\r\n"                  \
	"\r\n"

#define sip_publish                              \
	"PUBLISH sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"           \
	"CSeq: 314159 INVITE\r\n"                \
	"Content-Length: 0\r\n"                  \
	"\r\n"

#define sip_invite                              \
	"INVITE sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"          \
	"CSeq: 314159 INVITE\r\n"               \
	"Content-Length: 0\r\n"                 \
	"\r\n"

#define sip_cancel                              \
	"CANCEL sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"          \
	"CSeq: 314159 INVITE\r\n"               \
	"Content-Length: 0\r\n"                 \
	"\r\n"

#define sip_update                              \
	"UPDATE sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"          \
	"CSeq: 314159 INVITE\r\n"               \
	"Content-Length: 0\r\n"                 \
	"\r\n"

#define sip_notify                              \
	"NOTIFY sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"          \
	"CSeq: 314159 INVITE\r\n"               \
	"Content-Length: 0\r\n"                 \
	"\r\n"

#define sip_prack                              \
	"PRACK sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"         \
	"CSeq: 314159 INVITE\r\n"              \
	"Content-Length: 0\r\n"                \
	"\r\n"

#define sip_refer                              \
	"REFER sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"         \
	"CSeq: 314159 INVITE\r\n"              \
	"Content-Length: 0\r\n"                \
	"\r\n"

#define sip_info                              \
	"INFO sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"        \
	"CSeq: 314159 INVITE\r\n"             \
	"Content-Length: 0\r\n"               \
	"\r\n"

#define sip_ack                              \
	"ACK sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"       \
	"CSeq: 314159 INVITE\r\n"            \
	"Content-Length: 0\r\n"              \
	"\r\n"

#define sip_bye                              \
	"BYE sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"       \
	"CSeq: 314159 INVITE\r\n"            \
	"Content-Length: 0\r\n"              \
	"\r\n"

#define sip_resp                       \
	"SIP/2.0 200 OK\r\n"           \
	"Call-ID: " SIP_CALL_ID "\r\n" \
	"CSeq: 314159 INVITE\r\n"      \
	"Content-Length: 0\r\n"        \
	"\r\n"

#define sip_invite_no_callid                           \
	"INVITE sip:bob@biloxi.com SIP/2.0\r\n"        \
	"Crap-ID: a84b4c76e66710@pc33.atlanta.com\r\n" \
	"CSeq: 314159 INVITE\r\n"                      \
	"Content-Length: 0\r\n"                        \
	"\r\n"

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *ext_svc_mac = mac_three;

enum sip_test {
	TEST_RESP,
	TEST_REGISTER,
	TEST_SUBSCRIBE,
	TEST_OPTIONS,
	TEST_MESSAGE,
	TEST_PUBLISH,
	TEST_INVITE,
	TEST_CANCEL,
	TEST_UPDATE,
	TEST_NOTIFY,
	TEST_PRACK,
	TEST_REFER,
	TEST_INFO,
	TEST_ACK,
	TEST_BYE,
	TEST_INVITE_NO_CALLID,
};

static __always_inline int
sip_pktgen_common(struct __ctx_buff *ctx, enum sip_test test)
{
	struct pktgen builder;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)ext_svc_mac);

	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;
	l3->saddr = CLIENT_IP;
	l3->daddr = EXTERNAL_SVC_IP;
	l3->protocol = IPPROTO_UDP;

	l4 = pktgen__push_default_udphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = CLIENT_PORT;
	l4->dest = EXTERNAL_SVC_PORT;

	switch (test) {
	case TEST_RESP:
		data = pktgen__push_data(&builder, sip_resp, sizeof(sip_resp) - 1);
		break;

	case TEST_REGISTER:
		data = pktgen__push_data(
			&builder, sip_register, sizeof(sip_register) - 1);
		break;

	case TEST_SUBSCRIBE:
		data = pktgen__push_data(
			&builder, sip_subscribe, sizeof(sip_subscribe) - 1);
		break;

	case TEST_OPTIONS:
		data = pktgen__push_data(
			&builder, sip_options, sizeof(sip_options) - 1);
		break;

	case TEST_MESSAGE:
		data = pktgen__push_data(
			&builder, sip_message, sizeof(sip_message) - 1);
		break;

	case TEST_PUBLISH:
		data = pktgen__push_data(
			&builder, sip_publish, sizeof(sip_publish) - 1);
		break;

	case TEST_INVITE:
		data = pktgen__push_data(
			&builder, sip_invite, sizeof(sip_invite) - 1);
		break;

	case TEST_CANCEL:
		data = pktgen__push_data(
			&builder, sip_cancel, sizeof(sip_cancel) - 1);
		break;

	case TEST_UPDATE:
		data = pktgen__push_data(
			&builder, sip_update, sizeof(sip_update) - 1);
		break;

	case TEST_NOTIFY:
		data = pktgen__push_data(
			&builder, sip_notify, sizeof(sip_notify) - 1);
		break;

	case TEST_PRACK:
		data = pktgen__push_data(
			&builder, sip_prack, sizeof(sip_prack) - 1);
		break;

	case TEST_REFER:
		data = pktgen__push_data(
			&builder, sip_refer, sizeof(sip_refer) - 1);
		break;

	case TEST_INFO:
		data = pktgen__push_data(&builder, sip_info, sizeof(sip_info) - 1);
		break;

	case TEST_BYE:
		data = pktgen__push_data(&builder, sip_bye, sizeof(sip_bye) - 1);
		break;

	case TEST_ACK:
		data = pktgen__push_data(&builder, sip_ack, sizeof(sip_ack) - 1);
		break;

	case TEST_INVITE_NO_CALLID:
		data = pktgen__push_data(
			&builder, sip_invite_no_callid,
			sizeof(sip_invite_no_callid) - 1);
		break;
	}

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

PKTGEN("tc", "sip_resp")
int sip_resp_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_RESP);
}

PKTGEN("tc", "sip_register")
int sip_register_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_REGISTER);
}

PKTGEN("tc", "sip_subcribe")
int sip_subscribe_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_SUBSCRIBE);
}

PKTGEN("tc", "sip_options")
int sip_options_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_OPTIONS);
}

PKTGEN("tc", "sip_message")
int sip_message_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_MESSAGE);
}

PKTGEN("tc", "sip_publish")
int sip_publish_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_PUBLISH);
}

PKTGEN("tc", "sip_invite")
int sip_invite_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_INVITE);
}

PKTGEN("tc", "sip_cancel")
int sip_cancel_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_CANCEL);
}

PKTGEN("tc", "sip_update")
int sip_update_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_UPDATE);
}

PKTGEN("tc", "sip_notify")
int sip_notify_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_NOTIFY);
}

PKTGEN("tc", "sip_prack")
int sip_prack_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_PRACK);
}

PKTGEN("tc", "sip_refer")
int sip_refer_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_REFER);
}

PKTGEN("tc", "sip_info")
int sip_info_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_INFO);
}

PKTGEN("tc", "sip_ack")
int sip_ack_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_ACK);
}

PKTGEN("tc", "sip_bye")
int sip_bye_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_BYE);
}

PKTGEN("tc", "sip_invite_no_callid")
int sip_no_callid_pktgen(struct __ctx_buff *ctx)
{
	return sip_pktgen_common(ctx, TEST_INVITE_NO_CALLID);
}

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

CHECK("tc", "sip_register")
int bpf_register_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_subcribe")
int bpf_subscribe_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_options")
int bpf_options_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_message")
int bpf_message_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_publish")
int bpf_publish_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_invite")
int bpf_invite_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_cancel")
int bpf_cancel_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_update")
int bpf_update_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_notify")
int bpf_notify_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_prack")
int bpf_prack_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_refer")
int bpf_refer_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_info")
int bpf_info_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_ack")
int bpf_ack_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_bye")
int bpf_bye_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_resp")
int bpf_resp_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);
	if (got != SIP_CALL_ID_HASH)
		test_fatal("hash mismatch: got=%lx expected=%lx", got,
			   SIP_CALL_ID_HASH);

	test_finish();
}

CHECK("tc", "sip_invite_no_callid")
int bpf_test_no_callid(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	__u32 got = sip_inspect(ctx);

	if (got != 0)
		test_fatal("expected hash=0 for missing Call-ID, got=0x%08x", got);

	test_finish();
}
