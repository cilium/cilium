// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT

/* Skip ingress policy checks */
#define USE_BPF_PROG_FOR_INGRESS_POLICY

#define CLIENT_IP	    v4_ext_one
#define CLIENT_PORT	    __bpf_htons(5060)

#define FRONTEND_IP	    v4_svc_two
#define FRONTEND_PORT	    __bpf_htons(5060)

#define BACKEND_IP	    v4_pod_two
#define BACKEND_PORT	    __bpf_htons(5060)

#define LB_IP		    v4_node_one
#define IPV4_DIRECT_ROUTING LB_IP

#define fib_lookup	    mock_fib_lookup

#define SIP_CALL_ID	    "a84b4c76e66710@pc33.atlanta.com"
#define SIP_CALL_ID_HASH    0xb93dd48c

#define sip_invite                              \
	"INVITE sip:bob@biloxi.com SIP/2.0\r\n" \
	"Call-ID: " SIP_CALL_ID "\r\n"          \
	"CSeq: 314159 INVITE\r\n"               \
	"Content-Length: 0\r\n"                 \
	"\r\n"

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;
static volatile const __u8 *remote_backend_mac = mac_five;

long mock_fib_lookup(
	__maybe_unused void *ctx, struct bpf_fib_lookup *params,
	__maybe_unused int plen, __maybe_unused __u32 flags)
{
	params->ifindex = 0;

	if (params->ipv4_dst == BACKEND_IP) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(
			params->dmac, (__u8 *)remote_backend_mac, ETH_ALEN);
	} else {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
	}

	return 0;
}

#include "lib/bpf_host.h"

#include "lib/ipcache.h"
#include "lib/lb.h"

/* Test that a sip SVC request that is LBed to a remote backend
 * - gets DNATed,
 * - preserve the original source IP + port
 * - gets redirected back out by TC
 */
PKTGEN("tc", "sip_lb")
int sip_lb_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(
		&builder, (__u8 *)client_mac, (__u8 *)lb_mac, CLIENT_IP,
		FRONTEND_IP, CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, sip_invite, sizeof(sip_invite) - 1);
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "sip_lb")
int sip_lb_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service_sip(
		FRONTEND_IP, FRONTEND_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v4_add_backend(
		FRONTEND_IP, FRONTEND_PORT, 1, 124, BACKEND_IP, BACKEND_PORT,
		IPPROTO_UDP, 0);

	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "sip_lb")
int sip_lb_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct udphdr *l4;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	test_finish();
}
