// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Datapath test for the service VIP ICMP echo responder.
 *
 * The responder is split in two: svc_icmp_echo_is_target_v4() is a reads-only
 * probe (run inline in nodeport_lb4) and svc_icmp_echo_send_reply_v4() does the
 * packet writes (run in the CILIUM_CALL_IPV4_SVC_ICMP_ECHO tail-call). This test
 * exercises both in sequence.
 *
 * An ICMPv4 echo-request (type 8) addressed to a service VIP must be turned
 * into an echo-reply in place and reflected back to the client:
 *   - the probe returns 1 (it is a VIP echo-request);
 *   - the reply worker returns CTX_ACT_REDIRECT (reply sent via redirect_self);
 *   - outer IP src/dst are swapped (reply is sourced from the VIP);
 *   - the ICMP type becomes 0 (echo reply) while code, id, seq and payload
 *     are preserved;
 *   - the ICMP checksum is valid (folds to 0 over the message);
 *   - the ethernet addresses are swapped.
 *
 * A negative case (echo to a non-VIP address) asserts the probe returns 0 and
 * the packet is left untouched.
 */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_SVC_ICMP_ECHO_RESPONDER
#include <bpf/config/global.h>

/* The responder does not select a backend, so use "first slot" selection to
 * avoid needing the maglev maps. */
#define LB_SELECTION	LB_SELECTION_FIRST

#include "nodeport_defaults.h"

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/svc_echo.h>
#include "lib/lb.h"

#define CLIENT_IP	bpf_htonl(0x0a0000f0)	/* 10.0.0.240 (client) */
#define VIP_ADDR	bpf_htonl(0x0a00000a)	/* 10.0.0.10  (service VIP) */
#define NOT_A_VIP	bpf_htonl(0x0a00000b)	/* 10.0.0.11  (not a service) */
#define REVNAT		1
#define ECHO_ID		bpf_htons(0x1234)
#define ECHO_SEQ	bpf_htons(0x0001)

/* fd00::f0 client, fd00::a service VIP, fd00::b not-a-service. */
static volatile const union v6addr client_ip6 = {
	.addr = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf0},
};
static volatile const union v6addr vip_addr6 = {
	.addr = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a},
};
static volatile const union v6addr not_a_vip6 = {
	.addr = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b},
};

static volatile const __u8 cmac[ETH_ALEN] = {0x02, 0, 0, 0, 0, 1};	/* client */
static volatile const __u8 nmac[ETH_ALEN] = {0x02, 0, 0, 0, 0, 2};	/* node */

/* IPv6 pseudo-header used to compute/verify the ICMPv6 checksum. */
struct icmp6_pseudo {
	union v6addr saddr;
	union v6addr daddr;
	__be32 len;
	__u8 pad[3];
	__u8 nexthdr;
};

/* 16-byte echo payload so we can assert it survives untouched. */
static const __u8 echo_payload[16] = {
	0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
};

static __always_inline int build_echo(struct __ctx_buff *ctx, __be32 dst)
{
	struct pktgen builder;
	struct iphdr *ip4;
	struct icmphdr *icmp;

	pktgen__init(&builder, ctx);

	ip4 = pktgen__push_ipv4_packet(&builder, (__u8 *)cmac, (__u8 *)nmac,
				       CLIENT_IP, dst);
	if (!ip4)
		return TEST_ERROR;
	ip4->protocol = IPPROTO_ICMP;

	icmp = pktgen__push_icmphdr(&builder);
	if (!icmp)
		return TEST_ERROR;
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = ECHO_ID;
	icmp->un.echo.sequence = ECHO_SEQ;

	if (!pktgen__push_data(&builder, (void *)echo_payload, sizeof(echo_payload)))
		return TEST_ERROR;

	pktgen__finish(&builder);

	/* pktgen leaves the ICMP checksum at 0; fill in a valid one so the input
	 * looks like a real client's echo-request (the responder patches the
	 * checksum incrementally, which is only correct for a valid input). */
	{
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;
		struct iphdr *l3 = data + sizeof(struct ethhdr);
		struct icmphdr *l4;
		int icmp_len = sizeof(struct icmphdr) + sizeof(echo_payload);

		if ((void *)l3 + sizeof(*l3) > data_end)
			return TEST_ERROR;
		l4 = (void *)l3 + sizeof(*l3);
		if ((void *)l4 + icmp_len > data_end)
			return TEST_ERROR;
		l4->checksum = 0;
		l4->checksum = csum_fold(csum_diff(NULL, 0, l4, icmp_len, 0));
	}
	return 0;
}

PKTGEN("tc", "svc_icmp_echo_vip")
int svc_icmp_echo_vip_pktgen(struct __ctx_buff *ctx)
{
	return build_echo(ctx, VIP_ADDR);
}

SETUP("tc", "svc_icmp_echo_vip")
int svc_icmp_echo_vip_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	int l4_off, ret;

	/* A LoadBalancer/ClusterIP frontend parents a wildcard service entry
	 * keyed on the VIP with a wildcard port/proto -- that is what the
	 * responder looks up to recognise the VIP. */
	lb_v4_add_service(VIP_ADDR, LB_SVC_WILDCARD_DPORT, LB_SVC_WILDCARD_PROTO,
			  1, REVNAT);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ip4 = data + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		return TEST_ERROR;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	/* Detection (reads-only, runs inline in nodeport_lb4) recognises the VIP
	 * echo-request. */
	ret = svc_icmp_echo_is_target_v4(ctx, ip4, l4_off);
	if (ret != 1)
		return TEST_ERROR;

	/* The reply worker (runs in the CILIUM_CALL_IPV4_SVC_ICMP_ECHO tail-call)
	 * re-validates ip4 itself and crafts the reply. */
	ret = svc_icmp_echo_send_reply_v4(ctx);
	if (ret != CTX_ACT_REDIRECT)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "svc_icmp_echo_vip")
int svc_icmp_echo_vip_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *eth;
	struct iphdr *ip4;
	struct icmphdr *icmp;
	__u8 *payload;
	__u32 i;
	__wsum sum;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	if (*status_code != TEST_PASS)
		test_fatal("SETUP failed with status code: %d", *status_code);

	eth = data + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");
	/* MACs swapped: reply goes back to the client. */
	if (memcmp(eth->h_dest, (__u8 *)cmac, ETH_ALEN) != 0)
		test_fatal("eth dst not swapped to the client MAC");
	if (memcmp(eth->h_source, (__u8 *)nmac, ETH_ALEN) != 0)
		test_fatal("eth src not swapped to the node MAC");

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("ip out of bounds");
	if (ip4->saddr != VIP_ADDR)
		test_fatal("reply not sourced from the VIP");
	if (ip4->daddr != CLIENT_IP)
		test_fatal("reply not addressed to the client");

	icmp = (void *)ip4 + sizeof(*ip4);
	if ((void *)icmp + sizeof(*icmp) > data_end)
		test_fatal("icmp out of bounds");
	if (icmp->type != ICMP_ECHOREPLY)
		test_fatal("icmp type not flipped to echo reply");
	if (icmp->code != 0)
		test_fatal("icmp code must be preserved");
	if (icmp->un.echo.id != ECHO_ID)
		test_fatal("echo id must be preserved");
	if (icmp->un.echo.sequence != ECHO_SEQ)
		test_fatal("echo sequence must be preserved");

	payload = (void *)icmp + sizeof(*icmp);
	if ((void *)payload + sizeof(echo_payload) > data_end)
		test_fatal("echo payload out of bounds");
	for (i = 0; i < sizeof(echo_payload); i++)
		if (payload[i] != echo_payload[i])
			test_fatal("echo payload byte %d changed", i);

	/* The ICMP checksum must be valid: summing the whole message (header +
	 * payload, checksum field included) folds to 0. */
	sum = csum_diff(NULL, 0, icmp, sizeof(*icmp) + sizeof(echo_payload), 0);
	if (csum_fold(sum) != 0)
		test_fatal("icmp checksum invalid after type flip");

	test_finish();
}

/* Negative: an echo to a non-service address is left untouched. */
PKTGEN("tc", "svc_icmp_echo_non_vip")
int svc_icmp_echo_non_vip_pktgen(struct __ctx_buff *ctx)
{
	return build_echo(ctx, NOT_A_VIP);
}

SETUP("tc", "svc_icmp_echo_non_vip")
int svc_icmp_echo_non_vip_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	int l4_off, ret;

	lb_v4_add_service(VIP_ADDR, LB_SVC_WILDCARD_DPORT, LB_SVC_WILDCARD_PROTO,
			  1, REVNAT);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ip4 = data + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		return TEST_ERROR;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	/* Not a VIP -> detection returns 0 and the caller keeps its default
	 * handling; the reply worker is never reached, so the packet is untouched. */
	ret = svc_icmp_echo_is_target_v4(ctx, ip4, l4_off);
	if (ret != 0)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "svc_icmp_echo_non_vip")
int svc_icmp_echo_non_vip_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *ip4;
	struct icmphdr *icmp;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	if (*status_code != TEST_PASS)
		test_fatal("SETUP failed with status code: %d", *status_code);

	ip4 = data + sizeof(*status_code) + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("ip out of bounds");
	/* Untouched: still client -> non-VIP. */
	if (ip4->saddr != CLIENT_IP || ip4->daddr != NOT_A_VIP)
		test_fatal("non-VIP echo must be left untouched");

	icmp = (void *)ip4 + sizeof(*ip4);
	if ((void *)icmp + sizeof(*icmp) > data_end)
		test_fatal("icmp out of bounds");
	if (icmp->type != ICMP_ECHO)
		test_fatal("non-VIP echo type must stay echo-request");

	test_finish();
}

/* ------------------------------- IPv6 ------------------------------------- */

static __always_inline int build_echo6(struct __ctx_buff *ctx,
				       const volatile union v6addr *dst)
{
	struct pktgen builder;
	struct ipv6hdr *ip6;
	struct icmp6hdr *icmp;

	pktgen__init(&builder, ctx);

	ip6 = pktgen__push_ipv6_packet(&builder, (__u8 *)cmac, (__u8 *)nmac,
				       (__u8 *)client_ip6.addr, (__u8 *)dst->addr);
	if (!ip6)
		return TEST_ERROR;
	ip6->nexthdr = IPPROTO_ICMPV6;

	icmp = pktgen__push_icmp6hdr(&builder);
	if (!icmp)
		return TEST_ERROR;
	icmp->icmp6_type = ICMPV6_ECHO_REQUEST;
	icmp->icmp6_code = 0;
	icmp->icmp6_identifier = ECHO_ID;
	icmp->icmp6_sequence = ECHO_SEQ;

	if (!pktgen__push_data(&builder, (void *)echo_payload, sizeof(echo_payload)))
		return TEST_ERROR;

	pktgen__finish(&builder);

	/* Fill in a valid ICMPv6 checksum (over the pseudo-header + message), so
	 * the input looks like a real echo-request; the responder patches it
	 * incrementally, which is only correct for a valid input. */
	{
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;
		struct ipv6hdr *l3 = data + sizeof(struct ethhdr);
		struct icmp6hdr *l4;
		int icmp_len = sizeof(struct icmp6hdr) + sizeof(echo_payload);
		struct icmp6_pseudo pseudo = {};
		__wsum sum;

		if ((void *)l3 + sizeof(*l3) > data_end)
			return TEST_ERROR;
		l4 = (void *)l3 + sizeof(*l3);
		if ((void *)l4 + icmp_len > data_end)
			return TEST_ERROR;

		memcpy(&pseudo.saddr, (void *)client_ip6.addr, sizeof(pseudo.saddr));
		memcpy(&pseudo.daddr, (void *)dst->addr, sizeof(pseudo.daddr));
		pseudo.len = bpf_htonl(icmp_len);
		pseudo.nexthdr = IPPROTO_ICMPV6;

		l4->icmp6_cksum = 0;
		sum = csum_diff(NULL, 0, &pseudo, sizeof(pseudo), 0);
		l4->icmp6_cksum = csum_fold(csum_diff(NULL, 0, l4, icmp_len, sum));
	}
	return 0;
}

PKTGEN("tc", "svc_icmp_echo_vip6")
int svc_icmp_echo_vip6_pktgen(struct __ctx_buff *ctx)
{
	return build_echo6(ctx, &vip_addr6);
}

SETUP("tc", "svc_icmp_echo_vip6")
int svc_icmp_echo_vip6_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int l4_off, ret;
	__u8 nexthdr;

	lb_v6_add_service((const union v6addr *)&vip_addr6, LB_SVC_WILDCARD_DPORT,
			  LB_SVC_WILDCARD_PROTO, 1, REVNAT);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ip6 = data + sizeof(struct ethhdr);
	if ((void *)ip6 + sizeof(*ip6) > data_end)
		return TEST_ERROR;

	nexthdr = ip6->nexthdr;
	l4_off = ETH_HLEN + ipv6_hdrlen(ctx, &nexthdr);

	ret = svc_icmp_echo_is_target_v6(ctx, ip6, l4_off);
	if (ret != 1)
		return TEST_ERROR;

	ret = svc_icmp_echo_send_reply_v6(ctx);
	if (ret != CTX_ACT_REDIRECT)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "svc_icmp_echo_vip6")
int svc_icmp_echo_vip6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	struct icmp6hdr *icmp;
	struct icmp6_pseudo pseudo = {};
	__u8 *payload;
	__u32 i;
	__wsum sum;
	int icmp_len;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	if (*status_code != TEST_PASS)
		test_fatal("SETUP failed with status code: %d", *status_code);

	eth = data + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");
	if (memcmp(eth->h_dest, (__u8 *)cmac, ETH_ALEN) != 0)
		test_fatal("eth dst not swapped to the client MAC");
	if (memcmp(eth->h_source, (__u8 *)nmac, ETH_ALEN) != 0)
		test_fatal("eth src not swapped to the node MAC");

	ip6 = (void *)eth + sizeof(*eth);
	if ((void *)ip6 + sizeof(*ip6) > data_end)
		test_fatal("ip6 out of bounds");
	if (memcmp(&ip6->saddr, (void *)vip_addr6.addr, 16) != 0)
		test_fatal("reply not sourced from the VIP");
	if (memcmp(&ip6->daddr, (void *)client_ip6.addr, 16) != 0)
		test_fatal("reply not addressed to the client");

	icmp = (void *)ip6 + sizeof(*ip6);
	if ((void *)icmp + sizeof(*icmp) > data_end)
		test_fatal("icmp6 out of bounds");
	if (icmp->icmp6_type != ICMPV6_ECHO_REPLY)
		test_fatal("icmp6 type not flipped to echo reply");
	if (icmp->icmp6_code != 0)
		test_fatal("icmp6 code must be preserved");
	if (icmp->icmp6_identifier != ECHO_ID)
		test_fatal("echo id must be preserved");
	if (icmp->icmp6_sequence != ECHO_SEQ)
		test_fatal("echo sequence must be preserved");

	payload = (void *)icmp + sizeof(*icmp);
	if ((void *)payload + sizeof(echo_payload) > data_end)
		test_fatal("echo payload out of bounds");
	for (i = 0; i < sizeof(echo_payload); i++)
		if (payload[i] != echo_payload[i])
			test_fatal("echo payload byte %d changed", i);

	/* The ICMPv6 checksum must be valid: summing the pseudo-header plus the
	 * ICMPv6 message (checksum field included) folds to 0. */
	icmp_len = sizeof(*icmp) + sizeof(echo_payload);
	memcpy(&pseudo.saddr, &ip6->saddr, sizeof(pseudo.saddr));
	memcpy(&pseudo.daddr, &ip6->daddr, sizeof(pseudo.daddr));
	pseudo.len = bpf_htonl(icmp_len);
	pseudo.nexthdr = IPPROTO_ICMPV6;
	sum = csum_diff(NULL, 0, &pseudo, sizeof(pseudo), 0);
	if (csum_fold(csum_diff(NULL, 0, icmp, icmp_len, sum)) != 0)
		test_fatal("icmp6 checksum invalid after type flip");

	test_finish();
}

/* Negative: an ICMPv6 echo to a non-service address is left untouched. */
PKTGEN("tc", "svc_icmp_echo_non_vip6")
int svc_icmp_echo_non_vip6_pktgen(struct __ctx_buff *ctx)
{
	return build_echo6(ctx, &not_a_vip6);
}

SETUP("tc", "svc_icmp_echo_non_vip6")
int svc_icmp_echo_non_vip6_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int l4_off, ret;
	__u8 nexthdr;

	lb_v6_add_service((const union v6addr *)&vip_addr6, LB_SVC_WILDCARD_DPORT,
			  LB_SVC_WILDCARD_PROTO, 1, REVNAT);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ip6 = data + sizeof(struct ethhdr);
	if ((void *)ip6 + sizeof(*ip6) > data_end)
		return TEST_ERROR;

	nexthdr = ip6->nexthdr;
	l4_off = ETH_HLEN + ipv6_hdrlen(ctx, &nexthdr);

	ret = svc_icmp_echo_is_target_v6(ctx, ip6, l4_off);
	/* Not a VIP -> left for the caller's default handling. */
	if (ret != 0)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "svc_icmp_echo_non_vip6")
int svc_icmp_echo_non_vip6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *ip6;
	struct icmp6hdr *icmp;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	if (*status_code != TEST_PASS)
		test_fatal("SETUP failed with status code: %d", *status_code);

	ip6 = data + sizeof(*status_code) + sizeof(struct ethhdr);
	if ((void *)ip6 + sizeof(*ip6) > data_end)
		test_fatal("ip6 out of bounds");
	/* Untouched: still client -> non-VIP. */
	if (memcmp(&ip6->saddr, (void *)client_ip6.addr, 16) != 0 ||
	    memcmp(&ip6->daddr, (void *)not_a_vip6.addr, 16) != 0)
		test_fatal("non-VIP echo must be left untouched");

	icmp = (void *)ip6 + sizeof(*ip6);
	if ((void *)icmp + sizeof(*icmp) > data_end)
		test_fatal("icmp6 out of bounds");
	if (icmp->icmp6_type != ICMPV6_ECHO_REQUEST)
		test_fatal("non-VIP echo type must stay echo-request");

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
