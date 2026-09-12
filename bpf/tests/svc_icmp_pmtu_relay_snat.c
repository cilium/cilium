// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Datapath test for the SNAT-mode branch of the service ICMP PMTU relay.
 *
 * Unlike DSR, a SNAT-mode backend cannot be re-derived statelessly, so the
 * relay recovers it from the service conntrack entry the forward path created
 * on the ingress node. This test seeds that CT_SERVICE entry (mirroring
 * lb4_local(): prime the tuple flags via ct_lazy_lookup4(CT_SERVICE,
 * SCOPE_REVERSE) then ct_create4() with the backend id), sends an ICMPv4
 * "fragmentation needed" addressed to the VIP, and checks the relay rewrites
 * the error to the backend and returns CTX_ACT_REDIRECT.
 *
 * The "not the ingress node" case (no CT entry -> CTX_ACT_OK) is covered by a
 * second test that omits the seeding.
 */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_DSR
#define ENABLE_SVC_ICMP_PMTU_RELAY
#include <bpf/config/global.h>

#define TEST_REVNAT		       1

/* Satisfy the nat.h -> egress_gateway.h -> encap.h include chain. */
#define ENCAP_IFINDEX	42
#define ENCAP4_IFINDEX	42
#define ENCAP6_IFINDEX	42

#include "nodeport_defaults.h"

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/pmtu.h>
#include "lib/lb.h"

#define ROUTER_IP	bpf_htonl(0x0a000002)	/* 10.0.0.2   (ICMP source) */
#define VIP_ADDR	bpf_htonl(0x0a00000a)	/* 10.0.0.10  (service VIP)  */
#define CLIENT_IP	bpf_htonl(0x0a0000f0)	/* 10.0.0.240 (client)       */
#define BACKEND_IP	bpf_htonl(0x0a000105)	/* 10.0.1.5   (backend pod)  */
#define SVC_PORT	bpf_htons(80)
#define CLIENT_PORT	bpf_htons(12345)
/* Distinct flow for the miss case: subtests share the same map instance, so the
 * hit case's seeded CT entry would otherwise be found by the miss case too. */
#define CLIENT_PORT_MISS bpf_htons(23456)
#define BACKEND_PORT	bpf_htons(8080)
#define BACKEND_ID	124

static volatile const __u8 smac[ETH_ALEN] = {0x02, 0, 0, 0, 0, 1};
static volatile const __u8 dmac[ETH_ALEN] = {0x02, 0, 0, 0, 0, 2};

/* Build the ICMPv4 frag-needed addressed to the VIP, carrying the backend's
 * oversized reply (VIP:svc_port -> client) embedded. */
static __always_inline int build_frag_needed(struct __ctx_buff *ctx, __be16 client_port)
{
	struct pktgen builder;
	struct iphdr *ip4;
	struct icmphdr *icmp;
	struct iphdr inner_ip = {
		.version = 4,
		.ihl = 5,
		.protocol = IPPROTO_TCP,
		.saddr = VIP_ADDR,
		.daddr = CLIENT_IP,
	};
	struct tcphdr inner_tcp = {
		.source = SVC_PORT,
		.dest = client_port,
		.doff = 5,
	};

	pktgen__init(&builder, ctx);

	ip4 = pktgen__push_ipv4_packet(&builder, (__u8 *)smac, (__u8 *)dmac,
				       ROUTER_IP, VIP_ADDR);
	if (!ip4)
		return TEST_ERROR;
	ip4->protocol = IPPROTO_ICMP;

	icmp = pktgen__push_icmphdr(&builder);
	if (!icmp)
		return TEST_ERROR;
	icmp->type = ICMP_DEST_UNREACH;
	icmp->code = ICMP_FRAG_NEEDED;
	icmp->un.frag.mtu = bpf_htons(1400);

	if (!pktgen__push_data(&builder, &inner_ip, sizeof(inner_ip)))
		return TEST_ERROR;
	if (!pktgen__push_data(&builder, &inner_tcp, sizeof(inner_tcp)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* Add a SNAT-mode (no DSR flag) service VIP:80 with one backend. */
static __always_inline void add_snat_service(void)
{
	lb_v4_add_service_with_flags(VIP_ADDR, SVC_PORT, IPPROTO_TCP, 1, TEST_REVNAT,
				     SVC_FLAG_ROUTABLE, 0);
	lb_v4_add_backend(VIP_ADDR, SVC_PORT, 1, BACKEND_ID,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);
}

/* Seed the service conntrack entry the ingress node's forward path would have
 * created for this flow, storing the selected backend id. Mirrors lb4_local():
 * the CT_SERVICE tuple is stored swapped (sport = svc_port, dport = client_port)
 * and ct_lazy_lookup4() primes tuple->flags before ct_create4(). */
static __always_inline void seed_ct_service(struct __ctx_buff *ctx, int l4_off)
{
	struct ipv4_ct_tuple ct_tuple = {
		.saddr = CLIENT_IP,
		.daddr = VIP_ADDR,
		.nexthdr = IPPROTO_TCP,
		.sport = SVC_PORT,
		.dport = CLIENT_PORT,
	};
	struct ct_state seed = {
		.backend_id = BACKEND_ID,
		.rev_nat_index = TEST_REVNAT,
	};
	struct ct_state tmp = {};
	__s8 ext_err = 0;
	__u32 monitor = 0;

	ct_lazy_lookup4(get_ct_map4(&ct_tuple), &ct_tuple, ctx,
			IPFRAG_BIT_NO_L4_HEADER, l4_off, CT_SERVICE,
			SCOPE_REVERSE, CT_ENTRY_SVC, &tmp, &monitor);
	ct_create4(get_ct_map4(&ct_tuple), NULL, &ct_tuple, ctx, CT_SERVICE,
		   &seed, &ext_err);
}

static __always_inline int call_relay(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip4 = data + sizeof(struct ethhdr);
	__s8 ext_err = 0;

	if ((void *)ip4 + sizeof(*ip4) > data_end)
		return TEST_ERROR;

	return handle_icmp_svc_pmtu_v4(ctx, ip4,
				       ETH_HLEN + ipv4_hdrlen(ip4), &ext_err);
}

/* ---- Case 1: CT entry present (ingress node) -> relay to the backend. ---- */

PKTGEN("tc", "svc_icmp_pmtu_relay_snat_v4")
int svc_icmp_pmtu_relay_snat_v4_pktgen(struct __ctx_buff *ctx)
{
	return build_frag_needed(ctx, CLIENT_PORT);
}

SETUP("tc", "svc_icmp_pmtu_relay_snat_v4")
int svc_icmp_pmtu_relay_snat_v4_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip4 = data + sizeof(struct ethhdr);
	int l4_off;

	if ((void *)ip4 + sizeof(*ip4) > data_end)
		return TEST_ERROR;
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	add_snat_service();
	seed_ct_service(ctx, l4_off);

	if (call_relay(ctx) != CTX_ACT_REDIRECT)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "svc_icmp_pmtu_relay_snat_v4")
int svc_icmp_pmtu_relay_snat_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *ip4, *inner_ip;
	struct icmphdr *icmp;
	struct tcphdr *inner_tcp;

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
		test_fatal("outer ip out of bounds");
	if (ip4->daddr != BACKEND_IP)
		test_fatal("outer dst not rewritten to the backend");

	icmp = (void *)ip4 + sizeof(*ip4);
	if ((void *)icmp + sizeof(*icmp) > data_end)
		test_fatal("icmp out of bounds");

	inner_ip = (void *)icmp + sizeof(*icmp);
	if ((void *)inner_ip + sizeof(*inner_ip) > data_end)
		test_fatal("embedded ip out of bounds");
	if (inner_ip->saddr != BACKEND_IP)
		test_fatal("embedded src not rewritten to the backend");
	if (inner_ip->daddr != CLIENT_IP)
		test_fatal("embedded dst must remain the client");

	inner_tcp = (void *)inner_ip + sizeof(*inner_ip);
	if ((void *)inner_tcp + sizeof(*inner_tcp) > data_end)
		test_fatal("embedded tcp out of bounds");
	if (inner_tcp->source != BACKEND_PORT)
		test_fatal("embedded L4 source not rewritten to the backend port");
	if (inner_tcp->dest != CLIENT_PORT)
		test_fatal("embedded L4 dest must remain the client port");

	test_finish();
}

/* ---- Case 2: no CT entry (error landed on a non-ingress node) -> no relay. ---- */

PKTGEN("tc", "svc_icmp_pmtu_relay_snat_v4_miss")
int svc_icmp_pmtu_relay_snat_v4_miss_pktgen(struct __ctx_buff *ctx)
{
	return build_frag_needed(ctx, CLIENT_PORT_MISS);
}

SETUP("tc", "svc_icmp_pmtu_relay_snat_v4_miss")
int svc_icmp_pmtu_relay_snat_v4_miss_setup(struct __ctx_buff *ctx)
{
	/* Service exists but there is no CT_SERVICE entry for the flow, as on a
	 * node that did not handle the connection. The relay must fall through. */
	add_snat_service();

	if (call_relay(ctx) != CTX_ACT_OK)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "svc_icmp_pmtu_relay_snat_v4_miss")
int svc_icmp_pmtu_relay_snat_v4_miss_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *ip4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	if (*status_code != TEST_PASS)
		test_fatal("SETUP failed with status code: %d", *status_code);

	/* Packet must be untouched: outer dst still the VIP. */
	ip4 = data + sizeof(*status_code) + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("outer ip out of bounds");
	if (ip4->daddr != VIP_ADDR)
		test_fatal("outer dst must be unchanged when there is no CT entry");

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
