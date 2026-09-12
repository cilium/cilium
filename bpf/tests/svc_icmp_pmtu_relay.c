// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Datapath test for the service ICMP PMTU relay.
 *
 * Covers the L4/DSR IPv4 path: an ICMPv4 "fragmentation needed" addressed to a
 * DSR service VIP, carrying the backend's oversized reply (src = VIP:svc_port,
 * dst = client) embedded, must be rewritten so it is addressed to the backend
 * that owns the connection -- outer dst and embedded src rewritten to the
 * backend, embedded L4 source port rewritten to the backend port -- and the
 * helper must return CTX_ACT_REDIRECT so the caller delivers it to the backend.
 *
 * The backend is re-derived via Maglev (the relay is Maglev-only), so the test
 * mocks the maglev maps and points every LUT slot at the one backend. The L7
 * flood path is not exercised here (it needs fib_lookup/clone_redirect, which
 * do not run under BPF_PROG_RUN; that wants a separate mocked test).
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

#define TEST_LB_MAGLEV_MAP_MAX_ENTRIES 65536
#define TEST_CONDITIONAL_PREALLOC      0
#define TEST_REVNAT		       1
#define LB_MAGLEV_EXTERNAL

/* Satisfy the nat.h -> egress_gateway.h -> encap.h include chain; the relay
 * itself does not use encap. */
#define ENCAP_IFINDEX	42
#define ENCAP4_IFINDEX	42
#define ENCAP6_IFINDEX	42

/* The relay is Maglev-only. Select Maglev as the runtime backend-selection
 * algorithm via lb_default_alg; this must be defined before the node config
 * include, which assigns lb_default_alg from LB_DEFAULT_ALG. Defining the
 * obsolete compile-time LB_SELECTION here would silently mask a real bug: the
 * agent build has no such macro, so the guard resolves the algorithm at
 * runtime and must be tested that way. */
#include <bpf/lb_selection.h>
#define LB_DEFAULT_ALG LB_SELECTION_MAGLEV

#include "nodeport_defaults.h"

#undef LB_MAGLEV_LUT_SIZE
#define LB_MAGLEV_LUT_SIZE 20

/* Mock maglev maps used by lb{4,6}_select_backend_id_maglev(). */
struct lb4_maglev_map_inner {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32) * LB_MAGLEV_LUT_SIZE);
	__uint(max_entries, 1);
} test_lb4_maglev_map_inner __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, TEST_LB_MAGLEV_MAP_MAX_ENTRIES);
	__uint(map_flags, TEST_CONDITIONAL_PREALLOC);
	__array(values, struct lb4_maglev_map_inner);
} cilium_lb4_maglev __section_maps_btf = {
	.values = {[TEST_REVNAT] = &test_lb4_maglev_map_inner, },
};

#define OVERWRITE_MAGLEV_MAP_FROM_TEST 1

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
#define BACKEND_PORT	bpf_htons(8080)
#define BACKEND_ID	124

static volatile const __u8 smac[ETH_ALEN] = {0x02, 0, 0, 0, 0, 1};
static volatile const __u8 dmac[ETH_ALEN] = {0x02, 0, 0, 0, 0, 2};

PKTGEN("tc", "svc_icmp_pmtu_relay_dsr_v4")
int svc_icmp_pmtu_relay_dsr_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *ip4;
	struct icmphdr *icmp;
	struct iphdr inner_ip = {
		.version = 4,
		.ihl = 5,
		.protocol = IPPROTO_TCP,
		.saddr = VIP_ADDR,	/* backend reply is sourced from the VIP */
		.daddr = CLIENT_IP,
	};
	struct tcphdr inner_tcp = {
		.source = SVC_PORT,
		.dest = CLIENT_PORT,
		.doff = 5,
	};

	pktgen__init(&builder, ctx);

	/* Outer: ICMPv4 error from the tunnel router, addressed to the VIP. */
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

	/* Embedded (offending) packet: VIP:svc_port -> client. */
	if (!pktgen__push_data(&builder, &inner_ip, sizeof(inner_ip)))
		return TEST_ERROR;
	if (!pktgen__push_data(&builder, &inner_tcp, sizeof(inner_tcp)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "svc_icmp_pmtu_relay_dsr_v4")
int svc_icmp_pmtu_relay_dsr_v4_setup(struct __ctx_buff *ctx)
{
	__u32 backends[LB_MAGLEV_LUT_SIZE];
	__u32 zero = 0;
	void *data, *data_end;
	struct iphdr *ip4;
	__s8 ext_err = 0;
	int i, l4_off, ret;

	/* Point every maglev LUT slot at the single backend so the re-derivation
	 * is deterministic regardless of the hashed tuple. */
	for (i = 0; i < LB_MAGLEV_LUT_SIZE; i++)
		backends[i] = BACKEND_ID;
	map_update_elem(&test_lb4_maglev_map_inner, &zero, backends, BPF_ANY);

	/* DSR service VIP:80 with one backend. */
	lb_v4_add_service_with_flags(VIP_ADDR, SVC_PORT, IPPROTO_TCP, 1, TEST_REVNAT,
				     SVC_FLAG_ROUTABLE, SVC_FLAG_FWD_MODE_DSR);
	lb_v4_add_backend(VIP_ADDR, SVC_PORT, 1, BACKEND_ID,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ip4 = data + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		return TEST_ERROR;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	ret = handle_icmp_svc_pmtu_v4(ctx, ip4, l4_off, &ext_err);
	if (ret != CTX_ACT_REDIRECT)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "svc_icmp_pmtu_relay_dsr_v4")
int svc_icmp_pmtu_relay_dsr_v4_check(const struct __ctx_buff *ctx)
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

	/* Skip the prepended status code, then walk ether/ip/icmp/inner. */
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

BPF_LICENSE("Dual BSD/GPL");
