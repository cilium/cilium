// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Datapath test for the IPv6 L4/DSR path of the service ICMP PMTU relay: an
 * ICMPv6 "packet too big" addressed to a DSR service VIP, embedding the
 * backend's oversized reply (src = VIP:svc_port, dst = client), must be
 * rewritten to the backend that owns the connection (outer dst, embedded src
 * and embedded L4 source port) with the outer ICMPv6 and embedded TCP checksums
 * kept valid, and the helper must return CTX_ACT_REDIRECT. See the IPv4 sibling
 * for the maglev mocking.
 */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "svc_icmp_pmtu_relay_common.h"

#define ENABLE_IPV6
#include <bpf/config/global.h>

#define LB_DEFAULT_ALG LB_SELECTION_MAGLEV

#include "nodeport_defaults.h"
#undef LB_MAGLEV_LUT_SIZE
#define LB_MAGLEV_LUT_SIZE 20

struct lb6_maglev_map_inner {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32) * LB_MAGLEV_LUT_SIZE);
	__uint(max_entries, 1);
} test_lb6_maglev_map_inner __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, TEST_LB_MAGLEV_MAP_MAX_ENTRIES);
	__uint(map_flags, TEST_CONDITIONAL_PREALLOC);
	__array(values, struct lb6_maglev_map_inner);
} cilium_lb6_maglev __section_maps_btf = {
	.values = {[TEST_REVNAT] = &test_lb6_maglev_map_inner, },
};

#define OVERWRITE_MAGLEV_MAP_FROM_TEST 1

#include <lib/dbg.h>
#include <lib/eps.h>
#include <lib/pmtu.h>
#include "lib/lb.h"

/* 2001:db8::2 router, 2001:db8::a VIP, 2001:db8::f0 client, 2001:db8:1::5 backend. */
#define V6(...)		{ .addr = { 0x20, 0x01, 0x0d, 0xb8, __VA_ARGS__ } }
#define ROUTER_IP6	V6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02)
#define VIP_ADDR6	V6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a)
#define CLIENT_IP6	V6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf0)
#define BACKEND_IP6	V6(0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05)
#define SVC_PORT	bpf_htons(80)
#define CLIENT_PORT	bpf_htons(12345)
#define BACKEND_PORT	bpf_htons(8080)
#define BACKEND_ID	124

PKTGEN("tc", "svc_icmp_pmtu_relay_dsr_v6")
int svc_icmp_pmtu_relay_dsr_v6_pktgen(struct __ctx_buff *ctx)
{
	union v6addr router = ROUTER_IP6, vip = VIP_ADDR6, client = CLIENT_IP6;
	struct pktgen builder;
	struct ipv6hdr *ip6;
	struct icmp6hdr *icmp6;
	struct ipv6hdr inner_ip6 = {
		.version = 6,
		.payload_len = bpf_htons(sizeof(struct tcphdr)),
		.nexthdr = IPPROTO_TCP,
		.hop_limit = 64,
	};
	struct tcphdr inner_tcp = {
		.source = SVC_PORT,
		.dest = CLIENT_PORT,
		.doff = 5,
	};
	struct icmp6hdr icmp6_hdr = {
		.icmp6_type = ICMPV6_PKT_TOOBIG,
		.icmp6_mtu = bpf_htonl(1400),
	};
	struct ipv6hdr outer = {};

	ipv6_addr_copy((union v6addr *)&inner_ip6.saddr, &vip);
	ipv6_addr_copy((union v6addr *)&inner_ip6.daddr, &client);

	pktgen__init(&builder, ctx);

	/* Outer: ICMPv6 error from the tunnel router, addressed to the VIP. */
	ip6 = pktgen__push_ipv6_packet(&builder, (__u8 *)pmtu_test_smac,
				       (__u8 *)pmtu_test_dmac,
				       (__u8 *)router.addr, (__u8 *)vip.addr);
	if (!ip6)
		return TEST_ERROR;

	icmp6 = pktgen__push_icmp6hdr(&builder);
	if (!icmp6)
		return TEST_ERROR;
	/* Seed valid checksums so the relay's incremental updates can be
	 * verified in CHECK. The outer pseudo-header only needs the addresses. */
	ipv6_addr_copy((union v6addr *)&outer.saddr, &router);
	ipv6_addr_copy((union v6addr *)&outer.daddr, &vip);
	inner_tcp.check = pmtu_test_csum_tcp6(&inner_ip6, &inner_tcp);
	icmp6_hdr.icmp6_cksum = pmtu_test_csum_icmp6(&outer, &icmp6_hdr,
						     &inner_ip6, &inner_tcp);
	*icmp6 = icmp6_hdr;

	/* Embedded (offending) packet: VIP:svc_port -> client. */
	if (!pktgen__push_data(&builder, &inner_ip6, sizeof(inner_ip6)))
		return TEST_ERROR;
	if (!pktgen__push_data(&builder, &inner_tcp, sizeof(inner_tcp)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "svc_icmp_pmtu_relay_dsr_v6")
int svc_icmp_pmtu_relay_dsr_v6_setup(struct __ctx_buff *ctx)
{
	union v6addr vip = VIP_ADDR6, backend = BACKEND_IP6;
	__u32 backends[LB_MAGLEV_LUT_SIZE];
	__u32 zero = 0;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int i, ret;

	for (i = 0; i < LB_MAGLEV_LUT_SIZE; i++)
		backends[i] = BACKEND_ID;
	map_update_elem(&test_lb6_maglev_map_inner, &zero, backends, BPF_ANY);

	lb_v6_add_service_with_flags(&vip, SVC_PORT, IPPROTO_TCP, 1, TEST_REVNAT,
				     SVC_FLAG_ROUTABLE, SVC_FLAG_FWD_MODE_DSR);
	lb_v6_add_backend(&vip, SVC_PORT, 1, BACKEND_ID, &backend, BACKEND_PORT,
			  IPPROTO_TCP, 0);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ip6 = data + sizeof(struct ethhdr);
	if ((void *)ip6 + sizeof(*ip6) > data_end)
		return TEST_ERROR;

	ret = handle_icmp_svc_pmtu_v6(ctx, ip6, ETH_HLEN + sizeof(*ip6));
	if (ret != CTX_ACT_REDIRECT)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "svc_icmp_pmtu_relay_dsr_v6")
int svc_icmp_pmtu_relay_dsr_v6_check(const struct __ctx_buff *ctx)
{
	union v6addr backend = BACKEND_IP6, client = CLIENT_IP6;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *ip6, *inner_ip6;
	struct icmp6hdr *icmp6;
	struct tcphdr *inner_tcp;

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
		test_fatal("outer ip out of bounds");
	if (!ipv6_addr_equals((union v6addr *)&ip6->daddr, &backend))
		test_fatal("outer dst not rewritten to the backend");

	icmp6 = (void *)ip6 + sizeof(*ip6);
	if ((void *)icmp6 + sizeof(*icmp6) > data_end)
		test_fatal("icmp6 out of bounds");

	inner_ip6 = (void *)icmp6 + sizeof(*icmp6);
	if ((void *)inner_ip6 + sizeof(*inner_ip6) > data_end)
		test_fatal("embedded ip out of bounds");
	if (!ipv6_addr_equals((union v6addr *)&inner_ip6->saddr, &backend))
		test_fatal("embedded src not rewritten to the backend");
	if (!ipv6_addr_equals((union v6addr *)&inner_ip6->daddr, &client))
		test_fatal("embedded dst must remain the client");

	inner_tcp = (void *)inner_ip6 + sizeof(*inner_ip6);
	if ((void *)inner_tcp + sizeof(*inner_tcp) > data_end)
		test_fatal("embedded tcp out of bounds");
	if (inner_tcp->source != BACKEND_PORT)
		test_fatal("embedded L4 source not rewritten to the backend port");
	if (inner_tcp->dest != CLIENT_PORT)
		test_fatal("embedded L4 dest must remain the client port");

	if (pmtu_test_csum_icmp6(ip6, icmp6, inner_ip6, inner_tcp) != 0)
		test_fatal("outer icmp6 checksum invalid");
	if (pmtu_test_csum_tcp6(inner_ip6, inner_tcp) != 0)
		test_fatal("embedded tcp checksum invalid");

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
