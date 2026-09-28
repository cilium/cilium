// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Datapath test for the service ICMP PMTU relay.
 *
 * Covers the L4/DSR IPv4 path: an ICMPv4 "fragmentation needed" addressed to a
 * DSR service VIP, carrying the backend's oversized reply (src = VIP:svc_port,
 * dst = client) embedded, must be rewritten so it is addressed to the backend
 * that owns the connection -- outer dst and embedded src rewritten to the
 * backend, embedded L4 source port rewritten to the backend port -- with every
 * touched checksum kept valid, and the helper must return CTX_ACT_REDIRECT so
 * the caller delivers it to the backend.
 *
 * The backend is re-derived via Maglev (the relay is Maglev-only), so the test
 * mocks the maglev maps and points every LUT slot at the one backend. The L7
 * flood path is covered by svc_icmp_pmtu_relay_l7.c.
 */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "svc_icmp_pmtu_relay_common.h"

#define ENABLE_IPV4
#include <bpf/config/global.h>

#define LB_DEFAULT_ALG LB_SELECTION_MAGLEV

#include "nodeport_defaults.h"
#undef LB_MAGLEV_LUT_SIZE
#define LB_MAGLEV_LUT_SIZE 20

/* Mock maglev maps used by lb4_select_backend_id_maglev(). */
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

PKTGEN("tc", "svc_icmp_pmtu_relay_dsr_v4")
int svc_icmp_pmtu_relay_dsr_v4_pktgen(struct __ctx_buff *ctx)
{
	return pmtu_test_pktgen_icmp4(ctx, ROUTER_IP, VIP_ADDR, CLIENT_IP,
				      SVC_PORT, CLIENT_PORT);
}

SETUP("tc", "svc_icmp_pmtu_relay_dsr_v4")
int svc_icmp_pmtu_relay_dsr_v4_setup(struct __ctx_buff *ctx)
{
	__u32 backends[LB_MAGLEV_LUT_SIZE];
	__u32 zero = 0;
	void *data, *data_end;
	struct iphdr *ip4;
	int i, ret;

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

	ret = handle_icmp_svc_pmtu_v4(ctx, ip4, ETH_HLEN + ipv4_hdrlen(ip4));
	if (ret != CTX_ACT_REDIRECT)
		return TEST_ERROR;

	return TEST_PASS;
}

CHECK("tc", "svc_icmp_pmtu_relay_dsr_v4")
int svc_icmp_pmtu_relay_dsr_v4_check(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code = data;
	struct pmtu_test_pkt4 p;

	test_init();

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	if (*status_code != TEST_PASS)
		test_fatal("SETUP failed with status code: %d", *status_code);
	if (!pmtu_test_walk4(ctx, &p))
		test_fatal("packet truncated");

	if (p.ip4->daddr != BACKEND_IP)
		test_fatal("outer dst not rewritten to the backend");
	if (p.inner_ip->saddr != BACKEND_IP)
		test_fatal("embedded src not rewritten to the backend");
	if (p.inner_ip->daddr != CLIENT_IP)
		test_fatal("embedded dst must remain the client");
	if (p.inner_tcp->source != BACKEND_PORT)
		test_fatal("embedded L4 source not rewritten to the backend port");
	if (p.inner_tcp->dest != CLIENT_PORT)
		test_fatal("embedded L4 dest must remain the client port");

	/* Every checksum the relay touched must still be valid: outer IP (dst
	 * rewrite), outer ICMP (embedded change), embedded IP and TCP. */
	if (pmtu_test_csum_ip4(p.ip4) != 0)
		test_fatal("outer ip checksum invalid");
	if (pmtu_test_csum_icmp4(p.icmp, p.inner_ip, p.inner_tcp) != 0)
		test_fatal("outer icmp checksum invalid");
	if (pmtu_test_csum_ip4(p.inner_ip) != 0)
		test_fatal("embedded ip checksum invalid");
	if (pmtu_test_csum_tcp4(p.inner_ip, p.inner_tcp) != 0)
		test_fatal("embedded tcp checksum invalid");

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
