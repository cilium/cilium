// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "bpf/ctx/xdp.h"
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_NODEPORT_ACCELERATION
#define ENABLE_SESSION_AFFINITY
#define TEST_LB_MAGLEV_MAP_MAX_ENTRIES 65536
#define TEST_CONDITIONAL_PREALLOC      0
#define TEST_REVNAT		       1
#define LB_MAGLEV_EXTERNAL

/* Skip ingress policy checks, not needed to validate hairpin flow */
#define USE_BPF_PROG_FOR_INGRESS_POLICY

#define CLIENT_ID1    1
#define CLIENT_ID2    2
#define CLIENT_IP1    v4_ext_one
#define CLIENT_IP2    v4_ext_three
#define CLIENT_PORT1  __bpf_htons(111)
#define CLIENT_PORT2  __bpf_htons(222)
#define CLIENT_PORT3  __bpf_htons(333)

#define FRONTEND_IP   v4_svc_one
#define FRONTEND_PORT tcp_svc_one

#define BACKEND_PORT  __bpf_htons(8080)

#define fib_lookup    mock_fib_lookup

static volatile const __u8 *client_1_mac = mac_one;
static volatile const __u8 *client_2_mac = mac_two;
static volatile const __u8 lb_mac[ETH_ALEN] = {
	0xce, 0x72, 0xa7, 0x03, 0x88, 0x56
};

static volatile const __u8 base_backend_mac[ETH_ALEN] = {
	0xce, 0x72, 0xa7, 0x03, 0x87, 0x00
};

#include "node_config.h"

#undef LB_SELECTION
#define LB_SELECTION LB_SELECTION_MAGLEV
#undef LB_MAGLEV_LUT_SIZE
#define LB_MAGLEV_LUT_SIZE 20

/* Define a mock maglev map that would be used by the LB code */
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
	/* Maglev inner map definition */
	__array(values, struct lb6_maglev_map_inner);
} cilium_lb6_maglev __section_maps_btf = {
	.values = {[TEST_REVNAT] = &test_lb6_maglev_map_inner, },
};

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
	/* Maglev inner map definition */
	__array(values, struct lb4_maglev_map_inner);
} cilium_lb4_maglev __section_maps_btf = {
	.values = {[TEST_REVNAT] = &test_lb4_maglev_map_inner, },
};

#define OVERWRITE_MAGLEV_MAP_FROM_TEST 1

static __always_inline void get_backend_mac(__u8 *dst, __u32 backend_id)
{
	__bpf_memcpy_builtin(dst, (__u8 *)base_backend_mac, ETH_ALEN);
	dst[5] = (__u8)(backend_id & 0xFF);
}

long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	params->ifindex = 0;

	__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);

	if (params->ipv4_dst == CLIENT_IP1) {
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_1_mac, ETH_ALEN);
	} else if (params->ipv4_dst == CLIENT_IP2) {
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_2_mac, ETH_ALEN);
	} else { /* Backends */
		/* Last 2 bytes is the backend ID */
		__u32 backend_id = __bpf_htonl(params->ipv4_dst) & 0xFFFF;
		__u8 new_backend_mac[ETH_ALEN];

		get_backend_mac(new_backend_mac, backend_id);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)new_backend_mac, ETH_ALEN);
	}

	return 0;
}

#include "bpf_xdp.c"
#include "lib/lb.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
.values = {
  [0] = &cil_xdp_entry,
},
};

static __always_inline int
generate_packet(struct __ctx_buff *ctx, int client_id, __u16 src_port)
{
	__u8 *src_mac;
	__u32 src_ip;

	switch (client_id) {
	case CLIENT_ID1:
		src_mac = (__u8 *)client_1_mac;
		src_ip = CLIENT_IP1;
		break;
	case CLIENT_ID2:
		src_mac = (__u8 *)client_2_mac;
		src_ip = CLIENT_IP2;
		break;
	default:
		return TEST_ERROR;
	}

	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder, src_mac, (__u8 *)lb_mac, src_ip, FRONTEND_IP,
					  src_port, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

/* Backend_id must be greater than 0 */
static __always_inline __be32 get_backend_ip(__u32 backend_id)
{
	return __bpf_htonl(((192) << 24) + ((168) << 16) + backend_id);
}

static __always_inline void setup_test(void)
{
	/* The high 8 bits indicate maglev (2), the lower 24 bits are the session affinity
	 * timeout in seconds
	 */
	__u32 affinity_timeout = 0x2000064;

	__lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, LB_MAGLEV_LUT_SIZE,
			    TEST_REVNAT, true, affinity_timeout);

	/* Backend ID and slot must start by 1 */
	__u32 backends[LB_MAGLEV_LUT_SIZE];

	for (__u16 backend_id = 1; backend_id <= LB_MAGLEV_LUT_SIZE;
	     backend_id++) {
		__lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, /*backend_slot*/ backend_id,
				    /*backend_id*/ backend_id, get_backend_ip(backend_id),
						BACKEND_PORT, IPPROTO_TCP, 0, true);
		backends[backend_id - 1] = backend_id;
	}

	__u32 zero = 0;

	map_update_elem(&test_lb4_maglev_map_inner, &zero, backends, BPF_ANY);
}

static __always_inline int
check_packet(const struct __ctx_buff *ctx, int backend_id)
{
	/* For simplicty assume all backends have the same mac */
	__u8 dst_mac[ETH_ALEN];

	get_backend_mac(dst_mac, backend_id);
	__u32 dst_ip = get_backend_ip(backend_id);

	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(fib_ok(*status_code));

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not correct {%x, %x, %x, %x, %x, %x}",
			   l2->h_source[0], l2->h_source[1], l2->h_source[2],
			   l2->h_source[3], l2->h_source[4], l2->h_source[5]);

	if (memcmp(l2->h_dest, (__u8 *)dst_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not correct {%x, %x, %x, %x, %x, %x}",
			   l2->h_dest[0], l2->h_dest[1], l2->h_dest[2],
			   l2->h_dest[3], l2->h_dest[4], l2->h_dest[5]);

	if (l3->daddr != dst_ip)
		test_fatal("dst IP hasn't been NATed correctly %X  (expected %X)",
			   l3->daddr, dst_ip);

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed correctly %u (expected %u)",
			   l4->dest, BACKEND_PORT);

	test_finish();
}

/* ------------------------------------------------------------------------------ */

PKTGEN("xdp", "session_affinity_maglev_client_1_port_1")
int generate_packet_1_1(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, CLIENT_ID1, CLIENT_PORT1);
}

SETUP("xdp", "session_affinity_maglev_client_1_port_1")
int setup_1_1(struct __ctx_buff *ctx)
{
	setup_test();
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "session_affinity_maglev_client_1_port_1")
int test_1_1(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Client 1 always maps to the backend 13 */
	return check_packet(ctx, 13);
}

/* ------------------------------------------------------------------------------ */

PKTGEN("xdp", "session_affinity_maglev_client_1_port_2")
int generate_packet_1_2(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, CLIENT_ID1, CLIENT_PORT2);
}

SETUP("xdp", "session_affinity_maglev_client_1_port_2")
int setup_1_2(struct __ctx_buff *ctx)
{
	setup_test();
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "session_affinity_maglev_client_1_port_2")
int test_1_2(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Client 1 always maps to the backend 13 */
	return check_packet(ctx, 13);
}

/* ------------------------------------------------------------------------------ */

PKTGEN("xdp", "session_affinity_maglev_client_1_port_3")
int generate_packet_1_3(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, CLIENT_ID1, CLIENT_PORT3);
}

SETUP("xdp", "session_affinity_maglev_client_1_port_3")
int setup_1_3(struct __ctx_buff *ctx)
{
	setup_test();
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "session_affinity_maglev_client_1_port_3")
int test_1_3(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Client 1 always maps to the backend 13 */
	return check_packet(ctx, 13);
}

/* ------------------------------------------------------------------------------ */

PKTGEN("xdp", "session_affinity_maglev_client_2_port_1")
int generate_packet_2_1(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, CLIENT_ID2, CLIENT_PORT1);
}

SETUP("xdp", "session_affinity_maglev_client_2_port_1")
int setup_2_1(struct __ctx_buff *ctx)
{
	setup_test();
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "session_affinity_maglev_client_2_port_1")
int test_2_1(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Client 2 always maps to the backend 14 */
	return check_packet(ctx, 14);
}

/* ------------------------------------------------------------------------------ */

PKTGEN("xdp", "session_affinity_maglev_client_2_port_2")
int generate_packet_2_2(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, CLIENT_ID2, CLIENT_PORT2);
}

SETUP("xdp", "session_affinity_maglev_client_2_port_2")
int setup_2_2(struct __ctx_buff *ctx)
{
	setup_test();
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "session_affinity_maglev_client_2_port_2")
int test_2_2(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Client 2 always maps to the backend 14 */
	return check_packet(ctx, 14);
}

/* ------------------------------------------------------------------------------ */

PKTGEN("xdp", "session_affinity_maglev_client_2_port_3")
int generate_packet_2_3(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, CLIENT_ID2, CLIENT_PORT3);
}

SETUP("xdp", "session_affinity_maglev_client_2_port_3")
int setup_2_3(struct __ctx_buff *ctx)
{
	setup_test();
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "session_affinity_maglev_client_2_port_3")
int test_2_3(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Client 2 always maps to the backend 14 */
	return check_packet(ctx, 14);
}
