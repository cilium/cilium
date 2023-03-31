// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include "bpf/ctx/xdp.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_NODEPORT_ACCELERATION

#define fib_lookup mock_fib_lookup

static const char fib_smac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
static const char fib_dmac[6] = {0x13, 0x37, 0x13, 0x37, 0x13, 0x37};

long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	memcpy(params->smac, fib_smac, sizeof(fib_smac));
	memcpy(params->dmac, fib_dmac, sizeof(fib_dmac));
	return 0;
}

#include "bpf_xdp.c"
#include "lib/nodeport.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[0] = &cil_xdp_entry,
	},
};

#define FRONTEND_IP 0x0F00010A /* 10.0.1.15 */
#define FRONTEND_PORT 80
#define BACKEND_IP 0x0F00020A /* 10.2.0.15 */
#define BACKEND_PORT 8080

static long (*bpf_xdp_adjust_tail)(struct xdp_md *xdp_md, int delta) = (void *)65;

static __always_inline int build_packet(struct __ctx_buff *ctx)
{
	/* Create room for our packet to be crafted */
	unsigned int data_len = ctx->data_end - ctx->data;

	int offset = offset = 4096 - 256 - 320 - data_len;

	bpf_xdp_adjust_tail(ctx, offset);

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(struct ethhdr) > data_end)
		return TEST_ERROR;

	struct ethhdr l2 = {
		.h_source = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		.h_dest = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67},
		.h_proto = bpf_htons(ETH_P_IP)
	};
	memcpy(data, &l2, sizeof(struct ethhdr));
	data += sizeof(struct ethhdr);

	if (data + sizeof(struct iphdr) > data_end)
		return TEST_ERROR;

	struct iphdr l3 = {
		.version = 4,
		.ihl = 5,
		.tot_len = 40, /* 20 bytes l3 + 20 bytes l4 + 20 bytes data */
		.id = 0x5438,
		.frag_off = bpf_htons(IP_DF),
		.ttl = 64,
		.protocol = IPPROTO_TCP,
		.saddr = 0x0F00000A, /* 10.0.0.15 */
		.daddr = FRONTEND_IP,
	};
	memcpy(data, &l3, sizeof(struct iphdr));
	data += sizeof(struct iphdr);

	char tcp_data[20] = "Should not change!!";

	/* TCP header + data */
	if (data + (sizeof(struct tcphdr) + sizeof(tcp_data)) > data_end)
		return TEST_ERROR;

	struct tcphdr l4 = {
		.source = 23445,
		.dest = FRONTEND_PORT,
		.seq = 2922048129,
		.doff = 0, /* no options */
		.syn = 1,
		.window = 64240,
	};
	memcpy(data, &l4, sizeof(struct tcphdr));

	char *tcp_data_ptr = data + sizeof(tcp_data);

	memcpy(tcp_data_ptr, tcp_data, sizeof(tcp_data));

	data += sizeof(struct tcphdr) + sizeof(tcp_data);

	/* Shrink ctx to the exact size we used */
	offset = (long)data - (long)ctx->data_end;
	bpf_xdp_adjust_tail(ctx, offset);

	return 0;
}

SETUP("xdp", "xdp_lb4_forward_to_other_node")
int test1_setup(struct __ctx_buff *ctx)
{
	int ret;

	ret = build_packet(ctx);
	if (ret)
		return ret;

	/* Register a fake LB backend with endpoint ID 124 matching our packet. */
	struct lb4_key lb_svc_key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT
	};
	/* Create a service with only one backend */
	struct lb4_service lb_svc_value = {
		.count = 1,
		.flags = SVC_FLAG_ROUTABLE,
	};
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);
	/* We need to register both in the external and internal scopes for the */
	/* packet to be redirected to a neighboring node */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* A backend between 1 and .count is chosen, since we have only one backend */
	/* it is always backend_slot 1. Point it to backend_id 124. */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;
	lb_svc_key.backend_slot = 1;
	lb_svc_value.backend_id = 124;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* Create backend id 124 which contains the IP and port to send the */
	/* packet to. */
	struct lb4_backend backend = {
		.address = BACKEND_IP,
		.port = BACKEND_PORT,
		.proto = IPPROTO_TCP,
		.flags = 0,
	};
	map_update_elem(&LB4_BACKEND_MAP, &lb_svc_value.backend_id, &backend, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "xdp_lb4_forward_to_other_node")
int test1_check(__maybe_unused const struct __ctx_buff *ctx)
{
	test_init();

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	__u32 *status_code = data;

	if (*status_code != XDP_TX)
		test_fatal("status code != XDP_TX");

	data += sizeof(__u32);

	if (data + sizeof(struct ethhdr) > data_end)
		test_fatal("ctx doesn't fit ethhdr");

	struct ethhdr *l2 = data;

	data += sizeof(struct ethhdr);

	if (memcmp(l2->h_source, fib_smac, sizeof(fib_smac)) != 0)
		test_fatal("l2->h_source != fib_smac");

	if (memcmp(l2->h_dest, fib_dmac, sizeof(fib_dmac)) != 0)
		test_fatal("l2->h_dest != fib_dmac");

	if (data + sizeof(struct iphdr) > data_end)
		test_fatal("ctx doesn't fit iphdr");

	struct iphdr *l3 = data;

	data += sizeof(struct iphdr);

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst ip != backend IP");

	if (data + sizeof(struct tcphdr) > data_end)
		test_fatal("ctx doesn't fit tcphdr");

	struct tcphdr *l4 = data;

	data += sizeof(struct tcphdr);

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port != backend port");

	char msg[20] = "Should not change!!";

	if (data + sizeof(msg) > data_end)
		test_fatal("ctx doesn't fit tcp body");

	char *body = data;

	if (memcmp(body, msg, sizeof(msg)) != 0)
		test_fatal("body changed");

	test_finish();
}

SETUP("xdp", "xdp_lb4_drop_no_backend")
int test2_setup(struct __ctx_buff *ctx)
{
	/* Fake Service matching our packet. */
	struct lb4_key lb_svc_key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT
	};
	/* Service with no backends */
	struct lb4_service lb_svc_value = {
		.count = 0,
		.flags = SVC_FLAG_ROUTABLE,
	};
	int ret;

	ret = build_packet(ctx);
	if (ret)
		return ret;

	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);
	lb_svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "xdp_lb4_drop_no_backend")
int test2_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 expected_status = XDP_DROP;
	__u32 *status_code;

	test_init();

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != expected_status)
		test_fatal("status code is %lu, expected %lu", *status_code, expected_status);

	test_finish();
}
