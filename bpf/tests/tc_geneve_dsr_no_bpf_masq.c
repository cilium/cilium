// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4

#define ENABLE_NODEPORT 1
#define ENABLE_DSR 1
#define DSR_ENCAP_IPIP 2
#define DSR_ENCAP_GENEVE 3
#define DSR_ENCAP_MODE DSR_ENCAP_GENEVE

#define TUNNEL_PROTOCOL TUNNEL_PROTOCOL_GENEVE
#define ENCAP_IFINDEX 42
#define TUNNEL_MODE

#define CLIENT_IP v4_pod_one
#define CLIENT_PORT __bpf_htons(111)

#define BACKEND_IP		v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define NODE_IP v4_node_one

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#define skb_get_tunnel_key mock_skb_get_tunnel_key
int mock_skb_get_tunnel_key(__maybe_unused struct __sk_buff *skb,
			    struct bpf_tunnel_key *to,
			    __maybe_unused __u32 size,
			    __maybe_unused __u32 flags)
{
	to->remote_ipv4 = v4_node_two;
	/* 0xfffff is the default SECLABEL */
	to->tunnel_id = 0xfffff;
	return 0;
}

#define skb_get_tunnel_opt mock_skb_get_tunnel_opt
int mock_skb_get_tunnel_opt(__maybe_unused struct __sk_buff *skb,
			    void *opt, __u32 size)
{
	struct geneve_dsr_opt4 *gopt = opt;

	gopt->hdr.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS);
	gopt->hdr.type = DSR_GENEVE_OPT_TYPE;
	return size;
}

#include "bpf_overlay.c"

#include "lib/endpoint.h"

#define FROM_OVERLAY 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_OVERLAY] = &cil_from_overlay,
	},
};

PKTGEN("tc", "tc_geneve_dsr_no_bpf_masq")
int tc_geneve_dsr_no_bpf_masq_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)server_mac,
					  CLIENT_IP, BACKEND_IP,
					  CLIENT_PORT, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_geneve_dsr_no_bpf_masq")
int tc_geneve_dsr_no_bpf_masq_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(BACKEND_IP, 0, 0, 0, 0, 0, NULL, NULL);
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_geneve_dsr_no_bpf_masq")
int tc_geneve_dsr_no_bpf_masq_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* The packet should be passed to kernel-stack */
	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	test_finish();
}
