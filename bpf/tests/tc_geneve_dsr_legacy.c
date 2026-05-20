// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4		1
#define ENABLE_IPV6		1

#define ENABLE_NODEPORT 1
#define ENABLE_DSR 1
#define DSR_ENCAP_IPIP 2
#define DSR_ENCAP_GENEVE 3
#define DSR_ENCAP_MODE DSR_ENCAP_GENEVE

#define ENCAP_IFINDEX 42
#define TUNNEL_MODE

#define FRONTEND_IP		v4_node_one
#define FRONTEND_IPV6		{ .addr = v6_node_one_addr }
#define FRONTEND_PORT		__bpf_htons(80)

#define CLIENT_IP		v4_ext_one
#define CLIENT_IPV6		{ .addr = v6_ext_node_one_addr }
#define CLIENT_PORT		__bpf_htons(111)
#define CLIENT_SEC_IDENTITY	CIDR_IDENTITY_RANGE_START

#define BACKEND_IP		v4_pod_one
#define BACKEND_IPV6		{ .addr = v6_pod_one_addr }
#define BACKEND_PORT		__bpf_htons(8080)

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#define skb_get_tunnel_key mock_skb_get_tunnel_key
int mock_skb_get_tunnel_key(__maybe_unused struct __sk_buff *skb,
			    __maybe_unused  struct bpf_tunnel_key *to,
			    __maybe_unused __u32 size,
			    __maybe_unused __u32 flags);

#define skb_get_tunnel_opt mock_skb_get_tunnel_opt
int mock_skb_get_tunnel_opt(__maybe_unused struct __sk_buff *skb,
			    void *opt, __u32 size)
{
	if (size == sizeof(struct geneve_dsr_opt4)) {
		struct geneve_dsr_opt4 *gopt = opt;

		set_geneve_dsr_opt4(FRONTEND_PORT, FRONTEND_IP, gopt);
	} else {
		struct geneve_dsr_opt6 *gopt = opt;
		union v6addr frontend_ip = FRONTEND_IPV6;

		set_geneve_dsr_opt6(FRONTEND_PORT, &frontend_ip, gopt);
	}

	return size;
}

#include "lib/bpf_overlay.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)

int mock_skb_get_tunnel_key(__maybe_unused struct __sk_buff *skb,
			    __maybe_unused  struct bpf_tunnel_key *to,
			    __maybe_unused __u32 size,
			    __maybe_unused __u32 flags)
{
	to->remote_ipv4 = v4_node_one;
	to->tunnel_id = WORLD_ID;
	return 0;
}

PKTGEN("tc", "tc_geneve_dsr_v4_legacy")
int tc_geneve_dsr_v4_legacy_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "tc_geneve_dsr_v4_legacy")
int tc_geneve_dsr_v4_legacy_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(BACKEND_IP, 0, 0, 0, 0, 0, NULL, NULL);
	ipcache_v4_add_entry(CLIENT_IP, 0, CLIENT_SEC_IDENTITY, 0, 0);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "tc_geneve_dsr_v4_legacy")
int tc_geneve_dsr_v4_legacy_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ct_entry *ct_entry;
	struct ipv4_ct_tuple expected_tuple_for_ct = {
		.saddr   = BACKEND_IP,
		.daddr   = CLIENT_IP,
		.sport   = CLIENT_PORT,
		.dport   = BACKEND_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags   = TUPLE_F_OUT,
	};

	test_init();

	endpoint_v4_del_entry(BACKEND_IP);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* The packet must be passed to kernel-stack */
	status_code = data;
	assert(*status_code == CTX_ACT_OK);
	/* Client identity should *not* be embedded */
	assert((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_IDENTITY);

	/* Verify that the datapath inserted the conntrack entry */
	ct_entry = map_lookup_elem(&cilium_ct4_global, &expected_tuple_for_ct);
	if (!ct_entry)
		test_fatal("No entry in conntrack map");

	assert(ct_entry->nat_addr.p4 == FRONTEND_IP);
	assert(ct_entry->nat_port == FRONTEND_PORT);

	test_finish();
}

PKTGEN("tc", "tc_geneve_dsr_v6_legacy")
int tc_geneve_dsr_v6_legacy_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;
	union v6addr client_ip = CLIENT_IPV6;
	union v6addr backend_ip = BACKEND_IPV6;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)server_mac,
					  (__u8 *)&client_ip, (__u8 *)&backend_ip,
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

SETUP("tc", "tc_geneve_dsr_v6_legacy")
int tc_geneve_dsr_v6_legacy_setup(struct __ctx_buff *ctx)
{
	union v6addr backend_ip = BACKEND_IPV6;
	union v6addr client_ip = CLIENT_IPV6;

	endpoint_v6_add_entry(&backend_ip, 0, 0, 0, 0, NULL, NULL);
	ipcache_v6_add_entry(&client_ip, 0, CLIENT_SEC_IDENTITY, 0, 0);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "tc_geneve_dsr_v6_legacy")
int tc_geneve_dsr_v6_legacy_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ct_entry *ct_entry;
	union v6addr frontend_ip = FRONTEND_IPV6;

	union v6addr backend_ip = BACKEND_IPV6;
	union v6addr client_ip  = CLIENT_IPV6;
	struct ipv6_ct_tuple expected_tuple_for_ct = {
		.saddr   = backend_ip,
		.daddr   = client_ip,
		.sport   = CLIENT_PORT,
		.dport   = BACKEND_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags   = TUPLE_F_OUT,
	};

	test_init();

	data      = (void *)(long)ctx_data(ctx);
	data_end  = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Packet must be passed to the kernel stack */
	status_code = data;
	assert(*status_code == CTX_ACT_OK);
	assert((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_IDENTITY);

	/* Verify that the datapath inserted the conntrack entry */
	ct_entry = map_lookup_elem(&cilium_ct6_global, &expected_tuple_for_ct);
	if (!ct_entry)
		test_fatal("No entry in conntrack map");

	assert(ipv6_addr_equals(&ct_entry->nat_addr, &frontend_ip));
	assert(ct_entry->nat_port == FRONTEND_PORT);

	test_finish();
}
