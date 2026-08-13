// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT

#define ENCAP_IFINDEX		42
#define TUNNEL_MODE

#define CLIENT_IP		v4_pod_one
#define CLIENT_IP6		{ .addr = v6_pod_one_addr }
#define CLIENT_PORT		__bpf_htons(111)
#define CLIENT_SEC_IDENTITY	112233
#define CLIENT_NODE_IP		v4_node_one

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_IP6		{ .addr = v6_svc_one_addr }
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_two
#define LB_IP6			{ .addr = v6_node_two_addr }
#define IPV4_DIRECT_ROUTING	LB_IP
#define IPV6_DIRECT_ROUTING	LB_IP6

#define BACKEND_IP		v4_pod_three
#define BACKEND_IP6		{ .addr = v6_pod_three_addr }
#define BACKEND_PORT		__bpf_htons(8080)
#define BACKEND_SEC_IDENTITY	223344
#define BACKEND_NODE_IP		v4_node_three

static volatile const __u8 *zero_mac = mac_zero;

struct mock_settings {
	__be16 nat_source_port;
	bool trace_seen;
	__be32 trace_orig_ip4;
	union v6addr trace_orig_ip6;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct mock_settings));
	__uint(max_entries, 1);
} settings_map __section_maps_btf;

#define TRACE_NOTIFY
#define TRACE_EXTENSION
#define trace_extension_hook(ctx, msg) do { \
	__u32 __key = 0; \
	struct mock_settings *__settings = map_lookup_elem(&settings_map, &__key); \
	if (__settings && (msg).subtype == TRACE_TO_OVERLAY) { \
		__settings->trace_seen = true; \
		if ((msg).flags & CLS_FLAG_IPV6) \
			ipv6_addr_copy(&__settings->trace_orig_ip6, &(msg).orig_ip6); \
		else \
			__settings->trace_orig_ip4 = (msg).orig_ip4.be32; \
	} \
} while (0)

/* Set port ranges to have deterministic source port selection */
#include "nodeport_defaults.h"

#include "node_config.h"

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __ctx_buff *ctx __maybe_unused, int ifindex __maybe_unused,
		  __u32 flags __maybe_unused)
{
	/* in this scenario, all traffic should flow through the overlay interface */
	if (ifindex != ENCAP_IFINDEX)
		return CTX_ACT_DROP;

	return CTX_ACT_REDIRECT;
}

#define skb_get_tunnel_key mock_skb_get_tunnel_key
int mock_skb_get_tunnel_key(__maybe_unused struct __sk_buff *skb,
			    __maybe_unused struct bpf_tunnel_key *key,
			    __maybe_unused __u32 size,
			    __maybe_unused __u32 flags)
{
	/* hacky, this is actually only correct for the reply path. But
	 * at least for now the datapath doesn't care about the
	 * transported identity in the forward path.
	 */
	key->tunnel_id = BACKEND_SEC_IDENTITY;

	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_tunnel_key));
	__uint(max_entries, 1);
} tunnel_key_map __section_maps_btf;

#define skb_set_tunnel_key mock_skb_set_tunnel_key
int mock_skb_set_tunnel_key(__maybe_unused struct __sk_buff *skb,
			    __maybe_unused const struct bpf_tunnel_key *key,
			    __maybe_unused __u32 size,
			    __maybe_unused __u32 flags)
{
	__u32 map_key = 0;
	struct bpf_tunnel_key *mock_key = map_lookup_elem(&tunnel_key_map, &map_key);

	if (mock_key)
		memcpy(mock_key, key, sizeof(*key));

	return 0;
}

#include "lib/bpf_overlay.h"

#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_VXLAN)
ASSIGN_CONFIG(union v6addr, router_ipv6, LB_IP6)

/* Test that a SVC request to an intermediate LB node gets DNATed and SNATed,
 * and flows back out on the overlay interface to a remote backend
 * (with WORLD_ID security identity).
 */
PKTGEN(PROG_TYPE, "nodeport_overlay_nat_1_fwd")
int nodeport_overlay_nat_1_fwd_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)zero_mac, (__u8 *)zero_mac,
					  CLIENT_IP, FRONTEND_IP,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "nodeport_overlay_nat_1_fwd")
int nodeport_overlay_nat_1_fwd_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_UDP, 0);

	ipcache_v4_add_entry(BACKEND_IP, 0, BACKEND_SEC_IDENTITY,
			     BACKEND_NODE_IP, 0);

	return overlay_receive_packet(ctx);
}

CHECK(PROG_TYPE, "nodeport_overlay_nat_1_fwd")
int nodeport_overlay_nat_1_fwd_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 key = 0;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != IPV4_GATEWAY)
		test_fatal("src IP hasn't been SNATed to gateway IP");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP hasn't been DNATed to backend IP");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been DNATed to backend port");

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (!settings)
		test_fatal("no test settings found");

	settings->nat_source_port = l4->source;

	struct bpf_tunnel_key *tunnel_key = map_lookup_elem(&tunnel_key_map, &key);

	if (!tunnel_key)
		test_fatal("no tunnel key set");

	assert(tunnel_key->tunnel_id == WORLD_ID);

	assert(settings->trace_seen);
	assert(settings->trace_orig_ip4 == CLIENT_IP);

	test_finish();
}

/* Test that a reply for the SVC request is RevDNATed & RevSNATed,
 * and flows back out on the overlay interface to the client
 * (preserving the backend's security identity).
 */
PKTGEN(PROG_TYPE, "nodeport_overlay_nat_2_reply")
int nodeport_overlay_nat_2_reply_pktgen(struct __ctx_buff *ctx)
{
	__be16 nat_source_port = 0;
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	__u32 key = 0;
	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		nat_source_port = settings->nat_source_port;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)zero_mac, (__u8 *)zero_mac,
					  BACKEND_IP, IPV4_GATEWAY,
					  BACKEND_PORT, nat_source_port);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "nodeport_overlay_nat_2_reply")
int nodeport_overlay_nat_2_reply_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(CLIENT_IP, 0, CLIENT_SEC_IDENTITY,
			     CLIENT_NODE_IP, 0);

	return overlay_receive_packet(ctx);
}

CHECK(PROG_TYPE, "nodeport_overlay_nat_2_reply")
int nodeport_overlay_nat_2_reply_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 key = 0;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != FRONTEND_IP)
		test_fatal("src IP hasn't been RevDNATed to frontend IP");

	if (l3->daddr != CLIENT_IP)
		test_fatal("dst IP is not the client");

	if (l4->source != FRONTEND_PORT)
		test_fatal("src port hasn't been RevDNATed to frontend port");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port is not the client");

	struct bpf_tunnel_key *tunnel_key = map_lookup_elem(&tunnel_key_map, &key);

	if (!tunnel_key)
		test_fatal("no tunnel key set");

	assert(identity_is_remote_node(tunnel_key->tunnel_id));

	test_finish();
}

/* Test that tunneling a packet whose source already matches the selected SNAT
 * address does not report a source-address translation.
 */
PKTGEN(PROG_TYPE, "nodeport_overlay_nat_3_same_source")
int nodeport_overlay_nat_3_same_source_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)zero_mac, (__u8 *)zero_mac,
					  IPV4_GATEWAY, FRONTEND_IP,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "nodeport_overlay_nat_3_same_source")
int nodeport_overlay_nat_3_same_source_setup(struct __ctx_buff *ctx)
{
	__u32 key = 0;
	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (!settings)
		return TEST_ERROR;

	settings->trace_seen = false;
	settings->trace_orig_ip4 = 0;

	return overlay_receive_packet(ctx);
}

CHECK(PROG_TYPE, "nodeport_overlay_nat_3_same_source")
int nodeport_overlay_nat_3_same_source_check(__maybe_unused const struct __ctx_buff *ctx)
{
	__u32 key = 0;
	struct mock_settings *settings;

	test_init();

	settings = map_lookup_elem(&settings_map, &key);
	if (!settings)
		test_fatal("no test settings found");

	assert(settings->trace_seen);
	assert(settings->trace_orig_ip4 == 0);

	test_finish();
}

/* Test that an IPv6 SVC request to an intermediate LB node gets DNATed and
 * SNATed, and that the overlay trace reports the pre-SNAT source address.
 */
PKTGEN(PROG_TYPE, "nodeport_overlay_nat_4_fwd_v6")
int nodeport_overlay_nat_4_fwd_v6_pktgen(struct __ctx_buff *ctx)
{
	union v6addr client_ip = CLIENT_IP6;
	union v6addr frontend_ip = FRONTEND_IP6;
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_udp_packet(&builder,
					  (__u8 *)zero_mac, (__u8 *)zero_mac,
					  client_ip.addr, frontend_ip.addr,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "nodeport_overlay_nat_4_fwd_v6")
int nodeport_overlay_nat_4_fwd_v6_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IP6;
	union v6addr backend_ip = BACKEND_IP6;
	__u16 revnat_id = 2;

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip, FRONTEND_PORT, 1, 125,
			  &backend_ip, BACKEND_PORT, IPPROTO_UDP, 0);

	ipcache_v6_add_entry(&backend_ip, 0, BACKEND_SEC_IDENTITY,
			     BACKEND_NODE_IP, 0);

	return overlay_receive_packet(ctx);
}

CHECK(PROG_TYPE, "nodeport_overlay_nat_4_fwd_v6")
int nodeport_overlay_nat_4_fwd_v6_check(const struct __ctx_buff *ctx)
{
	union v6addr client_ip = CLIENT_IP6;
	union v6addr backend_ip = BACKEND_IP6;
	union v6addr lb_ip = LB_IP6;
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ipv6hdr *l3;
	struct ethhdr *l2;
	__u32 key = 0;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("L2 header out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("IPv6 header out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("UDP header out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &lb_ip))
		test_fatal("source IP hasn't been SNATed to router IP");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip))
		test_fatal("destination IP hasn't been DNATed to backend IP");

	if (l4->dest != BACKEND_PORT)
		test_fatal("destination port hasn't been DNATed to backend port");

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (!settings)
		test_fatal("no test settings found");

	struct bpf_tunnel_key *tunnel_key = map_lookup_elem(&tunnel_key_map, &key);

	if (!tunnel_key)
		test_fatal("no tunnel key set");

	assert(settings->trace_seen);
	assert(ipv6_addr_equals(&settings->trace_orig_ip6, &client_ip));

	test_finish();
}

/* Test that tunneling an IPv6 packet whose source already matches the selected
 * SNAT address does not report a source-address translation.
 */
PKTGEN(PROG_TYPE, "nodeport_overlay_nat_5_same_source_v6")
int nodeport_overlay_nat_5_same_source_v6_pktgen(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IP6;
	union v6addr lb_ip = LB_IP6;
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_udp_packet(&builder,
					  (__u8 *)zero_mac, (__u8 *)zero_mac,
					  lb_ip.addr, frontend_ip.addr,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "nodeport_overlay_nat_5_same_source_v6")
int nodeport_overlay_nat_5_same_source_v6_setup(struct __ctx_buff *ctx)
{
	__u32 key = 0;
	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (!settings)
		return TEST_ERROR;

	settings->trace_seen = false;
	memset(&settings->trace_orig_ip6, 0, sizeof(settings->trace_orig_ip6));

	return overlay_receive_packet(ctx);
}

CHECK(PROG_TYPE, "nodeport_overlay_nat_5_same_source_v6")
int nodeport_overlay_nat_5_same_source_v6_check(__maybe_unused const struct __ctx_buff *ctx)
{
	union v6addr zero_addr = {};
	__u32 key = 0;
	struct mock_settings *settings;

	test_init();

	settings = map_lookup_elem(&settings_map, &key);
	if (!settings)
		test_fatal("no test settings found");

	assert(settings->trace_seen);
	assert(ipv6_addr_equals(&settings->trace_orig_ip6, &zero_addr));

	test_finish();
}
