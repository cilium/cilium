// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT

#define TUNNEL_PROTOCOL		TUNNEL_PROTOCOL_VXLAN
#define ENCAP_IFINDEX		42
#define TUNNEL_MODE

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)
#define CLIENT_SEC_IDENTITY	112233
#define CLIENT_NODE_IP		v4_node_one

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_two
#define IPV4_DIRECT_ROUTING	LB_IP

#define BACKEND_IP		v4_pod_three
#define BACKEND_PORT		__bpf_htons(8080)
#define BACKEND_SEC_IDENTITY	223344
#define BACKEND_NODE_IP		v4_node_three

static volatile const __u8 *zero_mac = mac_zero;

struct mock_settings {
	__be16 nat_source_port;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct mock_settings));
	__uint(max_entries, 1);
} settings_map __section_maps_btf;

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

#include <bpf_overlay.c>

#include "lib/ipcache.h"
#include "lib/lb.h"

#define FROM_OVERLAY	0

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

/* Test that a SVC request to an intermediate LB node gets DNATed and SNATed,
 * and flows back out on the overlay interface to a remote backend
 * (with WORLD_ID security identity).
 */
PKTGEN("tc", "nodeport_overlay_nat_1_fwd")
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

SETUP("tc", "nodeport_overlay_nat_1_fwd")
int nodeport_overlay_nat_1_fwd_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_UDP, 0);

	ipcache_v4_add_entry(BACKEND_IP, 0, BACKEND_SEC_IDENTITY,
			     BACKEND_NODE_IP, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "nodeport_overlay_nat_1_fwd")
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

	if (settings)
		settings->nat_source_port = l4->source;

	struct bpf_tunnel_key *tunnel_key = map_lookup_elem(&tunnel_key_map, &key);

	if (!tunnel_key)
		test_fatal("no tunnel key set");

	assert(tunnel_key->tunnel_id == WORLD_ID);

	test_finish();
}

/* Test that a reply for the SVC request is RevDNATed & RevSNATed,
 * and flows back out on the overlay interface to the client
 * (preserving the backend's security identity).
 */
PKTGEN("tc", "nodeport_overlay_nat_2_reply")
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

SETUP("tc", "nodeport_overlay_nat_2_reply")
int nodeport_overlay_nat_2_reply_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(CLIENT_IP, 0, CLIENT_SEC_IDENTITY,
			     CLIENT_NODE_IP, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "nodeport_overlay_nat_2_reply")
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
