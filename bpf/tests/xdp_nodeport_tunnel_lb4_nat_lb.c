// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/xdp.h>
#include "pktgen.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_NODEPORT_ACCELERATION
#define TUNNEL_MODE
#define ENCAP_IFINDEX 42

#define DISABLE_LOOPBACK_LB

/* Skip ingress policy checks, not needed to validate hairpin flow */
#define USE_BPF_PROG_FOR_INGRESS_POLICY
#undef FORCE_LOCAL_POLICY_EVAL_AT_SOURCE

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP_LOCAL	v4_svc_one
#define FRONTEND_IP_REMOTE	v4_svc_two
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_one
#define IPV4_DIRECT_ROUTING	LB_IP

#define BACKEND_NODE_IP		v4_node_two
#define BACKEND_TUNNEL_SRC_PORT	__bpf_htons(1234)
#define BACKEND_IP_LOCAL	v4_pod_one
#define BACKEND_IP_REMOTE	v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)
#define BACKEND_SEC_LABEL	112233

static volatile const __u8 *client_mac = mac_one;
/* this matches the default node_config.h: */
static volatile const __u8 lb_mac[ETH_ALEN]	= { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 };
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *local_backend_mac = mac_four;
static volatile const __u8 *remote_backend_mac = mac_five;

static __be16 nat_source_port;

#include <bpf_xdp.c>

#define FROM_NETDEV	0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_xdp_entry,
	},
};

/* Test that a SVC request to a local backend
 * - gets DNATed (but not SNATed)
 * - gets passed up from XDP to TC
 */
PKTGEN("xdp", "xdp_nodeport_tunnel_local_backend")
int nodeport_tunnel_local_backend_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = FRONTEND_IP_LOCAL;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = FRONTEND_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("xdp", "xdp_nodeport_tunnel_local_backend")
int nodeport_tunnel_local_backend_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Register a fake LB backend matching our packet. */
	struct lb4_key lb_svc_key = {
		.address = FRONTEND_IP_LOCAL,
		.dport = FRONTEND_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	/* Create a service with only one backend */
	struct lb4_service lb_svc_value = {
		.count = 1,
		.flags = SVC_FLAG_ROUTABLE,
		.rev_nat_index = revnat_id,
	};
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);
	/* We need to register both in the external and internal scopes for the
	 * packet to be redirected to a neighboring node
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* A backend between 1 and .count is chosen, since we have only one backend
	 * it is always backend_slot 1. Point it to backend_id 124.
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;
	lb_svc_key.backend_slot = 1;
	lb_svc_value.backend_id = 124;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* Insert a reverse NAT entry for the above service */
	struct lb4_reverse_nat revnat_value = {
		.address = FRONTEND_IP_LOCAL,
		.port = FRONTEND_PORT,
	};
	map_update_elem(&LB4_REVERSE_NAT_MAP, &revnat_id, &revnat_value, BPF_ANY);

	/* Create backend id 124 which contains the IP and port to send the
	 * packet to.
	 */
	struct lb4_backend backend = {
		.address = BACKEND_IP_LOCAL,
		.port = BACKEND_PORT,
		.proto = IPPROTO_TCP,
		.flags = BE_STATE_ACTIVE,
	};
	map_update_elem(&LB4_BACKEND_MAP, &lb_svc_value.backend_id, &backend, BPF_ANY);

	/* add local backend */
	struct endpoint_info ep_value = {};

	memcpy(&ep_value.mac, (__u8 *)local_backend_mac, ETH_ALEN);
	memcpy(&ep_value.node_mac, (__u8 *)node_mac, ETH_ALEN);

	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP_LOCAL,
	};
	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP_LOCAL,
	};
	struct remote_endpoint_info cache_value = {
		.sec_label = BACKEND_SEC_LABEL,
	};
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "xdp_nodeport_tunnel_local_backend")
int nodeport_tunnel_local_backend_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 *meta;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	status_code = data;
	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	meta = (void *)status_code + sizeof(__u32);
	if ((void *)meta + sizeof(__u32) > data_end)
		test_fatal("meta out of bounds");

	l2 = (void *)meta + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	assert(*status_code == CTX_ACT_OK);

	assert((*meta & XFER_PKT_NO_SVC) == XFER_PKT_NO_SVC);

	if (memcmp(l2->h_source, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the client MAC")
	if (memcmp(l2->h_dest, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the LB MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP_LOCAL)
		test_fatal("dst IP hasn't been NATed to local backend IP");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst TCP port hasn't been NATed to backend port");

	test_finish();
}

/* Test that a SVC request that is LBed to a NAT remote backend
 * - gets DNATed and SNATed,
 * - gets passed up from XDP to TC for tunnel-redirect
 */
PKTGEN("xdp", "xdp_nodeport_tunnel_nat_fwd")
int nodeport_tunnel_nat_fwd_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = FRONTEND_IP_REMOTE;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = FRONTEND_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("xdp", "xdp_nodeport_tunnel_nat_fwd")
int nodeport_tunnel_nat_fwd_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Register a fake LB backend matching our packet. */
	struct lb4_key lb_svc_key = {
		.address = FRONTEND_IP_REMOTE,
		.dport = FRONTEND_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	/* Create a service with only one backend */
	struct lb4_service lb_svc_value = {
		.count = 1,
		.flags = SVC_FLAG_ROUTABLE,
		.rev_nat_index = revnat_id,
	};
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);
	/* We need to register both in the external and internal scopes for the
	 * packet to be redirected to a neighboring node
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* A backend between 1 and .count is chosen, since we have only one backend
	 * it is always backend_slot 1. Point it to backend_id 124.
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;
	lb_svc_key.backend_slot = 1;
	lb_svc_value.backend_id = 124;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* Insert a reverse NAT entry for the above service */
	struct lb4_reverse_nat revnat_value = {
		.address = FRONTEND_IP_REMOTE,
		.port = FRONTEND_PORT,
	};
	map_update_elem(&LB4_REVERSE_NAT_MAP, &revnat_id, &revnat_value, BPF_ANY);

	/* Create backend id 124 which contains the IP and port to send the
	 * packet to.
	 */
	struct lb4_backend backend = {
		.address = BACKEND_IP_REMOTE,
		.port = BACKEND_PORT,
		.proto = IPPROTO_TCP,
		.flags = BE_STATE_ACTIVE,
	};
	map_update_elem(&LB4_BACKEND_MAP, &lb_svc_value.backend_id, &backend, BPF_ANY);

	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP_REMOTE,
	};
	struct remote_endpoint_info cache_value = {
		.sec_label = BACKEND_SEC_LABEL,
		.tunnel_endpoint = BACKEND_NODE_IP,
	};
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

struct xdp_meta_encap {
	__u32 data[4];
};

CHECK("xdp", "xdp_nodeport_tunnel_nat_fwd")
int nodeport_tunnel_nat_fwd_check(__maybe_unused const struct __ctx_buff *ctx)
{
	struct xdp_meta_encap *meta;
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

	assert(*status_code == CTX_ACT_OK);

	meta = (void *)status_code + sizeof(*status_code);
	if ((void *)meta + sizeof(*meta) > data_end)
		test_fatal("meta data out of bounds");

	l2 = (void *)meta + sizeof(*meta);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (!(meta->data[XFER_FLAGS] & XFER_PKT_ENCAP))
		test_fatal("packet doesn't have encap-needed flag");
	if (!(meta->data[XFER_FLAGS] & XFER_PKT_SNAT_DONE))
		test_fatal("packet doesn't have snat-done flag");

	if (meta->data[XFER_ENCAP_NODEID] != BACKEND_NODE_IP)
		test_fatal("packet doesn't have the expected tunnel_id")
	if (meta->data[XFER_ENCAP_SECLABEL] != WORLD_ID)
		test_fatal("packet doesn't have the expected Src SEC label")
	if (meta->data[XFER_ENCAP_DSTID] != BACKEND_SEC_LABEL)
		test_fatal("packet doesn't have the expected Dst SEC ID")

	if (memcmp(l2->h_source, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("src MAC has changed")
	if (memcmp(l2->h_dest, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC has changed")

	if (l3->saddr != IPV4_GATEWAY)
		test_fatal("src IP hasn't been NATed to Gateway IP");

	if (l3->daddr != BACKEND_IP_REMOTE)
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (l4->source == CLIENT_PORT)
		test_fatal("src port hasn't been NATed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	nat_source_port = l4->source;

	test_finish();
}

int build_encap_reply(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct genevehdr *geneve;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct ethhdr *l2;
	struct iphdr *l3;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)remote_backend_mac, (__u8 *)lb_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = BACKEND_NODE_IP;
	l3->daddr = LB_IP;

	udp = pktgen__push_udphdr(&builder);
	if (!udp)
		return TEST_ERROR;

	udp->source = BACKEND_TUNNEL_SRC_PORT;
	udp->dest = bpf_htons(TUNNEL_PORT);

	geneve = pktgen__push_default_genevehdr(&builder);
	if (!geneve)
		return TEST_ERROR;

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = BACKEND_IP_REMOTE;
	l3->daddr = IPV4_GATEWAY;

	tcp = pktgen__push_default_tcphdr(&builder);
	if (!tcp)
		return TEST_ERROR;

	tcp->source = BACKEND_PORT;
	tcp->dest = nat_source_port;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

struct xdp_meta_skip_svc {
	__u32 data;
};

int check_encap_reply(const struct __ctx_buff *ctx)
{
	struct xdp_meta_skip_svc *meta;
	void *data, *data_end;
	__u32 *status_code;
	struct genevehdr *geneve;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct ethhdr *l2, *inner_l2;
	struct iphdr *l3, *inner_l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	meta = (void *)status_code + sizeof(*status_code);
	if ((void *)meta + sizeof(*meta) > data_end)
		test_fatal("meta data out of bounds");

	l2 = (void *)meta + sizeof(*meta);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	udp = (void *)l3 + sizeof(struct iphdr);
	if ((void *)udp + sizeof(*udp) > data_end)
		test_fatal("UDP header out of bounds");

	geneve = (void *)udp + sizeof(*udp);
	if ((void *)geneve + sizeof(*geneve) > data_end)
		test_fatal("GENEVE out of bounds");

	inner_l2 = (void *)geneve + sizeof(*geneve);
	if ((void *)inner_l2 + sizeof(*inner_l2) > data_end)
		test_fatal("inner l2 out of bounds");

	inner_l3 = (void *)inner_l2 + sizeof(*inner_l2);
	if ((void *)inner_l3 + sizeof(*inner_l3) > data_end)
		test_fatal("inner l3 out of bounds");

	tcp = (void *)inner_l3 + sizeof(*inner_l3);
	if ((void *)tcp + sizeof(*tcp) > data_end)
		test_fatal("TCP header out of bounds");

	if (!(meta->data & XFER_PKT_NO_SVC))
		test_fatal("packet doesn't have no-svc flag");

	if (memcmp(l2->h_source, (__u8 *)remote_backend_mac, ETH_ALEN) != 0)
		test_fatal("src MAC has changed")
	if (memcmp(l2->h_dest, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC has changed")

	if (l3->saddr != BACKEND_NODE_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != LB_IP)
		test_fatal("dst IP has changed");

	if (udp->source != BACKEND_TUNNEL_SRC_PORT)
		test_fatal("src port has changed");

	if (udp->dest != bpf_htons(TUNNEL_PORT))
		test_fatal("dst port has changed");

	if (geneve->protocol_type != bpf_htons(ETH_P_TEB))
		test_fatal("GENEVE doesn't have correct proto type");

	if (inner_l3->saddr != BACKEND_IP_REMOTE)
		test_fatal("inner src IP has changed");

	if (inner_l3->daddr != IPV4_GATEWAY)
		test_fatal("inner dst IP has changed");

	if (tcp->source != BACKEND_PORT)
		test_fatal("inner src port has changed");

	if (tcp->dest != nat_source_port)
		test_fatal("inner src port has changed");

	test_finish();
}

/* Test that XDP let's the encapsulated reply pass through.
 * (It isn't handled until from-overlay).
 */
PKTGEN("xdp", "xdp_nodeport_tunnel_nat_fwd_reply")
int nodeport_nat_fwd_reply_pktgen(struct __ctx_buff *ctx)
{
	return build_encap_reply(ctx);
}

SETUP("xdp", "xdp_nodeport_tunnel_nat_fwd_reply")
int nodeport_nat_fwd_reply_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "xdp_nodeport_tunnel_nat_fwd_reply")
int nodeport_nat_fwd_reply_check(const struct __ctx_buff *ctx)
{
	return check_encap_reply(ctx);
}
