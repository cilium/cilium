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
#define ENABLE_DSR

#define DISABLE_LOOPBACK_LB

/* Skip ingress policy checks, not needed to validate hairpin flow */
#define USE_BPF_PROG_FOR_INGRESS_POLICY
#undef FORCE_LOCAL_POLICY_EVAL_AT_SOURCE

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		v4_svc_two
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_one
#define IPV4_DIRECT_ROUTING	LB_IP

#define BACKEND_IP		v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define fib_lookup mock_fib_lookup

static volatile const __u8 *client_mac = mac_one;
/* this matches the default node_config.h: */
static volatile const __u8 lb_mac[ETH_ALEN] = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 };
static volatile const __u8 *remote_backend_mac = mac_five;

long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	params->ifindex = 0;

	if (params->ipv4_dst == BACKEND_IP) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)remote_backend_mac, ETH_ALEN);
	} else {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
	}

	return 0;
}

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

/* Test that a SVC request that is LBed to a DSR remote backend
 * - gets DNATed,
 * - has IP Option inserted,
 * - gets redirected back out by XDP
 */
PKTGEN("xdp", "xdp_nodeport_dsr_fwd")
int nodeport_dsr_fwd_pktgen(struct __ctx_buff *ctx)
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
	l3->daddr = FRONTEND_IP;

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

SETUP("xdp", "xdp_nodeport_dsr_fwd")
int nodeport_dsr_fwd_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Register a fake LB backend matching our packet. */
	struct lb4_key lb_svc_key = {
		.address = FRONTEND_IP,
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
		.address = FRONTEND_IP,
		.port = FRONTEND_PORT,
	};
	map_update_elem(&LB4_REVERSE_NAT_MAP, &revnat_id, &revnat_value, BPF_ANY);

	/* Create backend id 124 which contains the IP and port to send the
	 * packet to.
	 */
	struct lb4_backend backend = {
		.address = BACKEND_IP,
		.port = BACKEND_PORT,
		.proto = IPPROTO_TCP,
		.flags = BE_STATE_ACTIVE,
	};
	map_update_elem(&LB4_BACKEND_MAP, &lb_svc_value.backend_id, &backend, BPF_ANY);

	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = 32,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};
	struct remote_endpoint_info cache_value = {
		.sec_identity = 112233,
	};
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "xdp_nodeport_dsr_fwd")
int nodeport_dsr_fwd_check(__maybe_unused const struct __ctx_buff *ctx)
{
	struct dsr_opt_v4 *opt;
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

	opt = (void *)l3 + sizeof(struct iphdr);
	if ((void *)opt + 2 * sizeof(__u32) > data_end)
		test_fatal("l3 DSR option out of bounds");

	l4 = (void *)opt + sizeof(*opt);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)remote_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the backend MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (opt->type != DSR_IPV4_OPT_TYPE)
		test_fatal("type in DSR IP option is bad")
	if (opt->len != 8)
		test_fatal("length in DSR IP option is bad")
	if (opt->port != __bpf_ntohs(FRONTEND_PORT))
		test_fatal("port in DSR IP option is bad")
	if (opt->addr != __bpf_ntohl(FRONTEND_IP))
		test_fatal("addr in DSR IP option is bad")

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	test_finish();
}
