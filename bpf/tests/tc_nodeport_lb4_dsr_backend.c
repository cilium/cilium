// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_DSR		1
#define DSR_ENCAP_GENEVE	3
#define ENABLE_HOST_ROUTING

#define DISABLE_LOOPBACK_LB

/* Skip ingress policy checks, not needed to validate hairpin flow */
#define USE_BPF_PROG_FOR_INGRESS_POLICY
#undef FORCE_LOCAL_POLICY_EVAL_AT_SOURCE

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v4_pod_one
#define BACKEND_PORT		__bpf_htons(8080)

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *backend_mac = mac_four;

#define SECCTX_FROM_IPCACHE 1

#include "bpf_host.c"

#define FROM_NETDEV	0
#define TO_NETDEV	1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
		[TO_NETDEV] = &cil_to_netdev,
	},
};

/* Test that a remote node
 * - doesn't touch a DSR request,
 * - redirects it to the pod (as ENABLE_HOST_ROUTING is set)
 * - creates a matching CT entry, and SNAT entry from the DSR info
 */
PKTGEN("tc", "tc_nodeport_dsr_backend")
int nodeport_dsr_backend_pktgen(struct __ctx_buff *ctx)
{
	struct dsr_opt_v4 *opt;
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

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)node_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr_with_options(&builder, 2);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = BACKEND_IP;

	opt = (void *)l3 + sizeof(*l3);
	opt->type = DSR_IPV4_OPT_TYPE;
	opt->len = sizeof(*opt);
	opt->port = bpf_ntohs(FRONTEND_PORT);
	opt->addr = bpf_ntohl(FRONTEND_IP);

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = BACKEND_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_dsr_backend")
int nodeport_dsr_backend_setup(struct __ctx_buff *ctx)
{
	/* add local backend */
	struct endpoint_info ep_value = {};

	memcpy(&ep_value.mac, (__u8 *)backend_mac, ETH_ALEN);
	memcpy(&ep_value.node_mac, (__u8 *)node_mac, ETH_ALEN);

	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};
	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

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

CHECK("tc", "tc_nodeport_dsr_backend")
int nodeport_dsr_backend_check(struct __ctx_buff *ctx)
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

	assert(*status_code == CTX_ACT_REDIRECT);

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

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the endpoint MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP has changed");

	if (opt->type != DSR_IPV4_OPT_TYPE)
		test_fatal("type in DSR IP option has changed")
	if (opt->len != 8)
		test_fatal("length in DSR IP option has changed")
	if (opt->port != __bpf_ntohs(FRONTEND_PORT))
		test_fatal("port in DSR IP option has changed")
	if (opt->addr != __bpf_ntohl(FRONTEND_IP))
		test_fatal("addr in DSR IP option has changed")

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port has changed");

	struct ipv4_ct_tuple tuple;
	struct ct_entry *ct_entry;
	int l4_off, ret;

	ret = lb4_extract_tuple(ctx, l3, sizeof(*status_code) + ETH_HLEN,
				&l4_off, &tuple);
	assert(!IS_ERR(ret));

	tuple.flags = TUPLE_F_IN;
	ipv4_ct_tuple_reverse(&tuple);

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR found");
	if (!ct_entry->dsr)
		test_fatal("CT entry doesn't have the .dsr flag set");

	struct ipv4_nat_entry *nat_entry;

	tuple.sport = BACKEND_PORT;
	tuple.dport = CLIENT_PORT;

	nat_entry = snat_v4_lookup(&tuple);
	if (!nat_entry)
		test_fatal("no SNAT entry for DSR found");
	if (nat_entry->to_saddr != FRONTEND_IP)
		test_fatal("SNAT entry has wrong address");
	if (nat_entry->to_sport != FRONTEND_PORT)
		test_fatal("SNAT entry has wrong port");

	test_finish();
}

static __always_inline int build_reply(struct __ctx_buff *ctx)
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

	ethhdr__set_macs(l2, (__u8 *)node_mac, (__u8 *)client_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = BACKEND_IP;
	l3->daddr = CLIENT_IP;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = BACKEND_PORT;
	l4->dest = CLIENT_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

static __always_inline int check_reply(const struct __ctx_buff *ctx)
{
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

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the client MAC")

	if (l3->saddr != FRONTEND_IP)
		test_fatal("src IP hasn't been RevNATed to frontend IP");

	if (l3->daddr != CLIENT_IP)
		test_fatal("dst IP has changed");

	if (l4->source != FRONTEND_PORT)
		test_fatal("src port hasn't been RevNATed to frontend port");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port has changed");

	test_finish();
}

/* Test that the backend node revDNATs a reply from the
 * DSR backend, and sends the reply back to the client.
 */
PKTGEN("tc", "tc_nodeport_dsr_backend_reply")
int nodeport_dsr_backend_reply_pktgen(struct __ctx_buff *ctx)
{
	return build_reply(ctx);
}

SETUP("tc", "tc_nodeport_dsr_backend_reply")
int nodeport_dsr_backend_reply_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_dsr_backend_reply")
int nodeport_dsr_backend_reply_check(const struct __ctx_buff *ctx)
{
	return check_reply(ctx);
}
