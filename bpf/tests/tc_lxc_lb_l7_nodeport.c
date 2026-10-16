// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define ENABLE_NODEPORT 1

#define CLIENT_PORT __bpf_htons(12345)
#define LEGACY_PORT __bpf_htons(12346)
#define LEGACY_PROXY_PORT __bpf_htons(12347)
#define NODEPORT_PORT __bpf_htons(32443)
#define INGRESS_PROXY_PORT __bpf_htons(10445)
#define POLICY_PROXY_PORT __bpf_htons(15000)

static volatile bool fib_lookup_called;

#define fib_lookup mock_fib_lookup
static __always_inline int
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	fib_lookup_called = true;
	/* Keep non-proxy traffic independent of the test namespace's routes. */
	return BPF_FIB_LKUP_RET_NOT_FWDED;
}

#include "lib/bpf_lxc.h"
#include "lib/ipcache.h"
#include "lib/policy.h"
#include "nodeport_defaults.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })
ASSIGN_CONFIG(bool, enable_l7_lb, true)
ASSIGN_CONFIG(bool, enable_bpf_host_routing, true)

/* Keep the original frontend tuple across SYN, retransmission and ACK/data.
 * Unlike L4 LB, L7 LB does not DNAT the packet before creating CT_EGRESS.
 */
static __always_inline int
generate_packet(struct __ctx_buff *ctx, bool ipv6, __be16 client_port, bool syn)
{
	struct pktgen builder;
	struct tcphdr *tcp;

	pktgen__init(&builder, ctx);
	if (ipv6)
		tcp = pktgen__push_ipv6_tcp_packet(&builder,
						   (__u8 *)mac_one, (__u8 *)mac_two,
						   (__u8 *)v6_pod_one, (__u8 *)v6_node_two,
						   client_port, NODEPORT_PORT);
	else
		tcp = pktgen__push_ipv4_tcp_packet(&builder,
						   (__u8 *)mac_one, (__u8 *)mac_two,
						   v4_pod_one, v4_node_two,
						   client_port, NODEPORT_PORT);
	if (!tcp)
		return TEST_ERROR;

	tcp->syn = syn;
	tcp->ack = !syn;
	if (!syn) {
		tcp->seq = bpf_htonl(123457);
		tcp->ack_seq = bpf_htonl(654321);
		if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
			return TEST_ERROR;
	}
	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
setup_packet(struct __ctx_buff *ctx, bool ipv6, bool service, __be16 policy_proxy_port)
{
	struct lb4_key key4 = {
		.dport = NODEPORT_PORT,
		.proto = IPPROTO_TCP,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	struct lb6_key key6 = {
		.dport = NODEPORT_PORT,
		.proto = IPPROTO_TCP,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	struct lb4_service svc4 = {
		.flags = SVC_FLAG_ROUTABLE | SVC_FLAG_NODEPORT,
		.flags2 = SVC_FLAG_L7_LOADBALANCER,
		.l7_lb_proxy_port = INGRESS_PROXY_PORT,
	};
	struct lb6_service svc6 = {
		.flags = SVC_FLAG_ROUTABLE | SVC_FLAG_NODEPORT,
		.flags2 = SVC_FLAG_L7_LOADBALANCER,
		.l7_lb_proxy_port = INGRESS_PROXY_PORT,
	};
	union v6addr remote_node = { .addr = v6_node_two_addr };

	/* Only the wildcard frontend exists on the sending node. */
	if (ipv6) {
		ipcache_v6_add_entry(&remote_node, 0, REMOTE_NODE_ID, 0, 0);
		if (service)
			map_update_elem(&cilium_lb6_services_v2, &key6, &svc6, BPF_ANY);
		else
			map_delete_elem(&cilium_lb6_services_v2, &key6);
	} else {
		ipcache_v4_add_entry(v4_node_two, 0, REMOTE_NODE_ID, 0, 0);
		if (service)
			map_update_elem(&cilium_lb4_services_v2, &key4, &svc4, BPF_ANY);
		else
			map_delete_elem(&cilium_lb4_services_v2, &key4);
	}
	policy_add_entry(true, REMOTE_NODE_ID, IPPROTO_TCP, NODEPORT_PORT, 0, false,
			 policy_proxy_port);
	fib_lookup_called = false;
	return pod_send_packet(ctx);
}

static __always_inline int
check_packet(const struct __ctx_buff *ctx, bool ipv6, __be16 client_port,
	     __be16 proxy_port, bool source_node_lb)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct ct_entry *entry;
	struct tcphdr *tcp;
	struct ethhdr *eth;
	__u32 *status = data;

	test_init();

	if ((void *)(status + 1) > data_end)
		test_fatal("status out of bounds");
	assert(*status == CTX_ACT_OK);
	assert(proxy_port ? ctx->mark == (MARK_MAGIC_TO_PROXY | (__u32)proxy_port << 16) :
	       (ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_TO_PROXY);
	assert(fib_lookup_called == !proxy_port);

	eth = (void *)(status + 1);
	if ((void *)(eth + 1) > data_end)
		test_fatal("ethernet header out of bounds");

	if (ipv6) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		struct ipv6_ct_tuple tuple = {
			.saddr = { .addr = v6_node_two_addr },
			.daddr = { .addr = v6_pod_one_addr },
			.sport = client_port,
			.dport = NODEPORT_PORT,
			.nexthdr = IPPROTO_TCP,
			.flags = TUPLE_F_OUT,
		};

		if ((void *)(ip6 + 1) > data_end)
			test_fatal("IPv6 header out of bounds");
		assert(ipv6_addr_equals((union v6addr *)&ip6->saddr, &tuple.daddr));
		assert(ipv6_addr_equals((union v6addr *)&ip6->daddr, &tuple.saddr));
		tcp = (void *)(ip6 + 1);
		entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
		if (!entry)
			test_fatal("missing IPv6 CT entry");
		if (source_node_lb)
			assert(ipv6_addr_equals(&entry->nat_addr, &tuple.saddr));
	} else {
		struct iphdr *ip4 = (void *)(eth + 1);
		struct ipv4_ct_tuple tuple = {
			.saddr = v4_node_two,
			.daddr = v4_pod_one,
			.sport = client_port,
			.dport = NODEPORT_PORT,
			.nexthdr = IPPROTO_TCP,
			.flags = TUPLE_F_OUT,
		};

		if ((void *)(ip4 + 1) > data_end)
			test_fatal("IPv4 header out of bounds");
		assert(ip4->saddr == v4_pod_one);
		assert(ip4->daddr == v4_node_two);
		tcp = (void *)(ip4 + 1);
		entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
		if (!entry)
			test_fatal("missing IPv4 CT entry");
		if (source_node_lb)
			assert(entry->nat_addr.p4 == v4_node_two);
	}
	if ((void *)(tcp + 1) > data_end)
		test_fatal("TCP header out of bounds");
	assert(tcp->source == client_port);
	assert(tcp->dest == NODEPORT_PORT);
	assert(entry->proxy_redirect == !!proxy_port);
	assert(entry->nat_port == (source_node_lb ? NODEPORT_PORT : 0));

	test_finish();
}

/* v4: tests run in name order and preserve CT state between packets.
 * The legacy cases establish connections before adding the wildcard service.
 * An existing egress-policy proxy must not be mistaken for source-node L7 LB.
 */

PKTGEN(PROG_TYPE, "l7_nodeport_v4_01_syn")
int l7_nodeport_v4_01_syn_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, false, CLIENT_PORT, true);
}

SETUP(PROG_TYPE, "l7_nodeport_v4_01_syn")
int l7_nodeport_v4_01_syn_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, false, true, 0);
}

CHECK(PROG_TYPE, "l7_nodeport_v4_01_syn")
int l7_nodeport_v4_01_syn_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, false, CLIENT_PORT, INGRESS_PROXY_PORT, true);
}

PKTGEN(PROG_TYPE, "l7_nodeport_v4_02_syn_retransmit")
int l7_nodeport_v4_02_syn_retransmit_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, false, CLIENT_PORT, true);
}

SETUP(PROG_TYPE, "l7_nodeport_v4_02_syn_retransmit")
int l7_nodeport_v4_02_syn_retransmit_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, false, true, 0);
}

CHECK(PROG_TYPE, "l7_nodeport_v4_02_syn_retransmit")
int l7_nodeport_v4_02_syn_retransmit_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, false, CLIENT_PORT, INGRESS_PROXY_PORT, true);
}

PKTGEN(PROG_TYPE, "l7_nodeport_v4_03_ack_data")
int l7_nodeport_v4_03_ack_data_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, false, CLIENT_PORT, false);
}

SETUP(PROG_TYPE, "l7_nodeport_v4_03_ack_data")
int l7_nodeport_v4_03_ack_data_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, false, true, 0);
}

CHECK(PROG_TYPE, "l7_nodeport_v4_03_ack_data")
int l7_nodeport_v4_03_ack_data_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, false, CLIENT_PORT, INGRESS_PROXY_PORT, true);
}

PKTGEN(PROG_TYPE, "l7_nodeport_v4_04_legacy_syn")
int l7_nodeport_v4_04_legacy_syn_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, false, LEGACY_PORT, true);
}

SETUP(PROG_TYPE, "l7_nodeport_v4_04_legacy_syn")
int l7_nodeport_v4_04_legacy_syn_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, false, false, 0);
}

CHECK(PROG_TYPE, "l7_nodeport_v4_04_legacy_syn")
int l7_nodeport_v4_04_legacy_syn_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, false, LEGACY_PORT, 0, false);
}

PKTGEN(PROG_TYPE, "l7_nodeport_v4_05_legacy_ack")
int l7_nodeport_v4_05_legacy_ack_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, false, LEGACY_PORT, false);
}

SETUP(PROG_TYPE, "l7_nodeport_v4_05_legacy_ack")
int l7_nodeport_v4_05_legacy_ack_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, false, true, 0);
}

CHECK(PROG_TYPE, "l7_nodeport_v4_05_legacy_ack")
int l7_nodeport_v4_05_legacy_ack_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, false, LEGACY_PORT, 0, false);
}

PKTGEN(PROG_TYPE, "l7_nodeport_v4_06_legacy_proxy_syn")
int l7_nodeport_v4_06_legacy_proxy_syn_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, false, LEGACY_PROXY_PORT, true);
}

SETUP(PROG_TYPE, "l7_nodeport_v4_06_legacy_proxy_syn")
int l7_nodeport_v4_06_legacy_proxy_syn_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, false, false, POLICY_PROXY_PORT);
}

CHECK(PROG_TYPE, "l7_nodeport_v4_06_legacy_proxy_syn")
int l7_nodeport_v4_06_legacy_proxy_syn_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, false, LEGACY_PROXY_PORT, POLICY_PROXY_PORT, false);
}

PKTGEN(PROG_TYPE, "l7_nodeport_v4_07_legacy_proxy_ack")
int l7_nodeport_v4_07_legacy_proxy_ack_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, false, LEGACY_PROXY_PORT, false);
}

SETUP(PROG_TYPE, "l7_nodeport_v4_07_legacy_proxy_ack")
int l7_nodeport_v4_07_legacy_proxy_ack_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, false, true, POLICY_PROXY_PORT);
}

CHECK(PROG_TYPE, "l7_nodeport_v4_07_legacy_proxy_ack")
int l7_nodeport_v4_07_legacy_proxy_ack_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, false, LEGACY_PROXY_PORT, POLICY_PROXY_PORT, false);
}

/* v6: tests run in name order and preserve CT state between packets.
 * The legacy cases establish connections before adding the wildcard service.
 * An existing egress-policy proxy must not be mistaken for source-node L7 LB.
 */

PKTGEN(PROG_TYPE, "l7_nodeport_v6_01_syn")
int l7_nodeport_v6_01_syn_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, true, CLIENT_PORT, true);
}

SETUP(PROG_TYPE, "l7_nodeport_v6_01_syn")
int l7_nodeport_v6_01_syn_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, true, true, 0);
}

CHECK(PROG_TYPE, "l7_nodeport_v6_01_syn")
int l7_nodeport_v6_01_syn_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, true, CLIENT_PORT, INGRESS_PROXY_PORT, true);
}

PKTGEN(PROG_TYPE, "l7_nodeport_v6_02_syn_retransmit")
int l7_nodeport_v6_02_syn_retransmit_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, true, CLIENT_PORT, true);
}

SETUP(PROG_TYPE, "l7_nodeport_v6_02_syn_retransmit")
int l7_nodeport_v6_02_syn_retransmit_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, true, true, 0);
}

CHECK(PROG_TYPE, "l7_nodeport_v6_02_syn_retransmit")
int l7_nodeport_v6_02_syn_retransmit_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, true, CLIENT_PORT, INGRESS_PROXY_PORT, true);
}

PKTGEN(PROG_TYPE, "l7_nodeport_v6_03_ack_data")
int l7_nodeport_v6_03_ack_data_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, true, CLIENT_PORT, false);
}

SETUP(PROG_TYPE, "l7_nodeport_v6_03_ack_data")
int l7_nodeport_v6_03_ack_data_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, true, true, 0);
}

CHECK(PROG_TYPE, "l7_nodeport_v6_03_ack_data")
int l7_nodeport_v6_03_ack_data_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, true, CLIENT_PORT, INGRESS_PROXY_PORT, true);
}

PKTGEN(PROG_TYPE, "l7_nodeport_v6_04_legacy_syn")
int l7_nodeport_v6_04_legacy_syn_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, true, LEGACY_PORT, true);
}

SETUP(PROG_TYPE, "l7_nodeport_v6_04_legacy_syn")
int l7_nodeport_v6_04_legacy_syn_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, true, false, 0);
}

CHECK(PROG_TYPE, "l7_nodeport_v6_04_legacy_syn")
int l7_nodeport_v6_04_legacy_syn_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, true, LEGACY_PORT, 0, false);
}

PKTGEN(PROG_TYPE, "l7_nodeport_v6_05_legacy_ack")
int l7_nodeport_v6_05_legacy_ack_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, true, LEGACY_PORT, false);
}

SETUP(PROG_TYPE, "l7_nodeport_v6_05_legacy_ack")
int l7_nodeport_v6_05_legacy_ack_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, true, true, 0);
}

CHECK(PROG_TYPE, "l7_nodeport_v6_05_legacy_ack")
int l7_nodeport_v6_05_legacy_ack_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, true, LEGACY_PORT, 0, false);
}

PKTGEN(PROG_TYPE, "l7_nodeport_v6_06_legacy_proxy_syn")
int l7_nodeport_v6_06_legacy_proxy_syn_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, true, LEGACY_PROXY_PORT, true);
}

SETUP(PROG_TYPE, "l7_nodeport_v6_06_legacy_proxy_syn")
int l7_nodeport_v6_06_legacy_proxy_syn_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, true, false, POLICY_PROXY_PORT);
}

CHECK(PROG_TYPE, "l7_nodeport_v6_06_legacy_proxy_syn")
int l7_nodeport_v6_06_legacy_proxy_syn_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, true, LEGACY_PROXY_PORT, POLICY_PROXY_PORT, false);
}

PKTGEN(PROG_TYPE, "l7_nodeport_v6_07_legacy_proxy_ack")
int l7_nodeport_v6_07_legacy_proxy_ack_pktgen(struct __ctx_buff *ctx)
{
	return generate_packet(ctx, true, LEGACY_PROXY_PORT, false);
}

SETUP(PROG_TYPE, "l7_nodeport_v6_07_legacy_proxy_ack")
int l7_nodeport_v6_07_legacy_proxy_ack_setup(struct __ctx_buff *ctx)
{
	return setup_packet(ctx, true, true, POLICY_PROXY_PORT);
}

CHECK(PROG_TYPE, "l7_nodeport_v6_07_legacy_proxy_ack")
int l7_nodeport_v6_07_legacy_proxy_ack_check(const struct __ctx_buff *ctx)
{
	return check_packet(ctx, true, LEGACY_PROXY_PORT, POLICY_PROXY_PORT, false);
}
