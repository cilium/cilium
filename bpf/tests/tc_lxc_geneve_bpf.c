// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define TUNNEL_MODE		1
#define HAVE_ENCAP		1
#define ENABLE_BPF_GENEVE	1
#define TUNNEL_PROTOCOL		TUNNEL_PROTOCOL_GENEVE
#define TUNNEL_PORT		6081
#define ENCAP_IFINDEX		42
#define ENABLE_NODEPORT		1
#define ENABLE_DSR		1
#define ENABLE_ROUTING		1
#define ENABLE_HOST_ROUTING	1

static __u32 recorded_redirect_ifindex;
static __u32 recorded_redirect_flags;

static __always_inline int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused, int ifindex, __u32 flags)
{
	recorded_redirect_ifindex = (__u32)ifindex;
	recorded_redirect_flags = flags;
	return CTX_ACT_REDIRECT;
}

#undef ctx_redirect
#define ctx_redirect(ctx, ifindex, flags) mock_ctx_redirect(ctx, ifindex, flags)

#include "lib/static_data.h"
static volatile __u8 test_geneve_inner_proto = 0;

#undef CONFIG
#define __REAL_CONFIG(name)	\
(*({				\
	void *out;		\
	asm volatile("%0 = " __stringify(__config_##name) " ll"	\
			: "=r"(out));	\
	(typeof(__config_##name) *)out;	\
}))
#define CONFIG(name) \
	__builtin_choose_expr(__builtin_strcmp(#name, "geneve_inner_protocol") == 0, \
			      test_geneve_inner_proto, \
			      __REAL_CONFIG(name))

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })
ASSIGN_CONFIG(union macaddr, interface_mac, { .addr = mac_one_addr })
ASSIGN_CONFIG(__u32, cilium_net_ifindex, 10)
ASSIGN_CONFIG(__u16, device_mtu, 200)
ASSIGN_CONFIG(bool, enable_bpf_host_routing, true)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"
#include "nodeport_defaults.h"

#define BACKEND_PORT		__bpf_htons(8080)
#define REMOTE_CLIENT_PORT	__bpf_htons(5001)
#define LOCAL_CLIENT_PORT	__bpf_htons(5002)
#define BACKEND_IFACE		25
#define BACKEND_EP_ID		127

/* Test 1: DSR reply from backend pod (v4_pod_one:8080) to remote client
 * (v4_node_two:5001) encapsulated over BPF Geneve.
 * Verifies that tail_geneve_encap4 invokes bpf_geneve_rev_dnat_fwd ->
 * nodeport_rev_dnat_fwd_ipv4(revdnat_only=true) before encapsulating the
 * packet into Geneve, rewriting inner_ip4->saddr to v4_svc_one and
 * inner_tcp->source to tcp_svc_one.
 */
PKTGEN("tc", "tc_lxc_geneve_bpf_dsr_reply_to_remote_node_v4")
int tc_lxc_geneve_bpf_dsr_reply_to_remote_node_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_node_two,
					  BACKEND_PORT, REMOTE_CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_lxc_geneve_bpf_dsr_reply_to_remote_node_v4")
int tc_lxc_geneve_bpf_dsr_reply_to_remote_node_v4_setup(struct __ctx_buff *ctx)
{
	struct geneve_route_entry cached_rt = {
		.dmac = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
		.smac = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },
		.ifindex = ENCAP_IFINDEX,
		.saddr = v4_node_one,
	};
	__be32 dst_key = v4_node_two;
	struct ipv4_ct_tuple tuple_in = {
		.daddr = v4_node_two,
		.saddr = v4_pod_one,
		.dport = BACKEND_PORT,
		.sport = REMOTE_CLIENT_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_IN,
	};
	struct ct_entry entry_in = {
		.src_sec_id = REMOTE_NODE_ID,
		.from_tunnel = 1,
	};
	struct ipv4_ct_tuple tuple_out = {
		.daddr = v4_node_two,
		.saddr = v4_pod_one,
		.dport = BACKEND_PORT,
		.sport = REMOTE_CLIENT_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry entry_out = {
		.dsr_internal = 1,
		.nat_addr.p4 = v4_svc_one,
		.nat_port = tcp_svc_one,
		.src_sec_id = REMOTE_NODE_ID,
		.from_tunnel = 1,
	};

	recorded_redirect_ifindex = 0;
	recorded_redirect_flags = 0;

	endpoint_v4_add_entry(v4_pod_one, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)mac_one, (__u8 *)mac_two);
	ipcache_v4_add_entry(v4_node_two, 0, REMOTE_NODE_ID, v4_node_two, 0);
	map_update_elem(&cilium_geneve_routes, &dst_key, &cached_rt, BPF_ANY);

	map_update_elem(&cilium_ct4_global, &tuple_in, &entry_in, BPF_ANY);
	map_update_elem(&cilium_ct4_global, &tuple_out, &entry_out, BPF_ANY);

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_geneve_bpf_dsr_reply_to_remote_node_v4")
int tc_lxc_geneve_bpf_dsr_reply_to_remote_node_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *outer_eth;
	struct iphdr *outer_ip4, *inner_ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	struct tcphdr *inner_tcp;
	void *inner_l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(recorded_redirect_ifindex == ENCAP_IFINDEX);

	outer_eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(outer_eth + 1) > data_end)
		test_fatal("outer eth out of bounds");
	assert(outer_eth->h_proto == bpf_htons(ETH_P_IP));

	outer_ip4 = (void *)(outer_eth + 1);
	if ((void *)(outer_ip4 + 1) > data_end)
		test_fatal("outer ip4 out of bounds");
	assert(outer_ip4->protocol == IPPROTO_UDP);
	assert(outer_ip4->daddr == v4_node_two);

	udp = (void *)(outer_ip4 + 1);
	if ((void *)(udp + 1) > data_end)
		test_fatal("outer udp out of bounds");
	assert(udp->dest == bpf_htons(6081));

	geneve = (void *)(udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("geneve hdr out of bounds");

	inner_l3 = (void *)(geneve + 1) + (geneve->opt_len * 4);
	if (geneve->protocol_type == bpf_htons(ETH_P_TEB))
		inner_l3 += sizeof(struct ethhdr);

	inner_ip4 = inner_l3;
	if ((void *)(inner_ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(inner_ip4->saddr == v4_svc_one);
	assert(inner_ip4->daddr == v4_node_two);

	inner_tcp = (void *)inner_ip4 + ipv4_hdrlen(inner_ip4);
	if ((void *)(inner_tcp + 1) > data_end)
		test_fatal("inner tcp out of bounds");
	assert(inner_tcp->source == tcp_svc_one);
	assert(inner_tcp->dest == REMOTE_CLIENT_PORT);

	test_finish();
}

/* Test 2: DSR reply from backend pod (v4_pod_one:8080) to local host
 * (v4_node_one:5002).
 * Verifies that ipv4_forward_to_destination invokes
 * nodeport_rev_dnat_fwd_ipv4(revdnat_only=true) for ENDPOINT_F_HOST
 * CT_REPLY delivery and redirects to cilium_net_ifindex with ip4->saddr
 * rewritten to v4_svc_one and tcp->source rewritten to tcp_svc_one.
 */
PKTGEN("tc", "tc_lxc_geneve_bpf_dsr_reply_to_local_node_v4")
int tc_lxc_geneve_bpf_dsr_reply_to_local_node_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_node_one,
					  BACKEND_PORT, LOCAL_CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_lxc_geneve_bpf_dsr_reply_to_local_node_v4")
int tc_lxc_geneve_bpf_dsr_reply_to_local_node_v4_setup(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple_in = {
		.daddr = v4_node_one,
		.saddr = v4_pod_one,
		.dport = BACKEND_PORT,
		.sport = LOCAL_CLIENT_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_IN,
	};
	struct ct_entry entry_in = {
		.src_sec_id = HOST_ID,
	};
	struct ipv4_ct_tuple tuple_out = {
		.daddr = v4_node_one,
		.saddr = v4_pod_one,
		.dport = BACKEND_PORT,
		.sport = LOCAL_CLIENT_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry entry_out = {
		.dsr_internal = 1,
		.nat_addr.p4 = v4_svc_one,
		.nat_port = tcp_svc_one,
		.src_sec_id = HOST_ID,
	};

	recorded_redirect_ifindex = 0;
	recorded_redirect_flags = 0;

	endpoint_v4_add_entry(v4_pod_one, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)mac_one, (__u8 *)mac_two);
	endpoint_v4_add_entry(v4_node_one, 0, 0, ENDPOINT_F_HOST, HOST_ID, 0,
			      NULL, NULL);
	ipcache_v4_add_entry(v4_node_one, 0, HOST_ID, 0, 0);

	map_update_elem(&cilium_ct4_global, &tuple_in, &entry_in, BPF_ANY);
	map_update_elem(&cilium_ct4_global, &tuple_out, &entry_out, BPF_ANY);

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_geneve_bpf_dsr_reply_to_local_node_v4")
int tc_lxc_geneve_bpf_dsr_reply_to_local_node_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *eth;
	struct iphdr *ip4;
	struct tcphdr *tcp;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(recorded_redirect_ifindex == CONFIG(cilium_net_ifindex));

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end)
		test_fatal("eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));

	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("ip4 out of bounds");
	assert(ip4->saddr == v4_svc_one);
	assert(ip4->daddr == v4_node_one);

	tcp = (void *)ip4 + ipv4_hdrlen(ip4);
	if ((void *)(tcp + 1) > data_end)
		test_fatal("tcp out of bounds");
	assert(tcp->source == tcp_svc_one);
	assert(tcp->dest == LOCAL_CLIENT_PORT);

	test_finish();
}

/* Test 3: IPv6 DSR reply from backend pod (v6_pod_one:8080) to remote client
 * (v6_pod_two:5001) encapsulated over IPv6 BPF Geneve (tail_geneve_encap6).
 * Verifies that tail_geneve_encap6 invokes bpf_geneve_rev_dnat_fwd ->
 * nodeport_rev_dnat_fwd_ipv6(revdnat_only=true) before encapsulating the
 * packet into IPv6 Geneve, rewriting inner_ip6->saddr to v6_svc_one and
 * inner_tcp->source to tcp_svc_one.
 */
PKTGEN("tc", "tc_lxc_geneve_bpf_dsr_reply_to_remote_node_v6")
int tc_lxc_geneve_bpf_dsr_reply_to_remote_node_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)v6_pod_one, (__u8 *)v6_pod_two,
					  BACKEND_PORT, REMOTE_CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_lxc_geneve_bpf_dsr_reply_to_remote_node_v6")
int tc_lxc_geneve_bpf_dsr_reply_to_remote_node_v6_setup(struct __ctx_buff *ctx)
{
	struct ipv6_ct_tuple tuple_in __align_stack_8 = {
		.nexthdr = IPPROTO_TCP,
		.dport = BACKEND_PORT,
		.sport = REMOTE_CLIENT_PORT,
		.flags = TUPLE_F_IN,
	};
	struct ct_entry entry_in = {
		.src_sec_id = REMOTE_NODE_ID,
		.from_tunnel = 1,
	};
	struct ipv6_ct_tuple tuple_out __align_stack_8 = {
		.nexthdr = IPPROTO_TCP,
		.dport = BACKEND_PORT,
		.sport = REMOTE_CLIENT_PORT,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry entry_out = {
		.dsr_internal = 1,
		.nat_port = tcp_svc_one,
		.src_sec_id = REMOTE_NODE_ID,
	};

	ipv6_addr_copy(&tuple_in.daddr, (const union v6addr *)v6_pod_two);
	ipv6_addr_copy(&tuple_in.saddr, (const union v6addr *)v6_pod_one);
	ipv6_addr_copy(&tuple_out.daddr, (const union v6addr *)v6_pod_two);
	ipv6_addr_copy(&tuple_out.saddr, (const union v6addr *)v6_pod_one);
	ipv6_addr_copy(&entry_out.nat_addr, (const union v6addr *)v6_svc_one);

	recorded_redirect_ifindex = 0;
	recorded_redirect_flags = 0;

	endpoint_v6_add_entry((const union v6addr *)v6_pod_one, BACKEND_IFACE,
			      BACKEND_EP_ID, 0, 0,
			      (__u8 *)mac_one, (__u8 *)mac_two);
	ipcache_v6_add_entry_ipv6_underlay((const union v6addr *)v6_pod_two, 0,
					   REMOTE_NODE_ID,
					   (const union v6addr *)v6_node_two, 0);

	map_update_elem(&cilium_ct6_global, &tuple_in, &entry_in, BPF_ANY);
	map_update_elem(&cilium_ct6_global, &tuple_out, &entry_out, BPF_ANY);

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_geneve_bpf_dsr_reply_to_remote_node_v6")
int tc_lxc_geneve_bpf_dsr_reply_to_remote_node_v6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *outer_eth, *inner_eth;
	struct ipv6hdr *outer_ip6, *inner_ip6;
	struct udphdr *udp;
	struct genevehdr *geneve;
	struct tcphdr *inner_tcp;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	outer_eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(outer_eth + 1) > data_end)
		test_fatal("outer_eth out of bounds");
	assert(outer_eth->h_proto == bpf_htons(ETH_P_IPV6));

	outer_ip6 = (void *)(outer_eth + 1);
	if ((void *)(outer_ip6 + 1) > data_end)
		test_fatal("outer_ip6 out of bounds");
	assert(ipv6_addr_equals((union v6addr *)&outer_ip6->daddr,
				(const union v6addr *)v6_node_two));
	assert(outer_ip6->nexthdr == IPPROTO_UDP);

	udp = (void *)(outer_ip6 + 1);
	if ((void *)(udp + 1) > data_end)
		test_fatal("udp out of bounds");
	assert(udp->dest == bpf_htons(TUNNEL_PORT));

	geneve = (void *)(udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("geneve out of bounds");
	assert(geneve->protocol_type == bpf_htons(ETH_P_TEB));

	inner_eth = (void *)(geneve + 1) + ((__u32)geneve->opt_len << 2);
	if ((void *)(inner_eth + 1) > data_end)
		test_fatal("inner_eth out of bounds");
	assert(inner_eth->h_proto == bpf_htons(ETH_P_IPV6));

	inner_ip6 = (void *)(inner_eth + 1);
	if ((void *)(inner_ip6 + 1) > data_end)
		test_fatal("inner_ip6 out of bounds");
	assert(ipv6_addr_equals((union v6addr *)&inner_ip6->saddr,
				(const union v6addr *)v6_svc_one));
	assert(ipv6_addr_equals((union v6addr *)&inner_ip6->daddr,
				(const union v6addr *)v6_pod_two));

	inner_tcp = (void *)(inner_ip6 + 1);
	if ((void *)(inner_tcp + 1) > data_end)
		test_fatal("inner_tcp out of bounds");
	assert(inner_tcp->source == tcp_svc_one);
	assert(inner_tcp->dest == REMOTE_CLIENT_PORT);

	test_finish();
}

/* Test 4: IPv6 DSR reply from backend pod (v6_pod_one:8080) to local host client
 * (v6_node_one:5002) via ENDPOINT_MASK_HOST_DELIVERY in ipv6_forward_to_destination.
 * Verifies that bpf_lxc.c invokes nodeport_rev_dnat_fwd_ipv6(revdnat_only=true)
 * and redirects to cilium_net with inner_ip6->saddr == v6_svc_one and
 * tcp->source == tcp_svc_one.
 */
PKTGEN("tc", "tc_lxc_geneve_bpf_dsr_reply_to_local_node_v6")
int tc_lxc_geneve_bpf_dsr_reply_to_local_node_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)v6_pod_one, (__u8 *)v6_node_one,
					  BACKEND_PORT, LOCAL_CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_lxc_geneve_bpf_dsr_reply_to_local_node_v6")
int tc_lxc_geneve_bpf_dsr_reply_to_local_node_v6_setup(struct __ctx_buff *ctx)
{
	struct ipv6_ct_tuple tuple_in __align_stack_8 = {
		.nexthdr = IPPROTO_TCP,
		.dport = BACKEND_PORT,
		.sport = LOCAL_CLIENT_PORT,
		.flags = TUPLE_F_IN,
	};
	struct ct_entry entry_in = {
		.src_sec_id = HOST_ID,
	};
	struct ipv6_ct_tuple tuple_out __align_stack_8 = {
		.nexthdr = IPPROTO_TCP,
		.dport = BACKEND_PORT,
		.sport = LOCAL_CLIENT_PORT,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry entry_out = {
		.dsr_internal = 1,
		.nat_port = tcp_svc_one,
		.src_sec_id = HOST_ID,
	};

	ipv6_addr_copy(&tuple_in.daddr, (const union v6addr *)v6_node_one);
	ipv6_addr_copy(&tuple_in.saddr, (const union v6addr *)v6_pod_one);
	ipv6_addr_copy(&tuple_out.daddr, (const union v6addr *)v6_node_one);
	ipv6_addr_copy(&tuple_out.saddr, (const union v6addr *)v6_pod_one);
	ipv6_addr_copy(&entry_out.nat_addr, (const union v6addr *)v6_svc_one);

	recorded_redirect_ifindex = 0;
	recorded_redirect_flags = 0;

	endpoint_v6_add_entry((const union v6addr *)v6_pod_one, BACKEND_IFACE,
			      BACKEND_EP_ID, 0, 0,
			      (__u8 *)mac_one, (__u8 *)mac_two);
	endpoint_v6_add_entry((const union v6addr *)v6_node_one, 0, 0,
			      ENDPOINT_F_HOST, HOST_ID,
			      NULL, NULL);
	ipcache_v6_add_entry((const union v6addr *)v6_node_one, 0, HOST_ID, 0, 0);

	map_update_elem(&cilium_ct6_global, &tuple_in, &entry_in, BPF_ANY);
	map_update_elem(&cilium_ct6_global, &tuple_out, &entry_out, BPF_ANY);

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_geneve_bpf_dsr_reply_to_local_node_v6")
int tc_lxc_geneve_bpf_dsr_reply_to_local_node_v6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	struct tcphdr *tcp;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(recorded_redirect_ifindex == CONFIG(cilium_net_ifindex));

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end)
		test_fatal("eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));

	ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		test_fatal("ip6 out of bounds");
	assert(ipv6_addr_equals((union v6addr *)&ip6->saddr,
				(const union v6addr *)v6_svc_one));
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr,
				(const union v6addr *)v6_node_one));

	tcp = (void *)(ip6 + 1);
	if ((void *)(tcp + 1) > data_end)
		test_fatal("tcp out of bounds");
	assert(tcp->source == tcp_svc_one);
	assert(tcp->dest == LOCAL_CLIENT_PORT);

	test_finish();
}

static __u8 oversize_payload[128] = {
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
};

/* Test 5: Oversize IPv4 packet from local pod (v4_pod_one) to remote pod (v4_pod_two)
 * on remote node (v4_node_two) exceeding device_mtu (200B) after Geneve encap (50B).
 * Inner IPv4 tot_len = 20 + 20 + 128 = 168B -> post-encap outer_l3_len = 218B > 200B.
 * Verifies that tail_geneve_encap4 generates an RFC 1191 ICMPv4 Fragmentation Needed
 * (Type 3, Code 4) reply back to the sender with Next-Hop MTU = 200 - 50 = 150B.
 */
PKTGEN("tc", "tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4")
int tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  BACKEND_PORT, REMOTE_CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;

	data = pktgen__push_data(&builder, oversize_payload, sizeof(oversize_payload));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4")
int tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4_setup(struct __ctx_buff *ctx)
{
	recorded_redirect_ifindex = 0;
	recorded_redirect_flags = 0;

	policy_add_egress_allow_all_entry();
	endpoint_v4_add_entry(v4_pod_one, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
			      0, (__u8 *)mac_one, (__u8 *)mac_two);
	ipcache_v4_add_entry(v4_pod_two, 0, REMOTE_NODE_ID, v4_node_two, 0);

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4")
int tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *eth;
	struct iphdr *ip4, *orig_ip4;
	struct icmphdr *icmp4;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end)
		test_fatal("eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));

	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("ip4 out of bounds");
	assert(ip4->protocol == IPPROTO_ICMP);
	assert(ip4->saddr == v4_pod_two);
	assert(ip4->daddr == v4_pod_one);

	icmp4 = (void *)(ip4 + 1);
	if ((void *)(icmp4 + 1) > data_end)
		test_fatal("icmp4 out of bounds");
	assert(icmp4->type == ICMP_DEST_UNREACH);
	assert(icmp4->code == ICMP_FRAG_NEEDED);
	/* Next-Hop MTU = device_mtu (200) - Geneve v4 TEB overhead (50) = 150 */
	assert(icmp4->un.frag.mtu == bpf_htons(150));

	orig_ip4 = (void *)(icmp4 + 1);
	if ((void *)(orig_ip4 + 1) > data_end)
		test_fatal("orig_ip4 out of bounds");
	assert(orig_ip4->saddr == v4_pod_one);
	assert(orig_ip4->daddr == v4_pod_two);

	test_finish();
}

/* Test 6: Oversize IPv6 packet from local pod (v6_pod_one) to remote pod (v6_pod_two)
 * on remote node (v6_node_two) exceeding device_mtu (200B) after Geneve v6 encap (70B).
 * Inner IPv6 l3_len = 40 + 20 + 128 = 188B -> post-encap outer_l3_len = 258B > 200B.
 * Verifies that tail_geneve_encap6 generates an RFC 8201 ICMPv6 Packet Too Big
 * (Type 2, Code 0) reply back to the sender with Next-Hop MTU = 200 - 70 = 130B.
 */
PKTGEN("tc", "tc_lxc_geneve_bpf_oversize_icmp6_pkt_toobig_v6")
int tc_lxc_geneve_bpf_oversize_icmp6_pkt_toobig_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)v6_pod_one, (__u8 *)v6_pod_two,
					  BACKEND_PORT, REMOTE_CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;

	data = pktgen__push_data(&builder, oversize_payload, sizeof(oversize_payload));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_lxc_geneve_bpf_oversize_icmp6_pkt_toobig_v6")
int tc_lxc_geneve_bpf_oversize_icmp6_pkt_toobig_v6_setup(struct __ctx_buff *ctx)
{
	recorded_redirect_ifindex = 0;
	recorded_redirect_flags = 0;

	endpoint_v6_add_entry((const union v6addr *)v6_pod_one, BACKEND_IFACE,
			      BACKEND_EP_ID, 0, 0,
			      (__u8 *)mac_one, (__u8 *)mac_two);
	ipcache_v6_add_entry_ipv6_underlay((const union v6addr *)v6_pod_two, 0,
					   REMOTE_NODE_ID,
					   (const union v6addr *)v6_node_two, 0);

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_geneve_bpf_oversize_icmp6_pkt_toobig_v6")
int tc_lxc_geneve_bpf_oversize_icmp6_pkt_toobig_v6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *eth;
	struct ipv6hdr *ip6, *orig_ip6;
	struct icmp6hdr *icmp6;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end)
		test_fatal("eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));

	ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		test_fatal("ip6 out of bounds");
	assert(ip6->nexthdr == IPPROTO_ICMPV6);
	assert(ipv6_addr_equals((union v6addr *)&ip6->saddr,
				(const union v6addr *)v6_pod_two));
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr,
				(const union v6addr *)v6_pod_one));

	icmp6 = (void *)(ip6 + 1);
	if ((void *)(icmp6 + 1) > data_end)
		test_fatal("icmp6 out of bounds");
	assert(icmp6->icmp6_type == ICMPV6_PKT_TOOBIG);
	assert(icmp6->icmp6_code == 0);
	/* Next-Hop MTU = device_mtu (200) - Geneve v6 TEB overhead (70) = 130 */
	assert(icmp6->icmp6_mtu == bpf_htonl(130));

	orig_ip6 = (void *)(icmp6 + 1);
	if ((void *)(orig_ip6 + 1) > data_end)
		test_fatal("orig_ip6 out of bounds");
	assert(ipv6_addr_equals((union v6addr *)&orig_ip6->saddr,
				(const union v6addr *)v6_pod_one));
	assert(ipv6_addr_equals((union v6addr *)&orig_ip6->daddr,
				(const union v6addr *)v6_pod_two));

	test_finish();
}

/* Test 7: Oversize IPv4 packet in L3 Inner Protocol Mode (GENEVE_INNER_PROTO_IP)
 * Verifies that when geneve_inner_protocol == GENEVE_INNER_PROTO_IP (1), the
 * 14-byte inner Ethernet header is omitted from encap_overhead (36B instead of 50B),
 * yielding an RFC 1191 ICMPv4 Fragmentation Needed Next-Hop MTU of 200 - 36 = 164B
 * (+14B higher than ETH_P_TEB mode).
 */
PKTGEN("tc", "tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4_l3_mode")
int tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4_l3_mode_pktgen(struct __ctx_buff *ctx)
{
	return tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4_pktgen(ctx);
}

SETUP("tc", "tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4_l3_mode")
int tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4_l3_mode_setup(struct __ctx_buff *ctx)
{
	int ret;

	/* Temporarily enable L3 inner protocol mode (GENEVE_INNER_PROTO_IP = 1) */
	test_geneve_inner_proto = GENEVE_INNER_PROTO_IP;
	ret = tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4_setup(ctx);
	test_geneve_inner_proto = GENEVE_INNER_PROTO_ETH;
	return ret;
}

CHECK("tc", "tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4_l3_mode")
int tc_lxc_geneve_bpf_oversize_icmp_frag_needed_v4_l3_mode_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *eth;
	struct iphdr *ip4;
	struct icmphdr *icmp4;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end)
		test_fatal("eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));

	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("ip4 out of bounds");
	assert(ip4->protocol == IPPROTO_ICMP);

	icmp4 = (void *)(ip4 + 1);
	if ((void *)(icmp4 + 1) > data_end)
		test_fatal("icmp4 out of bounds");
	assert(icmp4->type == ICMP_DEST_UNREACH);
	assert(icmp4->code == ICMP_FRAG_NEEDED);
	/* Next-Hop MTU = device_mtu (200) - Geneve v4 L3 IP overhead (36) = 164 (+14B vs TEB) */
	assert(icmp4->un.frag.mtu == bpf_htons(164));

	test_finish();
}

/* Test 8: TC NodePort Tunnel Encapsulation via nodeport_add_tunnel_encap_opt()
 * (__encap_with_nodeid) in L3 Inner Protocol Mode (GENEVE_INNER_PROTO_IP).
 * Verifies that __encap_with_nodeid() dispatches directly to tail_geneve_encap4
 * (rather than falling back to cilium_geneve) and preserves DSR TLV options
 * with Zero-Inner-L2 (protocol_type == ETH_P_IP).
 */
PKTGEN("tc", "tc_nodeport_add_tunnel_encap_opt_geneve_l3_v4")
int tc_nodeport_add_tunnel_encap_opt_geneve_l3_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_ext_one, v4_pod_one,
					  REMOTE_CLIENT_PORT, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;
	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "tc_nodeport_add_tunnel_encap_opt_geneve_l3_v4")
int tc_nodeport_add_tunnel_encap_opt_geneve_l3_v4_setup(struct __ctx_buff *ctx)
{
	struct geneve_route_entry cached_rt = {
		.dmac = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
		.smac = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },
		.ifindex = ENCAP_IFINDEX,
		.saddr = v4_node_one,
	};
	struct remote_endpoint_info ep_info = {
		.tunnel_endpoint.ip4.be32 = v4_node_two,
		.sec_identity = REMOTE_NODE_ID,
		.flag_has_tunnel_ep = true,
	};
	struct geneve_dsr_opt4 gopt = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = DSR_IPV4_GENEVE_OPT_LEN,
		},
		.addr = v4_svc_one,
		.port = tcp_svc_one,
	};
	__be32 dst_key = v4_node_two;
	int ifindex = 0;
	int ret;

	recorded_redirect_ifindex = 0;
	recorded_redirect_flags = 0;
	map_update_elem(&cilium_geneve_routes, &dst_key, &cached_rt, BPF_ANY);

	test_geneve_inner_proto = GENEVE_INNER_PROTO_IP;
	ret = nodeport_add_tunnel_encap_opt(ctx, v4_node_one, 0, &ep_info,
					    WORLD_IPV4_ID, &gopt, sizeof(gopt),
					    (enum trace_reason)CT_NEW,
					    TRACE_PAYLOAD_LEN, &ifindex,
					    bpf_htons(ETH_P_IP));
	test_geneve_inner_proto = GENEVE_INNER_PROTO_ETH;
	return ret;
}

CHECK("tc", "tc_nodeport_add_tunnel_encap_opt_geneve_l3_v4")
int tc_nodeport_add_tunnel_encap_opt_geneve_l3_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *outer_eth;
	struct iphdr *outer_ip4, *inner_ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	struct geneve_dsr_opt4 *dsr_opt;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(recorded_redirect_ifindex == ENCAP_IFINDEX);

	outer_eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(outer_eth + 1) > data_end)
		test_fatal("outer eth out of bounds");
	assert(outer_eth->h_proto == bpf_htons(ETH_P_IP));

	outer_ip4 = (void *)(outer_eth + 1);
	if ((void *)(outer_ip4 + 1) > data_end)
		test_fatal("outer ip4 out of bounds");
	assert(outer_ip4->protocol == IPPROTO_UDP);
	assert(outer_ip4->daddr == v4_node_two);

	udp = (void *)(outer_ip4 + 1);
	if ((void *)(udp + 1) > data_end)
		test_fatal("outer udp out of bounds");
	assert(udp->dest == bpf_htons(6081));

	geneve = (void *)(udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("geneve hdr out of bounds");
	assert(geneve->protocol_type == bpf_htons(ETH_P_IP));
	assert(geneve->opt_len == 3);

	dsr_opt = (void *)(geneve + 1);
	if ((void *)(dsr_opt + 1) > data_end)
		test_fatal("dsr opt out of bounds");
	assert(dsr_opt->hdr.opt_class == bpf_htons(DSR_GENEVE_OPT_CLASS));
	assert(dsr_opt->hdr.type == DSR_GENEVE_OPT_TYPE);
	assert(dsr_opt->addr == v4_svc_one);
	assert(dsr_opt->port == tcp_svc_one);

	inner_ip4 = (void *)(dsr_opt + 1);
	if ((void *)(inner_ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(inner_ip4->saddr == v4_ext_one);
	assert(inner_ip4->daddr == v4_pod_one);

	test_finish();
}

