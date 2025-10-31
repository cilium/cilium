// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

/* Enable CT debug output */
#undef QUIET_CT

#include "pktgen.h"

/* Enable code paths under test*/
#define ENABLE_IPV4 1
#define ENABLE_IPV6 1

/* Skip ingress policy checks */
#define USE_BPF_PROG_FOR_INGRESS_POLICY 1

#include "lib/bpf_lxc.h"

/* Set the LXC source address to be the address of pod one */
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one})
ASSIGN_CONFIG(union v4addr, service_loopback_ipv4, { .be32 = v4_svc_loopback })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })
ASSIGN_CONFIG(union v6addr, service_loopback_ipv6, { .addr = v6_svc_loopback })

#define POD_IPV6 v6_pod_one
#define SERVICE_IPV6 v6_node_three
ASSIGN_CONFIG(bool, enable_no_service_endpoints_routable, true)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"

/* Setup for this test:
 * +-------ClusterIP--------+    +----------Pod 1---------+
 * | v4_svc_one:tcp_svc_one | -> | v4_pod_one:tcp_svc_one |
 * +------------------------+    +------------------------+
 *            ^                            |
 *            \---------------------------/
 */

static __always_inline int build_packet(struct __ctx_buff *ctx,
					__be16 sport)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)src, (__u8 *)dst,
					  v4_pod_one, v4_svc_one,
					  sport, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

PKTGEN("tc", "hairpin_flow_1_forward_v4")
int hairpin_flow_forward_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, tcp_src_one);
}

/* Test that sending a packet from a pod to its own service gets source nat-ed
 * and that it is forwarded to the correct veth.
 */
SETUP("tc", "hairpin_flow_1_forward_v4")
int hairpin_flow_forward_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(v4_svc_one, tcp_svc_one, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(v4_svc_one, tcp_svc_one, 1, 124,
			  v4_pod_one, tcp_dst_one, IPPROTO_TCP, 0);

	/* Add an IPCache entry for pod 1 */
	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);

	endpoint_v4_add_entry(v4_pod_one, 0, 0, 0, 0, 0, NULL, NULL);

	/* Hairpin should over-rule any installed network policy: */
	policy_add_egress_deny_all_entry();
	policy_add_ingress_deny_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "hairpin_flow_1_forward_v4")
int hairpin_flow_forward_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != CONFIG(service_loopback_ipv4).be32)
		test_fatal("src IP was not SNAT'ed");

	if (l3->daddr != v4_pod_one)
		test_fatal("dest IP hasn't been changed to the pod IP");

	if (l3->check != bpf_htons(-0x4f02))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_src_one)
		test_fatal("src TCP port was changed");

	if (l4->dest != tcp_dst_one)
		test_fatal("dst TCP port incorrect");

	if (l4->check != bpf_htons(0xb846))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	struct ipv4_ct_tuple tuple = {};
	struct ct_entry *ct_entry;

	/* Match the packet headers: */
	tuple.flags = TUPLE_F_SERVICE;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.saddr = v4_pod_one;
	tuple.sport = tcp_src_one;
	tuple.daddr = v4_svc_one;
	tuple.dport = tcp_svc_one;

	/* Ports are stored in reverse order: */
	ipv4_ct_tuple_swap_ports(&tuple);

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT_SERVICE entry found");

	/* Match the packet headers: */
	tuple.flags = TUPLE_F_OUT;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.saddr = CONFIG(service_loopback_ipv4).be32;
	tuple.sport = tcp_src_one;
	tuple.daddr = v4_pod_one;
	tuple.dport = tcp_dst_one;

	/* Addrs are stored in reverse order: */
	ipv4_ct_tuple_swap_addrs(&tuple);

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT_EGRESS entry found");
	if (!ct_entry->lb_loopback)
		test_fatal("CT_EGRESS entry doesn't have loopback flag");

	test_finish();
}

/* Let backend's ingress path create its own CT entry: */
PKTGEN("tc", "hairpin_flow_2_forward_ingress_v4")
int hairpin_flow_forward_ingress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)src, (__u8 *)dst,
					  CONFIG(service_loopback_ipv4).be32, v4_pod_one,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

/* Test that a packet in the forward direction is good. */
SETUP("tc", "hairpin_flow_2_forward_ingress_v4")
int hairpin_flow_forward_ingress_setup(struct __ctx_buff *ctx)
{
	return pod_receive_packet(ctx);
}

CHECK("tc", "hairpin_flow_2_forward_ingress_v4")
int hairpin_flow_forward_ingress_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_OK);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != CONFIG(service_loopback_ipv4).be32)
		test_fatal("src IP changed");

	if (l3->daddr != v4_pod_one)
		test_fatal("dest IP changed");

	if (l3->check != bpf_htons(-0x5002))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_src_one)
		test_fatal("src TCP port changed");

	if (l4->dest != tcp_dst_one)
		test_fatal("dst TCP port changed");

	if (l4->check != bpf_htons(0xb846))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	struct ipv4_ct_tuple tuple = {};
	struct ct_entry *ct_entry;

	/* Match the packet headers: */
	tuple.flags = TUPLE_F_IN;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.saddr = CONFIG(service_loopback_ipv4).be32;
	tuple.sport = tcp_src_one;
	tuple.daddr = v4_pod_one;
	tuple.dport = tcp_dst_one;

	/* Addrs are stored in reverse order: */
	ipv4_ct_tuple_swap_addrs(&tuple);

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT_INGRESS entry found");
	if (!ct_entry->lb_loopback)
		test_fatal("CT_INGRESS entry doesn't have loopback flag");

	test_finish();
}

PKTGEN("tc", "hairpin_flow_3_reverse_v4")
int hairpin_flow_reverse_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)src, (__u8 *)dst,
					  v4_pod_one, CONFIG(service_loopback_ipv4).be32,
					  tcp_dst_one, tcp_src_one);
	if (!l4)
		return TEST_ERROR;

	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

/* Test that a packet in the reverse direction gets translated back. */
SETUP("tc", "hairpin_flow_3_reverse_v4")
int hairpin_flow_rev_setup(struct __ctx_buff *ctx)
{
	return pod_send_packet(ctx);
}

CHECK("tc", "hairpin_flow_3_reverse_v4")
int hairpin_flow_rev_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != v4_pod_one)
		test_fatal("src IP changed");

	if (l3->daddr != CONFIG(service_loopback_ipv4).be32)
		test_fatal("dest IP changed");

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_dst_one)
		test_fatal("src TCP port changed");

	if (l4->dest != tcp_src_one)
		test_fatal("dst TCP port changed");

	if (l4->check != bpf_htons(0xb836))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

PKTGEN("tc", "hairpin_flow_4_reverse_ingress_v4")
int hairpin_flow_reverse_ingress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)src, (__u8 *)dst,
					  v4_pod_one, CONFIG(service_loopback_ipv4).be32,
					  tcp_dst_one, tcp_src_one);
	if (!l4)
		return TEST_ERROR;

	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hairpin_flow_4_reverse_ingress_v4")
int hairpin_flow_reverse_ingress_setup(struct __ctx_buff *ctx)
{
	return pod_receive_packet(ctx);
}

CHECK("tc", "hairpin_flow_4_reverse_ingress_v4")
int hairpin_flow_reverse_ingress_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != v4_svc_one)
		test_fatal("src IP was not NAT'ed back to the svc IP");

	if (l3->daddr != v4_pod_one)
		test_fatal("dest IP hasn't been NAT'ed to the original source IP");

	if (l3->check != bpf_htons(0x402))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_svc_one)
		test_fatal("src TCP port was changed");

	if (l4->dest != tcp_src_one)
		test_fatal("dst TCP port incorrect");

	if (l4->check != bpf_htons(0x6325))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

/* Test that a packet for a SVC without any backend gets dropped. */
SETUP("tc", "tc_drop_no_backend")
int tc_drop_no_backend_setup(struct __ctx_buff *ctx)
{
	int ret;

	ret = build_packet(ctx, tcp_src_two);
	if (ret)
		return ret;

	lb_v4_add_service(v4_svc_one, tcp_svc_one, IPPROTO_TCP, 0, 1);

	/* avoid policy drop */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_drop_no_backend")
int tc_drop_no_backend_check(const struct __ctx_buff *ctx)
{
	__u32 expected_status = TC_ACT_SHOT;
	__u32 *status_code;
	void *data_end;
	void *data;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != expected_status)
		test_fatal("status code is %lu, expected %lu", *status_code, expected_status);

	test_finish();
}

static __always_inline int build_packet_v6(struct __ctx_buff *ctx, __be16 sport)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)src, (__u8 *)dst,
					  (__u8 *)POD_IPV6, (__u8 *)SERVICE_IPV6,
					  sport, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

PKTGEN("tc", "hairpin_flow_1_forward_v6")
int hairpin_flow_forward_pktgen_v6(struct __ctx_buff *ctx)
{
	return build_packet_v6(ctx, tcp_src_one);
}

SETUP("tc", "hairpin_flow_1_forward_v6")
int hairpin_flow_forward_setup_v6(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v6_add_service((const union v6addr *)SERVICE_IPV6, tcp_svc_one, IPPROTO_TCP,
			  1, revnat_id);
	lb_v6_add_backend((const union v6addr *)SERVICE_IPV6, tcp_svc_one, 1, 124,
			  (const union v6addr *)POD_IPV6, tcp_dst_one, IPPROTO_TCP, 0);

	ipcache_v6_add_entry((union v6addr *)POD_IPV6, 0, 112233, 0, 0);

	endpoint_v6_add_entry((const union v6addr *)POD_IPV6, 0, 0, 0, 0, NULL, NULL);

	policy_add_egress_deny_all_entry();
	policy_add_ingress_deny_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "hairpin_flow_1_forward_v6")
int hairpin_flow_forward_check_v6(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (memcmp(&l3->saddr, (const void *)&CONFIG(service_loopback_ipv6).addr,
		   sizeof(l3->saddr)) != 0)
		test_fatal("src IPv6 was not SNAT'ed");

	if (memcmp(&l3->daddr, (const void *)POD_IPV6, sizeof(l3->daddr)) != 0)
		test_fatal("dest IPv6 hasn't been changed to the pod IP");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_src_one)
		test_fatal("src TCP port was changed");

	if (l4->dest != tcp_dst_one)
		test_fatal("dst TCP port incorrect");

	if (l4->check != bpf_htons(0x88f8))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	struct ipv6_ct_tuple tuple = {};
	struct ct_entry *ct_entry;

	tuple.flags = TUPLE_F_SERVICE;
	tuple.nexthdr = IPPROTO_TCP;
	memcpy(&tuple.saddr, (const void *)POD_IPV6, sizeof(tuple.saddr));
	tuple.sport = tcp_src_one;
	memcpy(&tuple.daddr, (const void *)SERVICE_IPV6, sizeof(tuple.daddr));
	tuple.dport = tcp_svc_one;

	ipv6_ct_tuple_swap_ports(&tuple);

	ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT_SERVICE entry found");

	tuple.flags = TUPLE_F_OUT;
	tuple.nexthdr = IPPROTO_TCP;
	memcpy(&tuple.saddr, (const void *)&CONFIG(service_loopback_ipv6).addr,
	       sizeof(tuple.saddr));
	tuple.sport = tcp_src_one;
	memcpy(&tuple.daddr, (const void *)POD_IPV6, sizeof(tuple.daddr));
	tuple.dport = tcp_dst_one;

	ipv6_ct_tuple_swap_addrs(&tuple);

	ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT_EGRESS entry found");
	if (!ct_entry->lb_loopback)
		test_fatal("CT_EGRESS entry doesn't have loopback flag");

	test_finish();
}

PKTGEN("tc", "hairpin_flow_2_forward_ingress_v6")
int hairpin_flow_forward_ingress_pktgen_v6(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)src, (__u8 *)dst,
					  (__u8 *)&CONFIG(service_loopback_ipv6).addr,
					  (__u8 *)POD_IPV6, tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "hairpin_flow_2_forward_ingress_v6")
int hairpin_flow_forward_ingress_setup_v6(struct __ctx_buff *ctx)
{
	return pod_receive_packet(ctx);
}

CHECK("tc", "hairpin_flow_2_forward_ingress_v6")
int hairpin_flow_forward_ingress_check_v6(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (memcmp(&l3->saddr, (const void *)&CONFIG(service_loopback_ipv6).addr,
		   sizeof(l3->saddr)) != 0)
		test_fatal("src IPv6 changed");

	if (memcmp(&l3->daddr, (const void *)POD_IPV6, sizeof(l3->daddr)) != 0)
		test_fatal("dest IPv6 changed");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_src_one)
		test_fatal("src TCP port changed");

	if (l4->dest != tcp_dst_one)
		test_fatal("dst TCP port changed");

	if (l4->check != bpf_htons(0x88f8))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	struct ipv6_ct_tuple tuple = {};
	struct ct_entry *ct_entry;

	tuple.flags = TUPLE_F_IN;
	tuple.nexthdr = IPPROTO_TCP;
	memcpy(&tuple.saddr, (const void *)&CONFIG(service_loopback_ipv6).addr,
	       sizeof(tuple.saddr));
	tuple.sport = tcp_src_one;
	memcpy(&tuple.daddr, (const void *)POD_IPV6, sizeof(tuple.daddr));
	tuple.dport = tcp_dst_one;

	ipv6_ct_tuple_swap_addrs(&tuple);

	ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT_INGRESS entry found");
	if (!ct_entry->lb_loopback)
		test_fatal("CT_INGRESS entry doesn't have loopback flag");
	test_finish();
}

PKTGEN("tc", "hairpin_flow_3_reverse_v6")
int hairpin_flow_reverse_pktgen_v6(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)src, (__u8 *)dst,
					  (__u8 *)POD_IPV6,
					  (__u8 *)&CONFIG(service_loopback_ipv6).addr,
					  tcp_dst_one, tcp_src_one);
	if (!l4)
		return TEST_ERROR;

	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "hairpin_flow_3_reverse_v6")
int hairpin_flow_rev_setup_v6(struct __ctx_buff *ctx)
{
	return pod_send_packet(ctx);
}

CHECK("tc", "hairpin_flow_3_reverse_v6")
int hairpin_flow_rev_check_v6(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (memcmp(&l3->saddr, (const void *)POD_IPV6, sizeof(l3->saddr)) != 0)
		test_fatal("src IPv6 changed");

	if (memcmp(&l3->daddr, (const void *)&CONFIG(service_loopback_ipv6).addr,
		   sizeof(l3->daddr)) != 0)
		test_fatal("dest IPv6 changed");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_dst_one)
		test_fatal("src TCP port changed");

	if (l4->dest != tcp_src_one)
		test_fatal("dst TCP port changed");

	if (l4->check != bpf_htons(0x88e8))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

PKTGEN("tc", "hairpin_flow_4_reverse_ingress_v6")
int hairpin_flow_reverse_ingress_pktgen_v6(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)src, (__u8 *)dst,
					  (__u8 *)POD_IPV6,
					  (__u8 *)&CONFIG(service_loopback_ipv6).addr,
					  tcp_dst_one, tcp_src_one);
	if (!l4)
		return TEST_ERROR;

	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "hairpin_flow_4_reverse_ingress_v6")
int hairpin_flow_reverse_ingress_setup_v6(struct __ctx_buff *ctx)
{
	return pod_receive_packet(ctx);
}

CHECK("tc", "hairpin_flow_4_reverse_ingress_v6")
int hairpin_flow_reverse_ingress_check_v6(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (memcmp(&l3->saddr, (const void *)SERVICE_IPV6, sizeof(l3->saddr)) != 0)
		test_fatal("src IPv6 was not NAT'ed back to the svc IP");

	if (memcmp(&l3->daddr, (const void *)POD_IPV6, sizeof(l3->daddr)) != 0)
		test_fatal("dest IPv6 hasn't been NAT'ed to the original source IP");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_svc_one)
		test_fatal("src TCP port was changed");

	if (l4->dest != tcp_src_one)
		test_fatal("dst TCP port incorrect");

	if (l4->check != bpf_htons(0xdfd1))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

SETUP("tc", "tc_drop_no_backend_v6")
int tc_drop_no_backend_setup_v6(struct __ctx_buff *ctx)
{
	int ret;

	ret = build_packet_v6(ctx, tcp_src_two);
	if (ret)
		return ret;

	lb_v6_add_service((const union v6addr *)SERVICE_IPV6, tcp_svc_one, IPPROTO_TCP, 0, 1);

	/* avoid policy drop */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_drop_no_backend_v6")
int tc_drop_no_backend_check_v6(const struct __ctx_buff *ctx)
{
	__u32 expected_status = TC_ACT_SHOT;
	__u32 *status_code;
	void *data_end;
	void *data;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != expected_status)
		test_fatal("status code is %lu, expected %lu", *status_code, expected_status);

	test_finish();
}
