// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

/* Set the LXC source address to be the address of pod one */
#define LXC_IPV4 (__be32)v4_pod_one
#include "config_replacement.h"

/* Enable CT debug output */
#undef QUIET_CT

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test*/
#define ENABLE_IPV4

/* Skip ingress policy checks, not needed to validate hairpin flow */
#define USE_BPF_PROG_FOR_INGRESS_POLICY
#undef FORCE_LOCAL_POLICY_EVAL_AT_SOURCE

#define ctx_redirect_peer mock_ctx_redirect_peer
static __always_inline __maybe_unused int
mock_ctx_redirect_peer(const struct __sk_buff *ctx __maybe_unused, int ifindex __maybe_unused,
		       __u32 flags __maybe_unused)
{
	return TC_ACT_REDIRECT;
}

#include <bpf_lxc.c>

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[0] = &cil_from_container,
	},
};

/* Setup for this test:
 * +-------ClusterIP--------+    +----------Pod 1---------+
 * | v4_svc_one:tcp_svc_one | -> | v4_pod_one:tcp_svc_one |
 * +------------------------+    +------------------------+
 *            ^                            |
 *            \---------------------------/
 */

static __always_inline int build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)src, (__u8 *)dst);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;
	l3->saddr = v4_pod_one;
	l3->daddr = v4_svc_one;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;
	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

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
	return build_packet(ctx);
}

/* Test that sending a packet from a pod to its own service gets source nat-ed
 * and that it is forwarded to the correct veth.
 */
SETUP("tc", "hairpin_flow_1_forward_v4")
int hairpin_flow_forward_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(v4_svc_one, tcp_svc_one, 1, revnat_id);
	lb_v4_add_backend(v4_svc_one, tcp_svc_one, 1, 124,
			  v4_pod_one, tcp_svc_one, IPPROTO_TCP, 0);

	/* Add an IPCache entry for pod 1 */
	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);

	endpoint_v4_add_entry(v4_pod_one, 0, 0, 0, NULL, NULL);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
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

	if (l3->saddr != IPV4_LOOPBACK)
		test_fatal("src IP was not SNAT'ed");

	if (l3->daddr != v4_pod_one)
		test_fatal("dest IP hasn't been changed to the pod IP");

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_src_one)
		test_fatal("src TCP port was changed");

	if (l4->dest != tcp_svc_one)
		test_fatal("dst TCP port incorrect");

	test_finish();
}

PKTGEN("tc", "hairpin_flow_2_reverse_v4")
int hairpin_flow_reverse_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct iphdr *l3;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)src, (__u8 *)dst);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->saddr = v4_pod_one;
	l3->daddr = IPV4_LOOPBACK;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = tcp_svc_one;
	l4->dest = tcp_src_one;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

/* Test that a packet in the reverse direction gets translated back. */
SETUP("tc", "hairpin_flow_2_reverse_v4")
int hairpin_flow_rev_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "hairpin_flow_2_reverse_v4")
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

	if (l3->saddr != v4_svc_one)
		test_fatal("src IP was not NAT'ed back to the svc IP");

	if (l3->daddr != v4_pod_one)
		test_fatal("dest IP hasn't been NAT'ed to the original source IP");

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_svc_one)
		test_fatal("src TCP port was changed");

	if (l4->dest != tcp_src_one)
		test_fatal("dst TCP port incorrect");

	test_finish();
}

/* Test that a packet for a SVC without any backend gets dropped. */
SETUP("tc", "tc_drop_no_backend")
int tc_drop_no_backend_setup(struct __ctx_buff *ctx)
{
	struct policy_key policy_key = {
		.egress = 1,
	};
	struct policy_entry policy_value = {
		.deny = 0,
	};

	int ret;

	ret = build_packet(ctx);
	if (ret)
		return ret;

	lb_v4_add_service(v4_svc_one, tcp_svc_one, 0, 1);

	/* avoid policy drop */
	map_update_elem(&POLICY_MAP, &policy_key, &policy_value, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
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
