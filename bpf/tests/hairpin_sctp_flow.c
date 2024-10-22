// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

/* Set the LXC source address to be the address of pod one */
#define LXC_IPV4 (__be32)v4_pod_one

/* Enable CT debug output */
#undef QUIET_CT

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Enable code paths under test*/
#define ENABLE_IPV4
#define ENABLE_SCTP

/* Use to-container for ingress policy: */
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
		[1] = &cil_to_container,
	},
};

/* Setup for this test:
 * +-------ClusterIP--------+    +----------Pod 1---------+
 * | v4_svc_one:tcp_svc_one | -> | v4_pod_one:tcp_svc_one |
 * +------------------------+    +------------------------+
 *            ^                            |
 *            \---------------------------/
 */

/* Test that sending a packet from a pod to its own service gets source nat-ed
 * and that it is forwarded to the correct veth.
 */
SETUP("tc", "hairpin_sctp_flow_1_forward_v4")
int hairpin_flow_forward_setup(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct iphdr *l3;
	struct sctphdr *l4;
	__u16 revnat_id = 1;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)src, (__u8 *)dst,
				      v4_pod_one, v4_svc_one);
	if (!l3)
		return TEST_ERROR;

	/* Push SCTP header */
	l4 = pktgen__push_sctphdr(&builder);

	if (!l4)
		return TEST_ERROR;
	if ((void *)l4 + sizeof(struct sctphdr) > ctx_data_end(ctx))
		return TEST_ERROR;

	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	lb_v4_add_service(v4_svc_one, tcp_svc_one, 1, revnat_id);
	lb_v4_add_backend(v4_svc_one, tcp_svc_one, 1, 124,
			  v4_pod_one, tcp_svc_one, IPPROTO_SCTP, 0);

	/* Add an IPCache entry for pod 1 */
	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);

	endpoint_v4_add_entry(v4_pod_one, 0, 0, 0, 0, NULL, NULL);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "hairpin_sctp_flow_1_forward_v4")
int hairpin_flow_forward_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct sctphdr *l4;

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

	if (l3->check != bpf_htons(0xb09c))
		test_fatal("L3 checksum is invalid: %d", bpf_htons(l3->check));

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct sctphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_src_one)
		test_fatal("src SCTP port was changed");

	if (l4->dest != tcp_svc_one)
		test_fatal("dst SCTP port incorrect");

	test_finish();
}

/* Let backend's ingress path create its CT own entry: */
PKTGEN("tc", "hairpin_sctp_flow_2_forward_ingress_v4")
int hairpin_flow_forward_ingress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct iphdr *l3;
	struct sctphdr *l4;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)src, (__u8 *)dst,
				      IPV4_LOOPBACK, v4_pod_one);
	if (!l3)
		return TEST_ERROR;

	/* Push SCTP header */
	l4 = pktgen__push_sctphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hairpin_sctp_flow_2_forward_ingress_v4")
int hairpin_flow_forward_ingress_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 1);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "hairpin_sctp_flow_2_forward_ingress_v4")
int hairpin_flow_forward_ingress_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct sctphdr *l4;

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

	if (l3->saddr != IPV4_LOOPBACK)
		test_fatal("src IP changed");

	if (l3->daddr != v4_pod_one)
		test_fatal("dest IP changed");

	if (l3->check != bpf_htons(0xaf9c))
		test_fatal("L3 checksum is invalid: %d", bpf_htons(l3->check));

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct sctphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_src_one)
		test_fatal("src SCTP port changed");

	if (l4->dest != tcp_svc_one)
		test_fatal("dst SCTP port changed");

	test_finish();
}

/* Test that a packet in the reverse direction gets translated back. */
SETUP("tc", "hairpin_sctp_flow_3_reverse_v4")
int hairpin_flow_rev_setup(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct iphdr *l3;
	struct sctphdr *l4;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)src, (__u8 *)dst,
				      v4_pod_one, IPV4_LOOPBACK);
	if (!l3)
		return TEST_ERROR;

	/* Push SCTP header */
	l4 = pktgen__push_sctphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = tcp_svc_one;
	l4->dest = tcp_src_one;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "hairpin_sctp_flow_3_reverse_v4")
int hairpin_flow_rev_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct sctphdr *l4;

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

	if (l3->daddr != IPV4_LOOPBACK)
		test_fatal("dest IP changed");

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct sctphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_svc_one)
		test_fatal("src SCTP port changed");

	if (l4->dest != tcp_src_one)
		test_fatal("dst SCTP port changed");

	test_finish();
}

PKTGEN("tc", "hairpin_sctp_flow_4_reverse_ingress_v4")
int hairpin_sctp_flow_4_reverse_ingress_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	volatile const __u8 *src = mac_one;
	volatile const __u8 *dst = mac_two;
	struct iphdr *l3;
	struct sctphdr *l4;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)src, (__u8 *)dst,
				      v4_pod_one, IPV4_LOOPBACK);
	if (!l3)
		return TEST_ERROR;

	/* Push SCTP header */
	l4 = pktgen__push_sctphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = tcp_svc_one;
	l4->dest = tcp_src_one;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hairpin_sctp_flow_4_reverse_ingress_v4")
int hairpin_sctp_flow_4_reverse_ingress_v4_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 1);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "hairpin_sctp_flow_4_reverse_ingress_v4")
int hairpin_sctp_flow_4_reverse_ingress_v4_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct sctphdr *l4;

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

	if (l3->check != bpf_htons(0x3a0))
		test_fatal("L3 checksum is invalid: %d", bpf_htons(l3->check));

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct sctphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_svc_one)
		test_fatal("src TCP port was changed");

	if (l4->dest != tcp_src_one)
		test_fatal("dst TCP port incorrect");

	test_finish();
}
