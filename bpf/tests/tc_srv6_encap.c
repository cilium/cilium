// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/skb.h>
#include <linux/in.h>
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_SRV6
#ifdef TUNNEL_MODE
#undef TUNNEL_MODE
#endif

/* Test SRH encap. Reduced encap code path is a subset of SRH encap */
#define ENABLE_SRV6_SRH_ENCAP

#include "bpf_lxc.c"
#include "lib/ipcache.h"
#include "lib/policy.h"

#define FROM_CONTAINER 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_CONTAINER] = &cil_from_container,
	},
};

#define POD_IPV4 v4_pod_one
#define EXT_IPV4 v4_ext_one
#define POD_IPV6 v6_pod_one
#define EXT_IPV6 v6_node_one
#define SID v6_node_two

PKTGEN("tc", "tc_srv6_encap_from_pod_ipv4")
int srv6_encap_from_pod_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_FAIL;

	/* We don't set mac addresses. It doesn't matter. */

	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_FAIL;

	l3->saddr = POD_IPV4;
	l3->daddr = EXT_IPV4;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_FAIL;

	/* We don't set ports. It doesn't matter. */

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_FAIL;

	pktgen__finish(&builder);

	return TEST_PASS;
}

SETUP("tc", "tc_srv6_encap_from_pod_ipv4")
int srv6_encap_from_pod_ipv4_setup(struct __ctx_buff *ctx __maybe_unused)
{
	struct srv6_vrf_key4 vrf_key = {
		.lpm = {SRV6_VRF_STATIC_PREFIX4, {} },
		.src_ip = POD_IPV4,
		.dst_cidr = 0,
	};
	struct srv6_policy_key4 policy_key = {
		.lpm = {SRV6_POLICY_STATIC_PREFIX4 + 32, {} },
		.vrf_id = 1,
		.dst_cidr = EXT_IPV4,
	};
	union v6addr sid;
	__u32 vrf_id = 1;

	memcpy(&sid, (const void *)SID, sizeof(sid));
	map_update_elem(&SRV6_VRF_MAP4, &vrf_key, &vrf_id, 0);
	map_update_elem(&SRV6_POLICY_MAP4, &policy_key, &sid, 0);

	/* We need this rule. Otherwise, network policy will drop the inner packet. */
	policy_add_egress_allow_all_entry();

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	return TEST_FAIL;
}

CHECK("tc", "tc_srv6_encap_from_pod_ipv4")
int srv6_encap_from_pod_ipv4_check(const struct __ctx_buff *ctx __maybe_unused)
{
	void *data;
	void *data_end;
	union v6addr expected_sid;
	__u32 *status_code;
	struct ethhdr *eth;
	struct ipv6hdr *ipv6;
	struct srv6_srh *srh;
	union v6addr *sid;
	struct iphdr *ipv4;

	memcpy(&expected_sid, (const void *)SID, sizeof(expected_sid));

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data +
		sizeof(__u32) +
		sizeof(struct ethhdr) +
		sizeof(struct ipv6hdr) +
		sizeof(struct srv6_srh) +
		sizeof(union v6addr) +
		sizeof(struct iphdr) > data_end)
		test_fatal("status code + eth + ipv6 + srh + sid + ipv4 out of bounds");

	status_code = data;
	eth = (struct ethhdr *)(status_code + 1);
	ipv6 = (struct ipv6hdr *)(eth + 1);
	srh = (struct srv6_srh *)(ipv6 + 1);
	sid = (union v6addr *)(srh + 1);
	ipv4 = (struct iphdr *)(sid + 1);

	if (*status_code != TC_ACT_OK)
		test_fatal("unexpected status code");

	if (eth->h_proto != __bpf_htons(ETH_P_IPV6))
		test_fatal("unexpected eth->h_proto");

	/* Destination address should be the SID */
	if (!ipv6_addr_equals((union v6addr *)&ipv6->daddr, sid))
		test_fatal("unexpected ipv6->daddr");

	/* Nexthdr should be routing header */
	if (ipv6->nexthdr != IPPROTO_ROUTING)
		test_fatal("unexpected ipv6->nexthdr");

	/* Nexthdr of routing header should be IPv4 */
	if (srh->rthdr.nexthdr != IPPROTO_IPIP)
		test_fatal("unexpected srh->rthdr.nexthdr");

	/* Header length should be 2 (8 * 2 + 8 (first fixed 8B) = 24 bytes) */
	if (srh->rthdr.hdrlen != 2)
		test_fatal("unexpected srh->rthdr.hdr_len");

	/* Routing header type should be 4 (Segment Routing Header) */
	if (srh->rthdr.type != 4)
		test_fatal("unexpected srh->rthdr.type");

	/* Currently, only one segment is supported */
	if (srh->rthdr.segments_left != 0)
		test_fatal("unexpected srh->rthdr.segments_left");

	/* First segment should be 0 */
	if (srh->first_segment != 0)
		test_fatal("unexpected srh->first_segment");

	/* Check SID is the expected one */
	if (!ipv6_addr_equals(sid, &expected_sid))
		test_fatal("unexpected sid");

	/* Check IPv4 header (just to make sure the encapsulation doesn't corrupt inner packet) */
	if (ipv4->saddr != POD_IPV4)
		test_fatal("unexpected ipv4->saddr");

	if (ipv4->daddr != EXT_IPV4)
		test_fatal("unexpected ipv4->daddr");

	test_finish();

	return TEST_PASS;
}

PKTGEN("tc", "tc_srv6_encap_from_pod_ipv6")
int srv6_encap_from_pod_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_FAIL;

	/* We don't set mac addresses. It doesn't matter. */

	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_FAIL;

	memcpy(&l3->saddr, (const void *)POD_IPV6, sizeof(l3->saddr));
	memcpy(&l3->daddr, (const void *)EXT_IPV6, sizeof(l3->daddr));

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_FAIL;

	/* We don't set ports. It doesn't matter. */

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_FAIL;

	pktgen__finish(&builder);

	return TEST_PASS;
}

SETUP("tc", "tc_srv6_encap_from_pod_ipv6")
int srv6_encap_from_pod_ipv6_setup(struct __ctx_buff *ctx __maybe_unused)
{
	struct srv6_vrf_key6 vrf_key = {
		.lpm = {SRV6_VRF_STATIC_PREFIX6, {} },
	};
	struct srv6_policy_key6 policy_key = {
		.lpm = {SRV6_POLICY_STATIC_PREFIX6 + 128, {} },
		.vrf_id = 1,
	};
	union v6addr sid;
	__u32 vrf_id = 1;

	memcpy(&vrf_key.src_ip, (const void *)POD_IPV6, sizeof(union v6addr));
	memset(&vrf_key.dst_cidr, 0, sizeof(union v6addr));
	map_update_elem(&SRV6_VRF_MAP6, &vrf_key, &vrf_id, 0);

	memcpy(&policy_key.dst_cidr, (const void *)EXT_IPV6, sizeof(union v6addr));
	memcpy(&sid, (const void *)SID, sizeof(sid));
	map_update_elem(&SRV6_POLICY_MAP6, &policy_key, &sid, 0);

	/* We need this rule. Otherwise, network policy will drop the inner packet. */
	policy_add_egress_allow_all_entry();

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	return TEST_FAIL;
}

CHECK("tc", "tc_srv6_encap_from_pod_ipv6")
int srv6_encap_from_pod_ipv6_check(const struct __ctx_buff *ctx __maybe_unused)
{
	void *data;
	void *data_end;
	union v6addr expected_sid;
	__u32 *status_code;
	struct ethhdr *eth;
	struct ipv6hdr *outer_ipv6;
	struct srv6_srh *srh;
	union v6addr *sid;
	struct ipv6hdr *inner_ipv6;

	memcpy(&expected_sid, (const void *)SID, sizeof(expected_sid));

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data +
		sizeof(__u32) +
		sizeof(struct ethhdr) +
		sizeof(struct ipv6hdr) +
		sizeof(struct srv6_srh) +
		sizeof(union v6addr) +
		sizeof(struct ipv6hdr) > data_end)
		test_fatal("status code + eth + ipv6 + srh + sid + ipv6 out of bounds");

	status_code = data;
	eth = (struct ethhdr *)(status_code + 1);
	outer_ipv6 = (struct ipv6hdr *)(eth + 1);
	srh = (struct srv6_srh *)(outer_ipv6 + 1);
	sid = (union v6addr *)(srh + 1);
	inner_ipv6 = (struct ipv6hdr *)(sid + 1);

	if (*status_code != TC_ACT_OK)
		test_fatal("unexpected status code");

	if (eth->h_proto != __bpf_htons(ETH_P_IPV6))
		test_fatal("unexpected eth->h_proto");

	/* Destination address should be the SID */
	if (!ipv6_addr_equals((union v6addr *)&outer_ipv6->daddr, sid))
		test_fatal("unexpected ipv6->daddr");

	/* Nexthdr should be routing header */
	if (outer_ipv6->nexthdr != IPPROTO_ROUTING)
		test_fatal("unexpected ipv6->nexthdr");

	/* Nexthdr of routing header should be IPv6 */
	if (srh->rthdr.nexthdr != IPPROTO_IPV6)
		test_fatal("unexpected srh->rthdr.nexthdr");

	/* Header length should be 2 (8 * 2 + 8 (first fixed 8B) = 24 bytes) */
	if (srh->rthdr.hdrlen != 2)
		test_fatal("unexpected srh->rthdr.hdr_len");

	/* Routing header type should be 4 (Segment Routing Header) */
	if (srh->rthdr.type != 4)
		test_fatal("unexpected srh->rthdr.type");

	/* Currently, only one segment is supported */
	if (srh->rthdr.segments_left != 0)
		test_fatal("unexpected srh->rthdr.segments_left");

	/* First segment should be 0 */
	if (srh->first_segment != 0)
		test_fatal("unexpected srh->first_segment");

	/* Check SID is the expected one */
	if (!ipv6_addr_equals(sid, &expected_sid))
		test_fatal("unexpected sid");

	/* Check IPv4 header (just to make sure the encapsulation doesn't corrupt inner packet) */
	if (memcmp(&inner_ipv6->saddr, (const void *)POD_IPV6, sizeof(inner_ipv6->saddr)) != 0)
		test_fatal("unexpected ipv6->saddr");

	if (memcmp(&inner_ipv6->daddr, (const void *)EXT_IPV6, sizeof(inner_ipv6->daddr)) != 0)
		test_fatal("unexpected ipv6->daddr");

	test_finish();

	return TEST_PASS;
}
