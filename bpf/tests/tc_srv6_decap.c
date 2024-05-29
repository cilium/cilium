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
#define ENABLE_HOST_ROUTING
#define ENABLE_NODEPORT

/* Test SRH encap. Reduced encap code path is a subset of SRH encap */
#define ENABLE_SRV6_SRH_ENCAP

#include "bpf_host.c"
#include "lib/ipcache.h"
#include "lib/endpoint.h"
#include "lib/lb.h"

#define FROM_NETDEV 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
	},
};

#define POD_IPV4 v4_pod_one
#define POD_IPV6 v6_pod_one
#define EXT_IPV4 v4_ext_one
#define EXT_IPV6 v6_pod_two
#define OUTER_SRC v6_node_one
#define SID v6_node_two
#define ROUTER_MAC mac_one
#define POD_MAC mac_two
#define SERVICE_IPV4 v4_svc_one
#define SERVICE_IPV6 v6_node_three
#define CLIENT_PORT __bpf_htons(12345)
#define SERVICE_PORT __bpf_htons(80)

PKTGEN("tc", "tc_srv6_decap_to_pod_ipv4")
int srv6_decap_to_pod_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct ipv6hdr *outer_l3;
	struct srv6_srh *srh;
	struct iphdr *inner_l3;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_FAIL;

	/* We don't set mac addresses. It doesn't matter. */

	outer_l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!outer_l3)
		return TEST_FAIL;

	memcpy(outer_l3->daddr.s6_addr, (const void *)SID, sizeof(SID));
	memcpy(outer_l3->saddr.s6_addr, (const void *)OUTER_SRC, sizeof(OUTER_SRC));

	srh = (struct srv6_srh *)pktgen__append_ipv6_extension_header(&builder,
			NEXTHDR_ROUTING, sizeof(*srh) + sizeof(union v6addr));
	if (!srh)
		return TEST_FAIL;

	srh->rthdr.nexthdr = IPPROTO_IPIP; /* Inner IP */
	srh->rthdr.hdrlen = 2;             /* 24B (excluding first 8B) */
	srh->rthdr.type = 4;               /* Segment Routing Header */
	srh->rthdr.segments_left = 0;      /* Single SID */
	srh->first_segment = 0;            /* Single SID */
	srh->flags = 0;
	srh->reserved = 0;

	/* Copy SID */
	memcpy(srh->segments, (const void *)SID, sizeof(SID));

	inner_l3 = pktgen__push_default_iphdr(&builder);
	if (!inner_l3)
		return TEST_FAIL;

	inner_l3->saddr = EXT_IPV4;
	inner_l3->daddr = POD_IPV4;

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

SETUP("tc", "tc_srv6_decap_to_pod_ipv4")
int srv6_decap_to_pod_ipv4_setup(struct __ctx_buff *ctx __maybe_unused)
{
	union v6addr sid;
	__u32 vrf_id = 1;

	memcpy(sid.addr, (const void *)SID, sizeof(sid.addr));

	map_update_elem(&SRV6_SID_MAP, &sid, &vrf_id, 0);

	endpoint_v4_add_entry(POD_IPV4, 12345, 100, 0, 0,
			      (__u8 *)POD_MAC, (__u8 *)ROUTER_MAC);

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);

	return TEST_FAIL;
}

CHECK("tc", "tc_srv6_decap_to_pod_ipv4")
int srv6_decap_to_pod_ipv4_check(const struct __ctx_buff *ctx __maybe_unused)
{
	void *data;
	void *data_end;
	union v6addr sid;
	__u32 *status_code;
	struct ethhdr *eth;
	struct iphdr *ipv4;

	memcpy(sid.addr, (const void *)SID, sizeof(sid.addr));

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data +
		sizeof(__u32) +
		sizeof(struct ethhdr) +
		sizeof(struct iphdr) > data_end)
		test_fatal("status code + eth + ipv4 out of bounds");

	status_code = data;
	eth = (struct ethhdr *)(status_code + 1);
	ipv4 = (struct iphdr *)(eth + 1);

	/* Ensure the packet is delivered to the Pod with the right MAC and IP */

	/* There's no policy call map entry, so drop is expected */
	if (*status_code != TC_ACT_SHOT)
		test_fatal("unexpected status code");

	if (memcmp(eth->h_dest, (__u8 *)POD_MAC, ETH_ALEN) != 0)
		test_fatal("unexpected eth->h_dest");

	if (memcmp(eth->h_source, (__u8 *)ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("unexpected eth->h_source");

	if (eth->h_proto != __bpf_htons(ETH_P_IP))
		test_fatal("unexpected eth->h_proto");

	if (ipv4->saddr != EXT_IPV4)
		test_fatal("unexpected ipv4->saddr");

	if (ipv4->daddr != POD_IPV4)
		test_fatal("unexpected ipv4->daddr");

	if (ipv4->protocol != IPPROTO_TCP)
		test_fatal("unexpected ipv4->protocol");

	test_finish();

	return TEST_PASS;
}

PKTGEN("tc", "tc_srv6_decap_to_pod_ipv6")
int srv6_decap_to_pod_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct ipv6hdr *outer_l3;
	struct srv6_srh *srh;
	struct ipv6hdr *inner_l3;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_FAIL;

	/* We don't set mac addresses. It doesn't matter. */

	outer_l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!outer_l3)
		return TEST_FAIL;

	memcpy(outer_l3->daddr.s6_addr, (const void *)SID, sizeof(SID));
	memcpy(outer_l3->saddr.s6_addr, (const void *)OUTER_SRC, sizeof(OUTER_SRC));

	srh = (struct srv6_srh *)pktgen__append_ipv6_extension_header(&builder,
			NEXTHDR_ROUTING, sizeof(*srh) + sizeof(union v6addr));
	if (!srh)
		return TEST_FAIL;

	srh->rthdr.nexthdr = IPPROTO_IPV6; /* Inner IPv6 */
	srh->rthdr.hdrlen = 2;             /* 24B (excluding first 8B) */
	srh->rthdr.type = 4;               /* Segment Routing Header */
	srh->rthdr.segments_left = 0;      /* Single SID */
	srh->first_segment = 0;            /* Single SID */
	srh->flags = 0;
	srh->reserved = 0;

	/* Copy SID */
	memcpy(srh->segments, (const void *)SID, sizeof(SID));

	inner_l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!inner_l3)
		return TEST_FAIL;

	memcpy(inner_l3->daddr.s6_addr, (const void *)POD_IPV6, sizeof(POD_IPV6));
	memcpy(inner_l3->saddr.s6_addr, (const void *)EXT_IPV6, sizeof(EXT_IPV6));

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

SETUP("tc", "tc_srv6_decap_to_pod_ipv6")
int srv6_decap_to_pod_ipv6_setup(struct __ctx_buff *ctx __maybe_unused)
{
	union v6addr sid;
	__u32 vrf_id = 1;

	memcpy(sid.addr, (const void *)SID, sizeof(sid.addr));

	map_update_elem(&SRV6_SID_MAP, &sid, &vrf_id, 0);

	endpoint_v6_add_entry((const union v6addr *)POD_IPV6, 12345, 100, 0, 0,
			      (__u8 *)POD_MAC, (__u8 *)ROUTER_MAC);

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);

	return TEST_FAIL;
}

CHECK("tc", "tc_srv6_decap_to_pod_ipv6")
int srv6_decap_to_pod_ipv6_check(const struct __ctx_buff *ctx __maybe_unused)
{
	void *data;
	void *data_end;
	union v6addr sid;
	__u32 *status_code;
	struct ethhdr *eth;
	struct ipv6hdr *ipv6;

	memcpy(sid.addr, (const void *)SID, sizeof(sid.addr));

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data +
		sizeof(__u32) +
		sizeof(struct ethhdr) +
		sizeof(struct ipv6hdr) > data_end)
		test_fatal("status code + eth + ipv6 out of bounds");

	status_code = data;
	eth = (struct ethhdr *)(status_code + 1);
	ipv6 = (struct ipv6hdr *)(eth + 1);

	/* Ensure the packet is delivered to the Pod with the right MAC and IP */

	/* There's no policy call map entry, so drop is expected */
	if (*status_code != TC_ACT_SHOT)
		test_fatal("unexpected status code");

	if (memcmp(eth->h_dest, (__u8 *)POD_MAC, ETH_ALEN) != 0)
		test_fatal("unexpected eth->h_dest");

	if (memcmp(eth->h_source, (__u8 *)ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("unexpected eth->h_source");

	if (eth->h_proto != __bpf_htons(ETH_P_IPV6))
		test_fatal("unexpected eth->h_proto");

	if (!ipv6_addr_equals((const union v6addr *)&ipv6->saddr, (const union v6addr *)EXT_IPV6))
		test_fatal("unexpected ipv6->saddr");

	if (!ipv6_addr_equals((const union v6addr *)&ipv6->daddr, (const union v6addr *)POD_IPV6))
		test_fatal("unexpected ipv6->daddr");

	if (ipv6->nexthdr != IPPROTO_TCP)
		test_fatal("unexpected ipv6->nexthdr");

	test_finish();

	return TEST_PASS;
}

PKTGEN("tc", "tc_srv6_decap_to_service_ipv4")
int srv6_decap_to_service_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct ipv6hdr *outer_l3;
	struct srv6_srh *srh;
	struct iphdr *inner_l3;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_FAIL;

	/* We don't set mac addresses. It doesn't matter. */

	outer_l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!outer_l3)
		return TEST_FAIL;

	memcpy(outer_l3->daddr.s6_addr, (const void *)SID, sizeof(SID));
	memcpy(outer_l3->saddr.s6_addr, (const void *)OUTER_SRC, sizeof(OUTER_SRC));

	srh = (struct srv6_srh *)pktgen__append_ipv6_extension_header(&builder,
			NEXTHDR_ROUTING, sizeof(*srh) + sizeof(union v6addr));
	if (!srh)
		return TEST_FAIL;

	srh->rthdr.nexthdr = IPPROTO_IPIP; /* Inner IP */
	srh->rthdr.hdrlen = 2;             /* 24B (excluding first 8B) */
	srh->rthdr.type = 4;               /* Segment Routing Header */
	srh->rthdr.segments_left = 0;      /* Single SID */
	srh->first_segment = 0;            /* Single SID */
	srh->flags = 0;
	srh->reserved = 0;

	/* Copy SID */
	memcpy(srh->segments, (const void *)SID, sizeof(SID));

	inner_l3 = pktgen__push_default_iphdr(&builder);
	if (!inner_l3)
		return TEST_FAIL;

	inner_l3->saddr = EXT_IPV4;
	inner_l3->daddr = SERVICE_IPV4;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_FAIL;

	l4->source = CLIENT_PORT;
	l4->dest = SERVICE_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_FAIL;

	pktgen__finish(&builder);

	return TEST_PASS;
}

SETUP("tc", "tc_srv6_decap_to_service_ipv4")
int srv6_decap_to_service_ipv4_setup(struct __ctx_buff *ctx __maybe_unused)
{
	union v6addr sid;
	__u32 vrf_id = 1;

	memcpy(sid.addr, (const void *)SID, sizeof(sid.addr));

	map_update_elem(&SRV6_SID_MAP, &sid, &vrf_id, 0);

	lb_v4_add_service(SERVICE_IPV4, SERVICE_PORT, 1, 1);
	lb_v4_add_backend(SERVICE_IPV4, SERVICE_PORT, 1, 124,
			  POD_IPV4, SERVICE_PORT, IPPROTO_TCP, 0);

	endpoint_v4_add_entry(POD_IPV4, 12345, 100, 0, 0,
			      (__u8 *)POD_MAC, (__u8 *)ROUTER_MAC);

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);

	return TEST_FAIL;
}

CHECK("tc", "tc_srv6_decap_to_service_ipv4")
int srv6_decap_to_service_ipv4_check(const struct __ctx_buff *ctx __maybe_unused)
{
	void *data;
	void *data_end;
	union v6addr sid;
	__u32 *status_code;
	struct ethhdr *eth;
	struct iphdr *ipv4;

	memcpy(sid.addr, (const void *)SID, sizeof(sid.addr));

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data +
		sizeof(__u32) +
		sizeof(struct ethhdr) +
		sizeof(struct iphdr) > data_end)
		test_fatal("status code + eth + ipv4 out of bounds");

	status_code = data;
	eth = (struct ethhdr *)(status_code + 1);
	ipv4 = (struct iphdr *)(eth + 1);

	/* Ensure the packet is delivered to the Pod with the right MAC and IP */

	/* There's no policy call map entry, so drop is expected */
	if (*status_code != TC_ACT_SHOT)
		test_fatal("unexpected status code");

	if (memcmp(eth->h_dest, (__u8 *)POD_MAC, ETH_ALEN) != 0)
		test_fatal("unexpected eth->h_dest");

	if (memcmp(eth->h_source, (__u8 *)ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("unexpected eth->h_source");

	if (eth->h_proto != __bpf_htons(ETH_P_IP))
		test_fatal("unexpected eth->h_proto");

	if (ipv4->saddr != EXT_IPV4)
		test_fatal("unexpected ipv4->saddr");

	if (ipv4->daddr != POD_IPV4)
		test_fatal("unexpected ipv4->daddr");

	if (ipv4->protocol != IPPROTO_TCP)
		test_fatal("unexpected ipv4->protocol");

	test_finish();

	return TEST_PASS;
}

PKTGEN("tc", "tc_srv6_decap_to_service_ipv6")
int srv6_decap_to_service_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct ipv6hdr *outer_l3;
	struct srv6_srh *srh;
	struct ipv6hdr *inner_l3;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_FAIL;

	/* We don't set mac addresses. It doesn't matter. */

	outer_l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!outer_l3)
		return TEST_FAIL;

	memcpy(outer_l3->daddr.s6_addr, (const void *)SID, sizeof(SID));
	memcpy(outer_l3->saddr.s6_addr, (const void *)OUTER_SRC, sizeof(OUTER_SRC));

	srh = (struct srv6_srh *)pktgen__append_ipv6_extension_header(&builder,
			NEXTHDR_ROUTING, sizeof(*srh) + sizeof(union v6addr));
	if (!srh)
		return TEST_FAIL;

	srh->rthdr.nexthdr = IPPROTO_IPV6; /* Inner IPv6 */
	srh->rthdr.hdrlen = 2;             /* 24B (excluding first 8B) */
	srh->rthdr.type = 4;               /* Segment Routing Header */
	srh->rthdr.segments_left = 0;      /* Single SID */
	srh->first_segment = 0;            /* Single SID */
	srh->flags = 0;
	srh->reserved = 0;

	/* Copy SID */
	memcpy(srh->segments, (const void *)SID, sizeof(SID));

	inner_l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!inner_l3)
		return TEST_FAIL;

	memcpy(inner_l3->daddr.s6_addr, (const void *)POD_IPV6, sizeof(POD_IPV6));
	memcpy(inner_l3->saddr.s6_addr, (const void *)EXT_IPV6, sizeof(EXT_IPV6));

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_FAIL;

	l4->source = CLIENT_PORT;
	l4->dest = SERVICE_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_FAIL;

	pktgen__finish(&builder);

	return TEST_PASS;
}

SETUP("tc", "tc_srv6_decap_to_service_ipv6")
int srv6_decap_to_service_ipv6_setup(struct __ctx_buff *ctx __maybe_unused)
{
	union v6addr sid;
	__u32 vrf_id = 1;

	memcpy(sid.addr, (const void *)SID, sizeof(sid.addr));

	map_update_elem(&SRV6_SID_MAP, &sid, &vrf_id, 0);

	lb_v6_add_service((const union v6addr *)SERVICE_IPV6, SERVICE_PORT, 1, 1);
	lb_v6_add_backend((const union v6addr *)SERVICE_IPV6, SERVICE_PORT, 1, 124,
			  (const union v6addr *)POD_IPV6, SERVICE_PORT, IPPROTO_TCP, 0);

	endpoint_v6_add_entry((const union v6addr *)POD_IPV6, 12345, 100, 0, 0,
			      (__u8 *)POD_MAC, (__u8 *)ROUTER_MAC);

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);

	return TEST_FAIL;
}

CHECK("tc", "tc_srv6_decap_to_service_ipv6")
int srv6_decap_to_service_ipv6_check(const struct __ctx_buff *ctx __maybe_unused)
{
	void *data;
	void *data_end;
	union v6addr sid;
	__u32 *status_code;
	struct ethhdr *eth;
	struct ipv6hdr *ipv6;

	memcpy(sid.addr, (const void *)SID, sizeof(sid.addr));

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data +
		sizeof(__u32) +
		sizeof(struct ethhdr) +
		sizeof(struct ipv6hdr) > data_end)
		test_fatal("status code + eth + ipv6 out of bounds");

	status_code = data;
	eth = (struct ethhdr *)(status_code + 1);
	ipv6 = (struct ipv6hdr *)(eth + 1);

	/* Ensure the packet is delivered to the Pod with the right MAC and IP */

	/* There's no policy call map entry, so drop is expected */
	if (*status_code != TC_ACT_SHOT)
		test_fatal("unexpected status code");

	if (memcmp(eth->h_dest, (__u8 *)POD_MAC, ETH_ALEN) != 0)
		test_fatal("unexpected eth->h_dest");

	if (memcmp(eth->h_source, (__u8 *)ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("unexpected eth->h_source");

	if (eth->h_proto != __bpf_htons(ETH_P_IPV6))
		test_fatal("unexpected eth->h_proto");

	if (!ipv6_addr_equals((const union v6addr *)&ipv6->saddr, (const union v6addr *)EXT_IPV6))
		test_fatal("unexpected ipv6->saddr");

	if (!ipv6_addr_equals((const union v6addr *)&ipv6->daddr, (const union v6addr *)POD_IPV6))
		test_fatal("unexpected ipv6->daddr");

	if (ipv6->nexthdr != IPPROTO_TCP)
		test_fatal("unexpected ipv6->protocol");

	test_finish();

	return TEST_PASS;
}
