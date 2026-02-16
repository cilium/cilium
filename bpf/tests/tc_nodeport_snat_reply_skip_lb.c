// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/*
 * Test: verify that reply traffic matching a reverse SNAT entry bypasses
 * the LB service lookup (fix for issue #44348).
 *
 * When a pod sends outgoing UDP from a port that is also exposed via an
 * LB service, the return traffic must NOT be intercepted by the LB
 * service lookup. The SNAT reverse map check fires first and skips the
 * LB, preserving the source port.
 */

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define ENABLE_NODEPORT		1
#define ENABLE_MASQUERADE_IPV4	1
#define ENABLE_MASQUERADE_IPV6	1
#define ENABLE_HOST_ROUTING	1

/* External server that sends reply traffic */
#define EXT_IP			v4_ext_one
#define EXT_PORT		__bpf_htons(80)

/* Node IP and the contested port (both SNAT'd and LB service) */
#define NODE_IP			v4_node_one
#define SVC_PORT		__bpf_htons(30001)

/* LB backend (should NOT be reached for reply traffic) */
#define BACKEND_IP		v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

/* Pod that originally sent the outgoing traffic */
#define POD_IP			v4_pod_one

#define DEFAULT_IFACE		24
#define BACKEND_IFACE		25
#define BACKEND_EP_ID		127

#define IPV4_DIRECT_ROUTING	NODE_IP

/* IPv6 addresses */
#define EXT_IP6			v6_ext_node_one
#define EXT_IP6_ADDR		{ .addr = v6_ext_node_one_addr }
#define NODE_IP6		v6_node_one
#define NODE_IP6_ADDR		{ .addr = v6_node_one_addr }
#define POD_IP6			v6_pod_one
#define POD_IP6_ADDR		{ .addr = v6_pod_one_addr }
#define BACKEND_IP6		v6_pod_two
#define BACKEND_IP6_ADDR	{ .addr = v6_pod_two_addr }

static volatile const __u8 *ext_mac = mac_one;
static volatile const __u8 *node_mac = mac_two;
static volatile const __u8 *backend_mac = mac_four;

__section_entry
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_REDIRECT;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[BACKEND_EP_ID] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(__maybe_unused struct __ctx_buff * volatile ctx,
		     struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;

	params->ifindex = DEFAULT_IFACE;
	__bpf_memcpy_builtin(params->smac, (__u8 *)node_mac, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)ext_mac, ETH_ALEN);
	return 0;
}

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	return CTX_ACT_REDIRECT;
}

#include "lib/bpf_host.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)

#include "nodeport_defaults.h"

/*
 * Baseline IPv4: when no SNAT reverse entry exists, the LB service should
 * match normally and DNAT the packet to the backend.
 */
PKTGEN("tc", "tc_nodeport_lb_dnat_no_snat_ipv4")
int tc_nodeport_lb_dnat_no_snat_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)ext_mac, (__u8 *)node_mac,
					   EXT_IP, NODE_IP,
					   EXT_PORT, SVC_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb_dnat_no_snat_ipv4")
int tc_nodeport_lb_dnat_no_snat_ipv4_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(NODE_IP, SVC_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v4_add_backend(NODE_IP, SVC_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_UDP, 0);

	endpoint_v4_add_entry(BACKEND_IP, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);
	ipcache_v4_add_world_entry();

	/* No SNAT entry — LB should handle this packet. */

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb_dnat_no_snat_ipv4")
int tc_nodeport_lb_dnat_no_snat_ipv4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
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

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != EXT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP hasn't been DNAT'd to backend IP");

	if (l4->source != EXT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been DNAT'd to backend port");

	test_finish();
}

#ifdef ENABLE_IPV6
/*
 * Baseline IPv6: same — no SNAT entry, LB should DNAT normally.
 */
PKTGEN("tc", "tc_nodeport_lb_dnat_no_snat_ipv6")
int tc_nodeport_lb_dnat_no_snat_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_udp_packet(&builder,
					   (__u8 *)ext_mac, (__u8 *)node_mac,
					   (__u8 *)EXT_IP6, (__u8 *)NODE_IP6,
					   EXT_PORT, SVC_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_lb_dnat_no_snat_ipv6")
int tc_nodeport_lb_dnat_no_snat_ipv6_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	union v6addr node_ip6 = NODE_IP6_ADDR;
	union v6addr backend_ip6 = BACKEND_IP6_ADDR;

	lb_v6_add_service(&node_ip6, SVC_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v6_add_backend(&node_ip6, SVC_PORT, 1, 125,
			  &backend_ip6, BACKEND_PORT, IPPROTO_UDP, 0);

	endpoint_v6_add_entry(&backend_ip6, BACKEND_IFACE, BACKEND_EP_ID, 0, 112233,
			      (__u8 *)backend_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry(&backend_ip6, 0, 112233, 0, 0);
	ipcache_v6_add_world_entry();

	/* No SNAT entry — LB should handle this packet. */

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_lb_dnat_no_snat_ipv6")
int tc_nodeport_lb_dnat_no_snat_ipv6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ipv6hdr *l3;
	union v6addr backend_ip6 = BACKEND_IP6_ADDR;
	union v6addr ext_ip6 = EXT_IP6_ADDR;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(&l3->saddr, &ext_ip6, sizeof(union v6addr)))
		test_fatal("src IP has changed");

	if (memcmp(&l3->daddr, &backend_ip6, sizeof(union v6addr)))
		test_fatal("dst IP hasn't been DNAT'd to backend IP");

	if (l4->source != EXT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been DNAT'd to backend port");

	test_finish();
}
#endif /* ENABLE_IPV6 */

/*
 * IPv4: send a UDP reply packet that matches both an SNAT reverse entry
 * and an LB service.  The SNAT check should bypass the LB.
 */
PKTGEN("tc", "tc_nodeport_snat_reply_skip_lb_ipv4")
int tc_nodeport_snat_reply_skip_lb_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)ext_mac, (__u8 *)node_mac,
					   EXT_IP, NODE_IP,
					   EXT_PORT, SVC_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_snat_reply_skip_lb_ipv4")
int tc_nodeport_snat_reply_skip_lb_ipv4_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Register an LB service on NODE_IP:SVC_PORT/UDP with a backend. */
	lb_v4_add_service(NODE_IP, SVC_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v4_add_backend(NODE_IP, SVC_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_UDP, 0);

	endpoint_v4_add_entry(BACKEND_IP, BACKEND_IFACE, BACKEND_EP_ID, 0, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);

	/* Pre-populate a reverse SNAT entry matching this reply traffic.
	 * This represents a previous outgoing connection:
	 *   POD_IP:SVC_PORT -> EXT_IP:EXT_PORT  (SNAT'd to NODE_IP:SVC_PORT)
	 */
	struct ipv4_ct_tuple snat_key = {
		.saddr   = EXT_IP,
		.daddr   = NODE_IP,
		.sport   = EXT_PORT,
		.dport   = SVC_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags   = TUPLE_F_IN,
	};
	struct ipv4_nat_entry snat_val = {};

	snat_val.to_daddr = POD_IP;
	snat_val.to_dport = SVC_PORT;

	map_update_elem(&cilium_snat_v4_external, &snat_key, &snat_val, BPF_ANY);

	ipcache_v4_add_world_entry();

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_snat_reply_skip_lb_ipv4")
int tc_nodeport_snat_reply_skip_lb_ipv4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* If the LB was incorrectly applied, we'd see CTX_ACT_REDIRECT
	 * (redirected to the backend).  With the fix, the packet skips the
	 * LB and is passed to the stack after RevSNAT.
	 */
	assert(*status_code == CTX_ACT_OK);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	/* The packet must NOT be DNAT'd to the backend. */
	if (l3->daddr == BACKEND_IP)
		test_fatal("dst IP was DNAT'd to backend - LB was not skipped");

	/* The source port must be preserved (not rewritten by the LB). */
	if (l4->source != EXT_PORT)
		test_fatal("src port was rewritten");

	/* The dest port must not be changed to the backend port. */
	if (l4->dest == BACKEND_PORT)
		test_fatal("dst port was changed to backend port - LB was not skipped");

	test_finish();
}

#ifdef ENABLE_IPV6
/*
 * IPv6: same scenario as above but for the IPv6 datapath.
 */
PKTGEN("tc", "tc_nodeport_snat_reply_skip_lb_ipv6")
int tc_nodeport_snat_reply_skip_lb_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_udp_packet(&builder,
					   (__u8 *)ext_mac, (__u8 *)node_mac,
					   (__u8 *)EXT_IP6, (__u8 *)NODE_IP6,
					   EXT_PORT, SVC_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_snat_reply_skip_lb_ipv6")
int tc_nodeport_snat_reply_skip_lb_ipv6_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	union v6addr node_ip6 = NODE_IP6_ADDR;
	union v6addr backend_ip6 = BACKEND_IP6_ADDR;
	union v6addr pod_ip6 = POD_IP6_ADDR;

	/* Register an LB service on NODE_IP6:SVC_PORT/UDP with a backend. */
	lb_v6_add_service(&node_ip6, SVC_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v6_add_backend(&node_ip6, SVC_PORT, 1, 125,
			  &backend_ip6, BACKEND_PORT, IPPROTO_UDP, 0);

	ipcache_v6_add_world_entry();

	/* Pre-populate a reverse SNAT entry matching this reply traffic. */
	struct ipv6_ct_tuple snat_key __align_stack_8 = {
		.saddr   = EXT_IP6_ADDR,
		.daddr   = NODE_IP6_ADDR,
		.sport   = EXT_PORT,
		.dport   = SVC_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags   = TUPLE_F_IN,
	};
	struct ipv6_nat_entry snat_val __align_stack_8 = {};

	snat_val.to_daddr = pod_ip6;
	snat_val.to_dport = SVC_PORT;

	map_update_elem(&cilium_snat_v6_external, &snat_key, &snat_val, BPF_ANY);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_snat_reply_skip_lb_ipv6")
int tc_nodeport_snat_reply_skip_lb_ipv6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ipv6hdr *l3;
	union v6addr backend_ip6 = BACKEND_IP6_ADDR;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	/* The packet must NOT be DNAT'd to the backend. */
	if (!memcmp(&l3->daddr, &backend_ip6, sizeof(union v6addr)))
		test_fatal("dst IP was DNAT'd to backend - LB was not skipped");

	/* The source port must be preserved. */
	if (l4->source != EXT_PORT)
		test_fatal("src port was rewritten");

	/* The dest port must not be the backend port. */
	if (l4->dest == BACKEND_PORT)
		test_fatal("dst port was changed to backend port - LB was not skipped");

	test_finish();
}
#endif /* ENABLE_IPV6 */
