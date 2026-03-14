// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/*
 * Test: demonstrate LB incorrectly intercepting SNAT reply traffic when
 * BPF masquerade is disabled (issue #44348).
 *
 * Real-world scenario (Talos Linux with KubeSpan, bpf.masquerade=false):
 *
 *  1) Pod listens on UDP port 10001 and sends outgoing UDP from the same
 *     port to an external server on port 9000.
 *  2) A NodePort/LB service exposes the pod on NODE_IP:10001.
 *     The LB backend is the SAME pod: POD_IP:10001.
 *  3) Since BPF masquerade is disabled, iptables MASQUERADE handles SNAT.
 *     iptables preserves the original source port, so on the wire:
 *       NODE_IP:10001 → EXT_IP:9000
 *  4) External server replies:  EXT_IP:9000 → NODE_IP:10001
 *  5) The reply enters the node via from-netdev (tc ingress BPF).
 *     BPF runs BEFORE netfilter, so kernel conntrack cannot help.
 *  6) nodeport_lb4() finds the LB service on NODE_IP:10001, treats
 *     the reply as a new inbound LB connection, and DNATs to the
 *     backend (which is the same pod).
 *  7) The NodePort CT entry created by ct_create4() uses the same
 *     5-tuple key as the pod's original outgoing CT entry, overwriting
 *     it.  The endpoint BPF detects the collision and SNATs the source
 *     port (9000 → random).
 *  8) Pod receives the reply with a wrong source port.  The application
 *     validates the source port and rejects the packet.
 *
 * Test 1 (tc_nodeport_no_bpf_masq_reply_lb_intercept_ipv4):
 *   Sends a reply packet and verifies the LB intercepts it — DNAT
 *   redirects to the backend (same pod).
 *
 * Test 2 (tc_nodeport_no_bpf_masq_ct_overwrite_ipv4):
 *   Pre-populates the pod's outgoing CT entry, sends the reply, and
 *   verifies the CT entry was overwritten by the NodePort entry
 *   (node_port flag set, rev_nat_index changed).
 */

#define ENABLE_IPV4		1
#define ENABLE_NODEPORT		1
#define ENABLE_HOST_ROUTING	1
/* Deliberately NOT defining ENABLE_MASQUERADE_IPV4 — the whole point. */

/* External server */
#define EXT_IP			v4_ext_one
#define EXT_PORT		__bpf_htons(9000)

/* Node IP and the contested port */
#define NODE_IP			v4_node_one
#define SVC_PORT		__bpf_htons(10001)

/* LB backend = the SAME pod that sent the outgoing traffic */
#define POD_IP			v4_pod_one
#define BACKEND_IP		POD_IP
#define BACKEND_PORT		SVC_PORT	/* same port */

#define DEFAULT_IFACE		24
#define POD_IFACE		26
#define POD_EP_ID		126

#define IPV4_DIRECT_ROUTING	NODE_IP

static volatile const __u8 *ext_mac = mac_one;
static volatile const __u8 *node_mac = mac_two;
static volatile const __u8 *pod_mac = mac_four;

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
		[POD_EP_ID] = &mock_handle_policy,
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

/* --------------------------------------------------------------------------
 * Test 1: LB intercepts the reply packet (basic scenario).
 *
 * Packet: EXT_IP:9000 → NODE_IP:10001 (reply to iptables-masqueraded traffic)
 * LB service: NODE_IP:10001 → POD_IP:10001 (backend = same pod)
 * Expected: LB matches, DNAT dst to POD_IP:10001 (bug — should pass through)
 * --------------------------------------------------------------------------
 */
PKTGEN("tc", "tc_nodeport_no_bpf_masq_reply_lb_intercept_ipv4")
int tc_nodeport_no_bpf_masq_reply_lb_intercept_ipv4_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "tc_nodeport_no_bpf_masq_reply_lb_intercept_ipv4")
int tc_nodeport_no_bpf_masq_reply_lb_intercept_ipv4_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* LB service: NODE_IP:10001 → POD_IP:10001 (backend = same pod). */
	lb_v4_add_service(NODE_IP, SVC_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v4_add_backend(NODE_IP, SVC_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_UDP, 0);

	/* Register pod as local endpoint for delivery after DNAT. */
	endpoint_v4_add_entry(POD_IP, POD_IFACE, POD_EP_ID, 0, 0, 0,
			      (__u8 *)pod_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(POD_IP, 0, 112233, 0, 0);
	ipcache_v4_add_world_entry();

	/* No BPF SNAT map entry — iptables handles masquerade. */

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_no_bpf_masq_reply_lb_intercept_ipv4")
int tc_nodeport_no_bpf_masq_reply_lb_intercept_ipv4_check(const struct __ctx_buff *ctx)
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

	/* BUG: The reply packet was intercepted by the LB and DNAT'd to
	 * the backend, which is the same pod.  The pod will receive this
	 * packet with a wrong source port (rewritten by endpoint BPF to
	 * avoid CT 5-tuple collision).
	 */
	if (l3->daddr != BACKEND_IP)
		test_fatal("expected dst IP to be DNAT'd to backend (demonstrating the bug)");

	if (l4->dest != BACKEND_PORT)
		test_fatal("expected dst port to be DNAT'd to backend port");

	if (l4->source != EXT_PORT)
		test_fatal("src port has changed unexpectedly");

	test_finish();
}

/* --------------------------------------------------------------------------
 * Test 2: CT entry collision — the NodePort CT entry overwrites the pod's
 * original outgoing CT entry.
 *
 * Setup:
 *   1. Pre-populate the pod's outgoing CT entry:
 *      key = {daddr=EXT_IP, saddr=POD_IP, dport=10001, sport=9000, UDP, OUT}
 *      (lb4_extract_tuple convention: dport=pkt_src_port, sport=pkt_dst_port)
 *   2. Send reply: EXT_IP:9000 → NODE_IP:10001
 *
 * Expected: LB creates NodePort CT entry with the SAME key, overwriting
 * the pod's original entry.  The overwritten entry has node_port=1 and
 * rev_nat_index set to the LB service's revnat ID.
 * --------------------------------------------------------------------------
 */
PKTGEN("tc", "tc_nodeport_no_bpf_masq_ct_overwrite_ipv4")
int tc_nodeport_no_bpf_masq_ct_overwrite_ipv4_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "tc_nodeport_no_bpf_masq_ct_overwrite_ipv4")
int tc_nodeport_no_bpf_masq_ct_overwrite_ipv4_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	/* LB service: NODE_IP:10001 → POD_IP:10001 (backend = same pod). */
	lb_v4_add_service(NODE_IP, SVC_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v4_add_backend(NODE_IP, SVC_PORT, 1, 125,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_UDP, 0);

	endpoint_v4_add_entry(POD_IP, POD_IFACE, POD_EP_ID, 0, 0, 0,
			      (__u8 *)pod_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(POD_IP, 0, 112233, 0, 0);
	ipcache_v4_add_world_entry();

	/* Pre-populate the pod's original outgoing CT entry.
	 *
	 * When the pod sends POD_IP:10001 → EXT_IP:9000, the BPF egress
	 * path creates a CT entry with this key (l4_load_ports convention:
	 * dport = packet source port, sport = packet destination port):
	 *
	 *   {daddr=EXT_IP, saddr=POD_IP, dport=10001, sport=9000, UDP, OUT}
	 *
	 * This is the SAME key that nodeport_svc_lb4() will use for the
	 * NodePort CT entry after __ipv4_ct_tuple_reverse(DNAT'd tuple).
	 */
	struct ipv4_ct_tuple ct_key = {
		.daddr   = EXT_IP,
		.saddr   = POD_IP,
		.dport   = SVC_PORT,	/* 10001 — packet source port */
		.sport   = EXT_PORT,	/* 9000  — packet dest port */
		.nexthdr = IPPROTO_UDP,
		.flags   = TUPLE_F_OUT,
	};
	struct ct_entry ct_value = {};

	ct_value.lifetime = 0xFFFFFFFF;

	map_update_elem(&cilium_ct_any4_global, &ct_key, &ct_value, BPF_ANY);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_no_bpf_masq_ct_overwrite_ipv4")
int tc_nodeport_no_bpf_masq_ct_overwrite_ipv4_check(const struct __ctx_buff *ctx)
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

	assert(*status_code == CTX_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->daddr != BACKEND_IP)
		test_fatal("expected dst IP to be DNAT'd to backend");

	if (l4->dest != BACKEND_PORT)
		test_fatal("expected dst port to be DNAT'd to backend port");

	/* Verify the CT collision: the pod's original outgoing CT entry
	 * should now be overwritten with the NodePort entry.
	 *
	 * The original entry had node_port=0 and rev_nat_index=0.
	 * After overwrite, it should have node_port=1 and rev_nat_index
	 * set to the LB service's revnat ID.
	 */
	struct ipv4_ct_tuple ct_key = {
		.daddr   = EXT_IP,
		.saddr   = POD_IP,
		.dport   = SVC_PORT,
		.sport   = EXT_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags   = TUPLE_F_OUT,
	};
	struct ct_entry *entry = map_lookup_elem(&cilium_ct_any4_global, &ct_key);

	if (!entry)
		test_fatal("CT entry disappeared");

	if (!entry->node_port)
		test_fatal("CT entry was NOT overwritten: node_port flag not set");

	if (entry->rev_nat_index == 0)
		test_fatal("CT entry was NOT overwritten: rev_nat_index still 0");

	test_finish();
}
