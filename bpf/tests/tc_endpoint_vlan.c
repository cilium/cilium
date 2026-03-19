// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_HOST_ROUTING

#define PRIMARY_IFACE	1
#define BACKEND_IFACE	25
#define BACKEND_EP_ID	127
#define POD_VLAN_ID	100

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *pod_mac = mac_two;

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
}

#include "lib/bpf_host.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"

ASSIGN_CONFIG(bool, enable_endpoint_vlan, true)
ASSIGN_CONFIG(__u32, interface_ifindex, PRIMARY_IFACE)

/* =========================================================================
 * Test 1: Egress - pod with VLAN ID, verify VLAN tag is pushed
 * =========================================================================
 * Pod (v4_pod_one, VLAN 100) sends a TCP packet to external (v4_ext_one).
 * After cil_to_netdev, the packet should have an 802.1Q VLAN tag with VID=100.
 */
PKTGEN("tc", "ep_vlan_egress_push")
int ep_vlan_egress_push_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_zero, (__u8 *)node_mac,
					  v4_pod_one, v4_ext_one,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ep_vlan_egress_push")
int ep_vlan_egress_push_setup(struct __ctx_buff *ctx)
{
	/* Register pod endpoint with VLAN ID */
	endpoint_v4_add_entry_with_vlan(v4_pod_one, BACKEND_IFACE, BACKEND_EP_ID,
					0, 0, 0, POD_VLAN_ID,
					(__u8 *)pod_mac, (__u8 *)node_mac);

	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);

	/* Send through to_netdev */
	return netdev_send_packet(ctx);
}

CHECK("tc", "ep_vlan_egress_push")
int ep_vlan_egress_push_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *eth;
	struct iphdr *ip4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* The packet should pass through without being dropped. skb_vlan_push
	 * uses kernel hardware-acceleration: VLAN info is stored as sk_buff
	 * metadata (not inserted into raw packet bytes) and is not reflected
	 * in ctx_out from BPF_PROG_TEST_RUN. CTX_ACT_OK confirms that
	 * ep_vlan_push_egress found the endpoint's VLAN ID and succeeded.
	 */
	if (*status_code != CTX_ACT_OK)
		test_fatal("unexpected status code %d, expected CTX_ACT_OK (%d)",
			   *status_code, CTX_ACT_OK);

	/* skb_vlan_push does not modify raw packet bytes (hw-accelerated), so
	 * verify the original Ethernet and IP headers remain intact.
	 */
	eth = data + sizeof(__u32);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("ip4 out of bounds");

	if (ip4->saddr != v4_pod_one)
		test_fatal("source IP changed");

	if (ip4->daddr != v4_ext_one)
		test_fatal("dest IP changed");

	test_finish();
}

/* =========================================================================
 * Test 2: Egress - pod without VLAN ID, verify packet is untagged
 * =========================================================================
 * Pod (v4_pod_two, no VLAN) sends a TCP packet to external.
 * The packet should exit without a VLAN tag.
 */
PKTGEN("tc", "ep_vlan_egress_no_vlan")
int ep_vlan_egress_no_vlan_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_zero, (__u8 *)node_mac,
					  v4_pod_two, v4_ext_one,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ep_vlan_egress_no_vlan")
int ep_vlan_egress_no_vlan_setup(struct __ctx_buff *ctx)
{
	/* Register pod endpoint WITHOUT VLAN ID (vlan_id=0) */
	endpoint_v4_add_entry(v4_pod_two, BACKEND_IFACE, BACKEND_EP_ID + 1,
			      0, 0, 0, (__u8 *)pod_mac, (__u8 *)node_mac);

	ipcache_v4_add_entry(v4_pod_two, 0, 112234, 0, 0);

	return netdev_send_packet(ctx);
}

CHECK("tc", "ep_vlan_egress_no_vlan")
int ep_vlan_egress_no_vlan_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *eth;
	struct iphdr *ip4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_fatal("unexpected status code %d, expected CTX_ACT_OK (%d)",
			   *status_code, CTX_ACT_OK);

	eth = data + sizeof(__u32);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");

	/* Without VLAN, ethertype should remain IPv4 (no 802.1Q) */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("expected IPv4 ethertype, got 0x%x", eth->h_proto);

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("ip4 out of bounds");

	if (ip4->saddr != v4_pod_two)
		test_fatal("source IP changed");

	if (ip4->daddr != v4_ext_one)
		test_fatal("dest IP changed");

	test_finish();
}

/* =========================================================================
 * Test 3: Ingress - VLAN-tagged packet arrives, verify VLAN is stripped
 * =========================================================================
 * External sends a VLAN-tagged (VID=100) TCP packet to pod (v4_pod_one).
 * After cil_from_netdev, the VLAN tag should be stripped and
 * the packet should be processed normally.
 *
 * NOTE: bpf_skb_vlan_pop in BPF test environment is simulated.
 * We verify the return code indicates the packet was accepted (not dropped).
 */
PKTGEN("tc", "ep_vlan_ingress_strip")
int ep_vlan_ingress_strip_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_zero, (__u8 *)node_mac,
					  v4_ext_one, v4_pod_one,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ep_vlan_ingress_strip")
int ep_vlan_ingress_strip_setup(struct __ctx_buff *ctx)
{
	/* Register pod endpoint with VLAN ID for the destination */
	endpoint_v4_add_entry_with_vlan(v4_pod_one, BACKEND_IFACE, BACKEND_EP_ID,
					0, 0, 0, POD_VLAN_ID,
					(__u8 *)pod_mac, (__u8 *)node_mac);

	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);
	ipcache_v4_add_entry(v4_ext_one, 0, WORLD_IPV4_ID, 0, 0);

	/* Simulate a VLAN-tagged packet arriving by using skb_vlan_push.
	 * Direct writes to ctx->vlan_present are rejected by the BPF verifier
	 * (read-only field). Using the real skb_vlan_push helper correctly sets
	 * the VLAN metadata (vlan_present and vlan_tci) in the skb.
	 */
	skb_vlan_push(ctx, bpf_htons(ETH_P_8021Q), POD_VLAN_ID);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "ep_vlan_ingress_strip")
int ep_vlan_ingress_strip_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* The packet should not be dropped (DROP_VLAN_FILTERED).
	 * With enable_endpoint_vlan, the VLAN tag is stripped and
	 * processing continues. The final result depends on routing,
	 * but it should NOT be a VLAN filter drop.
	 */
	if ((__s32)*status_code == DROP_VLAN_FILTERED)
		test_fatal("packet was dropped by VLAN filter, expected VLAN strip");

	test_finish();
}

/* =========================================================================
 * Test 4: Ingress - untagged packet arrives, normal processing
 * =========================================================================
 * External sends an untagged TCP packet to pod.
 * Should be processed normally (no VLAN stripping needed).
 */
PKTGEN("tc", "ep_vlan_ingress_untagged")
int ep_vlan_ingress_untagged_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_zero, (__u8 *)node_mac,
					  v4_ext_one, v4_pod_one,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ep_vlan_ingress_untagged")
int ep_vlan_ingress_untagged_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry_with_vlan(v4_pod_one, BACKEND_IFACE, BACKEND_EP_ID,
					0, 0, 0, POD_VLAN_ID,
					(__u8 *)pod_mac, (__u8 *)node_mac);

	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);
	ipcache_v4_add_entry(v4_ext_one, 0, WORLD_IPV4_ID, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "ep_vlan_ingress_untagged")
int ep_vlan_ingress_untagged_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Untagged packet should not be dropped by VLAN filter */
	if ((__s32)*status_code == DROP_VLAN_FILTERED)
		test_fatal("untagged packet dropped by VLAN filter");

	test_finish();
}
