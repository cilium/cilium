// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4			1
#define ENABLE_IPSEC			1
#define ENABLE_ENCRYPTED_OVERLAY	1

#define TUNNEL_MODE			1
#define TUNNEL_PROTOCOL			TUNNEL_PROTOCOL_VXLAN
#define TUNNEL_PORT			8472
#define ENCAP_IFINDEX			25

#define NODE1_IP			v4_ext_one
#define NODE1_TUNNEL_SPORT		1337

#define NODE2_IP			v4_ext_two
#define NODE1_SPI			5
#define NODE2_ID			123
#define NODE2_SPI			6

#define POD1_IP				v4_pod_one
#define POD1_IFACE			100
#define POD2_IP				v4_pod_two

#define POD1_SEC_IDENTITY		112233

static volatile const __u8 *node1_mac = mac_one;
static volatile const __u8 *node2_mac = mac_two;

static volatile const __u8 *pod1_mac = mac_three;
static volatile const __u8 *pod2_mac = mac_four;

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if ((__u32)ifindex != ctx->ifindex)
		return CTX_ACT_DROP;
	if (flags != BPF_F_INGRESS)
		return CTX_ACT_DROP;

	return CTX_ACT_REDIRECT;
}

#define SECCTX_FROM_IPCACHE 1

#include "bpf_host.c"

#include "lib/endpoint.h"
#include "lib/node.h"

#define TO_NETDEV	0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_NETDEV] = &cil_to_netdev,
	},
};

PKTGEN("tc", "tc_host_encrypted_overlay_01")
int host_encrypted_overlay_01_pktgen(struct __ctx_buff *ctx)
{
	struct vxlanhdr *vxlan;
	struct iphdr *inner_l3;
	struct pktgen builder;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	vxlan = pktgen__push_ipv4_vxlan_packet(&builder,
					       (__u8 *)node1_mac, (__u8 *)node2_mac,
					       NODE1_IP, NODE2_IP,
					       NODE1_TUNNEL_SPORT, TUNNEL_PORT);
	if (!vxlan)
		return TEST_ERROR;

	vxlan->vx_vni = sec_identity_to_tunnel_vni(ENCRYPTED_OVERLAY_ID);

	inner_l3 = pktgen__push_ipv4_packet(&builder,
					    (__u8 *)pod1_mac, (__u8 *)pod2_mac,
					    POD1_IP, POD2_IP);
	if (!inner_l3)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_host_encrypted_overlay_01")
int tc_host_encrypted_overlay_01_setup(struct __ctx_buff *ctx)
{
	struct encrypt_config encrypt_value = { .encrypt_key = NODE1_SPI };
	__u32 encrypt_key = 0;

	endpoint_v4_add_entry(POD1_IP, POD1_IFACE, 0, 0, POD1_SEC_IDENTITY,
			      (__u8 *)pod1_mac, (__u8 *)node1_mac);
	node_v4_add_entry(NODE2_IP, NODE2_ID, NODE2_SPI);
	map_update_elem(&ENCRYPT_MAP, &encrypt_key, &encrypt_value, BPF_ANY);

	set_identity_mark(ctx, ENCRYPTED_OVERLAY_ID, MARK_MAGIC_OVERLAY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_host_encrypted_overlay_01")
int tc_host_encrypted_overlay_01_check(const struct __ctx_buff *ctx)
{
	struct vxlanhdr *vxlan;
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
	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	vxlan = (void *)l4 + sizeof(*l4);
	if ((void *)vxlan + sizeof(*vxlan) > data_end)
		test_fatal("vxlan out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node1_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)node1_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC has not been updated")

	if (l3->saddr != NODE1_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != NODE2_IP)
		test_fatal("dst IP has changed");

	if (l3->check != bpf_htons(0x7da4))
		test_fatal("L3 checksum is invalid: %d", bpf_htons(l3->check));

	if (l4->source != NODE1_TUNNEL_SPORT)
		test_fatal("src port has changed");

	if (l4->dest != TUNNEL_PORT)
		test_fatal("dst port has changed");

	if (tunnel_vni_to_sec_identity(vxlan->vx_vni) != POD1_SEC_IDENTITY)
		test_fatal("VNI has not been updated");

	assert(ctx->mark == (or_encrypt_key(NODE1_SPI) | (NODE2_ID << 16)));
	assert(ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY) == POD1_SEC_IDENTITY);

	test_finish();
}
