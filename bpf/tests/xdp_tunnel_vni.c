// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* The VXLAN VNI is 24 bits wide, so it cannot carry a node-local security
 * identity. These tests encapsulate a packet whose source identity comes out
 * of the ipcache, the way the from-host path feeds an encap, and then read the
 * literal VNI bytes back out of the packet cilium built. The XDP encoder writes
 * the VNI itself, so the bytes are there to look at; on the skb path the kernel
 * writes them, see from_host_tunnel_id.c.
 */

#include <bpf/ctx/xdp.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_NODEPORT_ACCELERATION
#define TUNNEL_MODE

#define ENCAP_IFINDEX		42

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define POD_IP			v4_pod_one_on_node_two
#define POD_PORT		__bpf_htons(8080)
#define POD_NODE_IP		v4_node_two
#define POD_ID			0xaabb

#define LOCAL_NODE_IP		v4_node_one

/* The first local identity a node allocates. Truncated to 24 bits it is
 * HOST_ID, which cil_from_overlay rejects with DROP_INVALID_IDENTITY.
 */
#define CIDR_ID			(IDENTITY_LOCAL_SCOPE_CIDR | 1)

/* Truncated to 24 bits this one is INGRESS_ID, a valid identity, so the peer
 * does not drop the packet at all: it enforces the wrong ingress policy.
 */
#define CIDR_ID_ALIAS		(IDENTITY_LOCAL_SCOPE_CIDR | INGRESS_ID)

#include "lib/bpf_xdp.h"
#include "lib/ipcache.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_VXLAN)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = LOCAL_NODE_IP })

#include "nodeport_defaults.h"

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *node_mac = mac_two;

struct encap_view {
	__u32 *status_code;
	struct iphdr *l3;
	struct udphdr *l4;
	struct vxlanhdr *vxlan;
	struct iphdr *inner_l3;
};

static __always_inline bool
encap_parse(const struct __ctx_buff *ctx, struct encap_view *view)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *inner_l2;
	struct ethhdr *l2;

	if (data + sizeof(__u32) > data_end)
		return false;

	view->status_code = data;

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(*l2) > data_end)
		return false;

	view->l3 = (void *)l2 + sizeof(*l2);
	if ((void *)view->l3 + sizeof(*view->l3) > data_end)
		return false;

	view->l4 = (void *)view->l3 + sizeof(*view->l3);
	if ((void *)view->l4 + sizeof(*view->l4) > data_end)
		return false;

	view->vxlan = (void *)view->l4 + sizeof(*view->l4);
	if ((void *)view->vxlan + sizeof(*view->vxlan) > data_end)
		return false;

	inner_l2 = (void *)view->vxlan + sizeof(*view->vxlan);
	if ((void *)inner_l2 + sizeof(*inner_l2) > data_end)
		return false;

	view->inner_l3 = (void *)inner_l2 + sizeof(*inner_l2);
	if ((void *)view->inner_l3 + sizeof(*view->inner_l3) > data_end)
		return false;

	return true;
}

static __always_inline int
tunnel_vni_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)node_mac,
					  CLIENT_IP, POD_IP,
					  CLIENT_PORT, POD_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* Give the source address a node-local identity in the ipcache, read it back
 * the way bpf_host does, and hand it to the tunnel encap.
 */
static __always_inline int
tunnel_vni_setup(struct __ctx_buff *ctx, __u32 identity)
{
	const struct remote_endpoint_info *info;
	__u32 src_sec_identity;
	int ifindex = 0;

	ipcache_v4_add_entry(CLIENT_IP, 0, identity, 0, 0);
	ipcache_v4_add_entry(POD_IP, 0, POD_ID, POD_NODE_IP, 0);

	info = lookup_ip4_remote_endpoint(CLIENT_IP, 0);
	if (!info)
		return TEST_ERROR;

	src_sec_identity = info->sec_identity;
	if (src_sec_identity != identity)
		return TEST_ERROR;

	info = lookup_ip4_remote_endpoint(POD_IP, 0);
	if (!info || !info->flag_has_tunnel_ep)
		return TEST_ERROR;

	return nodeport_add_tunnel_encap(ctx, CONFIG(ipv4_direct_routing).be32,
					 CLIENT_PORT, info, src_sec_identity,
					 (enum trace_reason)CT_NEW, 0, &ifindex,
					 bpf_htons(ETH_P_IP));
}

PKTGEN(PROG_TYPE, "xdp_tunnel_vni_cidr_id")
int tunnel_vni_cidr_id_pktgen(struct __ctx_buff *ctx)
{
	return tunnel_vni_pktgen(ctx);
}

SETUP(PROG_TYPE, "xdp_tunnel_vni_cidr_id")
int tunnel_vni_cidr_id_setup(struct __ctx_buff *ctx)
{
	return tunnel_vni_setup(ctx, CIDR_ID);
}

CHECK(PROG_TYPE, "xdp_tunnel_vni_cidr_id")
int tunnel_vni_cidr_id_check(const struct __ctx_buff *ctx)
{
	struct encap_view view;
	__be32 want_vni;
	__be32 got_vni;
	__u8 *vni_bytes;
	__u32 peer_id;

	test_init();

	if (!encap_parse(ctx, &view))
		test_fatal("encapsulated packet is truncated");

	TEST("encapsulated", {
		assert(*view.status_code == CTX_ACT_REDIRECT);

		if (view.l3->protocol != IPPROTO_UDP)
			test_fatal("outer IP is not UDP");
		if (view.l3->saddr != LOCAL_NODE_IP)
			test_fatal("outerSrcIP is not the local node");
		if (view.l3->daddr != POD_NODE_IP)
			test_fatal("outerDstIP is not the pod node");
		if (view.l4->dest != bpf_htons(CONFIG(tunnel_port)))
			test_fatal("outerDstPort is not the tunnel port");

		if (view.inner_l3->saddr != CLIENT_IP)
			test_fatal("innerSrcIP is not the client");
		if (view.inner_l3->daddr != POD_IP)
			test_fatal("innerDstIP is not the pod");
	});

	/* The three identity bytes of the VNI, in wire order, plus the
	 * reserved byte that follows them.
	 */
	TEST("vni-bytes", {
		vni_bytes = (__u8 *)&view.vxlan->vx_vni;

		if (vni_bytes[0] != 0 || vni_bytes[1] != 0 ||
		    vni_bytes[2] != WORLD_ID || vni_bytes[3] != 0)
			test_fatal("vni %lx %lx %lx rsvd %lx",
				   vni_bytes[0], vni_bytes[1], vni_bytes[2],
				   vni_bytes[3]);
	});

	TEST("vni-word", {
		want_vni = sec_identity_to_tunnel_vni(WORLD_ID);
		got_vni = view.vxlan->vx_vni;

		if (got_vni != want_vni)
			test_fatal("vni is %lx, want %lx",
				   bpf_ntohl(got_vni), bpf_ntohl(want_vni));
	});

	/* Same value, stated as the identity the peer reads back out. */
	TEST("vni-identity", {
		peer_id = tunnel_vni_to_sec_identity(view.vxlan->vx_vni);

		if (peer_id == HOST_ID)
			test_fatal("peer reads HOST_ID from vni %lx",
				   bpf_ntohl(view.vxlan->vx_vni));

		if (peer_id != WORLD_ID)
			test_fatal("peer reads id %lu, want %lu",
				   peer_id, (__u32)WORLD_ID);
	});

	test_finish();
}

PKTGEN(PROG_TYPE, "xdp_tunnel_vni_alias_id")
int tunnel_vni_alias_id_pktgen(struct __ctx_buff *ctx)
{
	return tunnel_vni_pktgen(ctx);
}

SETUP(PROG_TYPE, "xdp_tunnel_vni_alias_id")
int tunnel_vni_alias_id_setup(struct __ctx_buff *ctx)
{
	return tunnel_vni_setup(ctx, CIDR_ID_ALIAS);
}

CHECK(PROG_TYPE, "xdp_tunnel_vni_alias_id")
int tunnel_vni_alias_id_check(const struct __ctx_buff *ctx)
{
	struct encap_view view;
	__u32 peer_id;

	test_init();

	if (!encap_parse(ctx, &view))
		test_fatal("encapsulated packet is truncated");

	TEST("vni-identity-not-aliased", {
		assert(*view.status_code == CTX_ACT_REDIRECT);

		peer_id = tunnel_vni_to_sec_identity(view.vxlan->vx_vni);

		if (peer_id == INGRESS_ID)
			test_fatal("peer reads INGRESS_ID from vni %lx",
				   bpf_ntohl(view.vxlan->vx_vni));

		if (peer_id != WORLD_ID)
			test_fatal("peer reads id %lu, want %lu",
				   peer_id, (__u32)WORLD_ID);
	});

	test_finish();
}
