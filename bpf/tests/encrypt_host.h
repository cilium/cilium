/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright Authors of Cilium
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4			1
#define ENABLE_IPV6			1

#define SRC_POD_V4			v4_pod_one
#define DST_POD_V4			v4_pod_one_on_node_two
#define DST_POD_CIDR_V4			v4_pod_cidr_on_node_two

#define SRC_POD_V6			((const union v6addr *)v6_pod_one)
#define DST_POD_V6			((const union v6addr *)v6_pod_one_on_node_two)
#define DST_POD_CIDR_V6			((const union v6addr *)v6_pod_cidr_on_node_two)

#define SRC_POD_SEC_IDENTITY		(CIDR_IDENTITY_RANGE_START - 2)
#define DST_POD_SEC_IDENTITY		(CIDR_IDENTITY_RANGE_START - 3)

#define SRC_NODE_V4			v4_node_one
#define DST_NODE_V4			v4_node_two

#define SRC_NODE_V6			(const union v6addr *)v6_node_one
#define DST_NODE_V6			(const union v6addr *)v6_node_two

#define VXLAN_PORT			bpf_htons(8472)
#define GENERAL_PORT			bpf_htons(12134)

#define DST_NODE_ID			123
#define ENCRYPT_KEY			0xFF

#ifdef ENCRYPTION_STRICT_MODE_EGRESS
#define STRICT_IPV4_NET			IPV4(192, 168, 0, 0)
#define STRICT_IPV4_NET_SIZE		16
#endif

/* mock and record calls to ctx_redirect */
struct ctx_redirect_recorder {
	int ifindex;
	__u32 flags;
} rec;

int mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused, int ifindex, __u32 flags)
{
	rec.flags = flags;
	rec.ifindex = ifindex;
	return CTX_ACT_REDIRECT;
}

#define ctx_redirect mock_ctx_redirect

#include "lib/bpf_host.h"

#include "lib/ipcache.h"
#include "lib/ipsec.h"
#include "lib/node.h"

ASSIGN_CONFIG(bool, enable_identity_mark, true)

const union macaddr cilium_net_mac = { .addr = {0xce, 0x72, 0xa7, 0x03, 0x88, 0x57} };
ASSIGN_CONFIG(union macaddr, cilium_net_mac, cilium_net_mac)

ASSIGN_CONFIG(__u32, wg_ifindex, 42)

static __always_inline
int check(const struct __ctx_buff *ctx, __u32 expected_result)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == expected_result);

	if (expected_result == CTX_ACT_REDIRECT) {
#ifdef ENABLE_IPSEC
		union macaddr expected_l2_addr = CONFIG(cilium_net_mac);
		struct ethhdr *l2 = data + sizeof(*status_code);
		int i;

		if (data + sizeof(struct ethhdr) > data_end)
			test_fatal("packet too small for eth header");

		assert(ctx->mark == ipsec_encode_encryption_mark(ENCRYPT_KEY, DST_NODE_ID));

		for (i = 0; i < 6; i++)
			assert(l2->h_dest[i] == expected_l2_addr.addr[i]);

		/* With IPSec we redirect to cilium_net ingress. */
		assert(rec.flags == BPF_F_INGRESS);
		assert(rec.ifindex == (int)CONFIG(cilium_net_ifindex));
#endif
#ifdef ENABLE_WIREGUARD
		/* With WireGuard we redirect to cilium_wg0 egress. */
		assert(rec.flags == 0);
		assert(rec.ifindex == (int)CONFIG(wg_ifindex));
#endif
	}

	test_finish();
}

static __always_inline
int v4_build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
				      SRC_POD_V4, DST_POD_V4);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* Validate that if the destination endpoint is being torn down (and
 * its ipcache entry is missing), then the corresponding PodCIDR entry
 * is still sufficient to apply encryption for a pod-to-pod packet.
 */
PKTGEN("tc", "encrypt_v4_1_missing_dst")
int encrypt_v4_1_missing_dst_pktgen(struct __ctx_buff *ctx)
{
	return v4_build_packet(ctx);
}

SETUP("tc", "encrypt_v4_1_missing_dst")
int encrypt_v4_1_missing_dst_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry_with_mask_size(DST_POD_CIDR_V4, 0, WORLD_ID,
					    DST_NODE_V4, ENCRYPT_KEY,
					    v4_pod_cidr_size);

#ifdef ENABLE_IPSEC
	ipsec_set_encrypt_state(ENCRYPT_KEY);
	node_v4_add_entry(DST_NODE_V4, DST_NODE_ID, ENCRYPT_KEY);
#endif

	set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_IDENTITY);

	return netdev_send_packet(ctx);
}

CHECK("tc", "encrypt_v4_1_missing_dst")
int encrypt_v4_1_missing_dst_check(const struct __ctx_buff *ctx)
{
	return check(ctx, CTX_ACT_REDIRECT);
}

/* Validate the behavior for a terminating source endpoint.
 *
 * First we test *with* the sec identity in the mark. This should be
 * sufficient to trigger encryption, even if the endpoint's ipcache entry
 * is not available.
 */
PKTGEN("tc", "encrypt_v4_2_src_mark")
int encrypt_v4_2_src_mark_pktgen(struct __ctx_buff *ctx)
{
	return v4_build_packet(ctx);
}

SETUP("tc", "encrypt_v4_2_src_mark")
int encrypt_v4_2_src_mark_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(DST_POD_V4, 0, DST_POD_SEC_IDENTITY,
			     DST_NODE_V4, ENCRYPT_KEY);

	set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_IDENTITY);

	return netdev_send_packet(ctx);
}

CHECK("tc", "encrypt_v4_2_src_mark")
int encrypt_v4_2_src_mark_check(const struct __ctx_buff *ctx)
{
	return check(ctx, CTX_ACT_REDIRECT);
}

/* Now test *without* the identity in the mark. This should *not* trigger
 * encryption. Strict-Mode should capture the packet.
 */
PKTGEN("tc", "encrypt_v4_3_no_src_mark")
int encrypt_v4_3_no_src_mark_pktgen(struct __ctx_buff *ctx)
{
	return v4_build_packet(ctx);
}

SETUP("tc", "encrypt_v4_3_no_src_mark")
int encrypt_v4_3_no_src_mark_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK("tc", "encrypt_v4_3_no_src_mark")
int encrypt_v4_3_no_src_mark_check(const struct __ctx_buff *ctx)
{
#ifdef ENCRYPTION_STRICT_MODE_EGRESS
	return check(ctx, CTX_ACT_DROP);
#else
	return check(ctx, CTX_ACT_OK);
#endif
}

/* Finally test without the mark, but with the endpoint's ipcache entry: */
PKTGEN("tc", "encrypt_v4_4_no_src_mark_with_src_entry")
int encrypt_v4_4_no_src_mark_with_src_entry_pktgen(struct __ctx_buff *ctx)
{
	return v4_build_packet(ctx);
}

SETUP("tc", "encrypt_v4_4_no_src_mark_with_src_entry")
int encrypt_v4_4_no_src_mark_with_src_entry_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(SRC_POD_V4, 0, SRC_POD_SEC_IDENTITY,
			     0, ENCRYPT_KEY);

	return netdev_send_packet(ctx);
}

CHECK("tc", "encrypt_v4_4_no_src_mark_with_src_entry")
int encrypt_v4_4_no_src_mark_with_src_entry_check(const struct __ctx_buff *ctx)
{
	return check(ctx, CTX_ACT_REDIRECT);
}

/* IPv6 variants of the tests.*/

static __always_inline
int v6_build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6hdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv6_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
				      (__u8 *)SRC_POD_V6, (__u8 *)DST_POD_V6);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

PKTGEN("tc", "encrypt_v6_1_missing_dst")
int encrypt_v6_1_missing_dst_pktgen(struct __ctx_buff *ctx)
{
	return v6_build_packet(ctx);
}

SETUP("tc", "encrypt_v6_1_missing_dst")
int encrypt_v6_1_missing_dst_setup(struct __ctx_buff *ctx)
{
	ipcache_v6_add_entry_with_mask_size_ipv6_underlay(DST_POD_CIDR_V6, 0, WORLD_ID,
							  DST_NODE_V6, ENCRYPT_KEY,
							  v6_pod_cidr_size);

#ifdef ENABLE_IPSEC
	ipsec_set_encrypt_state(ENCRYPT_KEY);
	node_v6_add_entry(DST_NODE_V6, DST_NODE_ID, ENCRYPT_KEY);
#endif

	set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_IDENTITY);

	return netdev_send_packet(ctx);
}

CHECK("tc", "encrypt_v6_1_missing_dst")
int encrypt_v6_1_missing_dst_check(const struct __ctx_buff *ctx)
{
	return check(ctx, CTX_ACT_REDIRECT);
}

PKTGEN("tc", "encrypt_v6_2_src_mark")
int encrypt_v6_2_src_mark_pktgen(struct __ctx_buff *ctx)
{
	return v6_build_packet(ctx);
}

SETUP("tc", "encrypt_v6_2_src_mark")
int encrypt_v6_2_src_mark_setup(struct __ctx_buff *ctx)
{
	ipcache_v6_add_entry_ipv6_underlay(DST_POD_V6, 0, DST_POD_SEC_IDENTITY,
					   DST_NODE_V6, ENCRYPT_KEY);

	set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_IDENTITY);

	return netdev_send_packet(ctx);
}

CHECK("tc", "encrypt_v6_2_src_mark")
int encrypt_v6_2_src_mark_check(const struct __ctx_buff *ctx)
{
	return check(ctx, CTX_ACT_REDIRECT);
}

PKTGEN("tc", "encrypt_v6_3_no_src_mark")
int encrypt_v6_3_no_src_mark_pktgen(struct __ctx_buff *ctx)
{
	return v6_build_packet(ctx);
}

SETUP("tc", "encrypt_v6_3_no_src_mark")
int encrypt_v6_3_no_src_mark_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK("tc", "encrypt_v6_3_no_src_mark")
int encrypt_v6_3_no_src_mark_check(const struct __ctx_buff *ctx)
{
	return check(ctx, CTX_ACT_OK);
}

PKTGEN("tc", "encrypt_v6_4_no_src_mark_with_src_entry")
int encrypt_v6_4_no_src_mark_with_src_entry_pktgen(struct __ctx_buff *ctx)
{
	return v6_build_packet(ctx);
}

SETUP("tc", "encrypt_v6_4_no_src_mark_with_src_entry")
int encrypt_v6_4_no_src_mark_with_src_entry_setup(struct __ctx_buff *ctx)
{
	ipcache_v6_add_entry(SRC_POD_V6, 0, SRC_POD_SEC_IDENTITY,
			     0, ENCRYPT_KEY);

	return netdev_send_packet(ctx);
}

CHECK("tc", "encrypt_v6_4_no_src_mark_with_src_entry")
int encrypt_v6_4_no_src_mark_with_src_entry_check(const struct __ctx_buff *ctx)
{
	return check(ctx, CTX_ACT_REDIRECT);
}

#ifdef TUNNEL_MODE
PKTGEN("tc", "encrypt_v4_vxlan")
int encrypt_v4_vxlan_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *l3;
	struct vxlanhdr *vxlan __maybe_unused;

	pktgen__init(&builder, ctx);

	vxlan = pktgen__push_ipv4_vxlan_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
					       SRC_NODE_V4, DST_NODE_V4,
					       GENERAL_PORT, VXLAN_PORT);
	if (!vxlan)
		return TEST_ERROR;

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
				      SRC_POD_V4, DST_POD_V4);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "encrypt_v4_vxlan")
int encrypt_v4_vxlan_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_OVERLAY);

	return netdev_send_packet(ctx);
}

CHECK("tc", "encrypt_v4_vxlan")
int encrypt_v4_vxlan_check(const struct __ctx_buff *ctx)
{
	return check(ctx, CTX_ACT_REDIRECT);
}

PKTGEN("tc", "encrypt_v6_vxlan")
int encrypt_v6_vxlan_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct vxlanhdr *vxlan __maybe_unused;
	struct ipv6hdr *l3;

	pktgen__init(&builder, ctx);

	vxlan = pktgen__push_ipv6_vxlan_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
					       (__u8 *)SRC_NODE_V6, (__u8 *)DST_NODE_V6,
					       GENERAL_PORT, VXLAN_PORT);
	if (!vxlan)
		return TEST_ERROR;

	l3 = pktgen__push_ipv6_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
				      (__u8 *)SRC_POD_V6, (__u8 *)DST_POD_V6);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "encrypt_v6_vxlan")
int encrypt_v6_vxlan_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_OVERLAY);

	return netdev_send_packet(ctx);
}

CHECK("tc", "encrypt_v6_vxlan")
int encrypt_v6_vxlan_check(const struct __ctx_buff *ctx)
{
	return check(ctx, CTX_ACT_REDIRECT);
}
#endif
