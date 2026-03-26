/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright Authors of Cilium
 */

#ifdef ENABLE_WIREGUARD
# define NODE_SPI 255
#endif

#ifdef ENABLE_IPSEC
# define NODE_SPI 3
#endif

#define NODE_ID 7

#define ENABLE_IPV4
#define ENABLE_IPV6

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#include "lib/bpf_host.h"

#include "lib/node.h"
#include "scapy.h"

ASSIGN_CONFIG(__u16, wg_port, 51871)

int pktgen(struct __ctx_buff *ctx, bool ipv4)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

#ifdef ENABLE_WIREGUARD
	if (ipv4) {
		BUF_DECL(V4_WIREGUARD, v4_wireguard);
		BUILDER_PUSH_BUF(builder, V4_WIREGUARD);
	} else {
		BUF_DECL(V6_WIREGUARD, v6_wireguard);
		BUILDER_PUSH_BUF(builder, V6_WIREGUARD);
	}
#endif
#ifdef ENABLE_IPSEC
	if (ipv4) {
		BUF_DECL(V4_IPSEC, v4_ipsec);
		BUILDER_PUSH_BUF(builder, V4_IPSEC);
	} else {
		BUF_DECL(V6_IPSEC, v6_ipsec);
		BUILDER_PUSH_BUF(builder, V6_IPSEC);
	}
#endif

	pktgen__finish(&builder);
	return 0;
}

int setup(struct __ctx_buff *ctx, bool ipv4)
{
	if (ipv4)
		node_v4_add_entry(v4_node_one, NODE_ID, NODE_SPI);
	else
		node_v6_add_entry((union v6addr *)v6_node_one, NODE_ID, NODE_SPI);

	return netdev_receive_packet(ctx);
}

int check(const struct __ctx_buff *ctx, bool ipv4)
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

	assert(*status_code == CTX_ACT_OK);

	assert(ctx_is_decrypt(ctx));

#ifdef ENABLE_WIREGUARD
	if (ipv4) {
		BUF_DECL(EXPECTED_WG_PACKET_V4, v4_wireguard);
		ASSERT_CTX_BUF_OFF("v4_wg_pkt_ok", "Ether", ctx, sizeof(__u32),
				   EXPECTED_WG_PACKET_V4, sizeof(BUF(EXPECTED_WG_PACKET_V4)));
	} else {
		BUF_DECL(EXPECTED_WG_PACKET_V6, v6_wireguard);
		ASSERT_CTX_BUF_OFF("v6_wg_pkt_ok", "Ether", ctx, sizeof(__u32),
				   EXPECTED_WG_PACKET_V6, sizeof(BUF(EXPECTED_WG_PACKET_V6)));
	}
#endif
#ifdef ENABLE_IPSEC
	if (ipv4) {
		BUF_DECL(EXPECTED_IPSEC_PACKET_V4, v4_ipsec);
		ASSERT_CTX_BUF_OFF("v4_ipsec_pkt_ok", "Ether", ctx, sizeof(__u32),
				   EXPECTED_IPSEC_PACKET_V4, sizeof(BUF(EXPECTED_IPSEC_PACKET_V4)));
	} else {
		BUF_DECL(EXPECTED_IPSEC_PACKET_V6, v6_ipsec);
		ASSERT_CTX_BUF_OFF("v6_ipsec_pkt_ok", "Ether", ctx, sizeof(__u32),
				   EXPECTED_IPSEC_PACKET_V6, sizeof(BUF(EXPECTED_IPSEC_PACKET_V6)));
	}

#endif

	test_finish();
}

/* These tests validate that a real encrypted packet is handled properly.
 * For both WireGuard and IPSec, we expect the packet to not be modified,
 * and to be passed up the stack with the MARK_MAGIC_DECRYPT mark set.
 */
PKTGEN("tc", "encrypted_v4")
int encrypted_v4_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, true);
}

SETUP("tc", "encrypted_v4")
int encrypted_v4_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, true);
}

CHECK("tc", "encrypted_v4")
int encrypted_v4_check(const struct __ctx_buff *ctx)
{
	return check(ctx, true);
}

PKTGEN("tc", "encrypted_v6")
int encrypted_v6_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, false);
}

SETUP("tc", "encrypted_v6")
int encrypted_v6_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, false);
}

CHECK("tc", "encrypted_v6")
int encrypted_v6_check(const struct __ctx_buff *ctx)
{
	return check(ctx, false);
}
