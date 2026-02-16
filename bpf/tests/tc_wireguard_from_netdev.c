// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define WG_SPI 255
#define NODE_ID 7
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_WIREGUARD 1
#define ENABLE_NODE_ENCRYPTION

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#include "lib/bpf_host.h"

#include "lib/ipcache.h"
#include "scapy.h"

ASSIGN_CONFIG(__u16, wg_port, 51871)

/* these tests validate that a real wireguard packet is handled properly
 * we expect the packet to not be modified, and to be passed up the stack with
 * the MARK_MAGIC_DECRYPT mark in skb->mark.
 * conditions:
 *  - udp packet
 *  - source and dest ports == $wg_port
 *  - source node with a valid identity in the cluster
 */
PKTGEN("tc", "ipv4_not_decrypted_wireguard_from_netdev")
int ipv4_not_decrypted_wireguard_from_netdev_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V4_WIREGUARD, v4_wireguard);
	BUILDER_PUSH_BUF(builder, V4_WIREGUARD);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv4_not_decrypted_wireguard_from_netdev")
int ipv4_not_decrypted_wireguard_from_netdev_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry_with_flags(v4_node_one, 0, NODE_ID, 0, WG_SPI, false);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "ipv4_not_decrypted_wireguard_from_netdev")
int ipv4_not_decrypted_wireguard_from_netdev_check(const struct __ctx_buff *ctx)
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
	/* packet goes up the stack for decryption */
	assert(*status_code == CTX_ACT_OK);

	/* we use this mark to skip conntrack for encrypted flows */
	assert(ctx_is_decrypt(ctx));

	/*  make sure packet was not modified */
	/* declare the buffer where our expectation is (the same wireguard packet we injected) */
	BUF_DECL(EXPECTED_WG_PACKET_V4, v4_wireguard);
	/* call the assert, passing in the buffer we declared above and the proper offsets */
	ASSERT_CTX_BUF_OFF("v4_wg_pkt_ok", "Ether", ctx, sizeof(__u32),
			   EXPECTED_WG_PACKET_V4, sizeof(BUF(EXPECTED_WG_PACKET_V4)));

	test_finish();
}

PKTGEN("tc", "ipv6_not_decrypted_wireguard_from_netdev")
int ipv6_not_decrypted_wireguard_from_netdev_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_WIREGUARD, v6_wireguard);
	BUILDER_PUSH_BUF(builder, V6_WIREGUARD);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv6_not_decrypted_wireguard_from_netdev")
int ipv6_not_decrypted_wireguard_from_netdev_setup(struct __ctx_buff *ctx)
{
	ipcache_v6_add_entry_with_flags((union v6addr *)v6_node_one, 0, NODE_ID, 0, WG_SPI, false);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "ipv6_not_decrypted_wireguard_from_netdev")
int ipv6_not_decrypted_wireguard_from_netdev_check(const struct __ctx_buff *ctx)
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

	/* packet goes up the stack for decryption */
	assert(*status_code == CTX_ACT_OK);

	/* we use this mark to skip conntrack for encrypted flows */
	assert(ctx_is_decrypt(ctx));

	/*  make sure packet was not modified */
	/* declare the buffer where our expectation is (the same wireguard packet we injected) */
	BUF_DECL(EXPECTED_WG_PACKET_V6, v6_wireguard);
	/* call the assert, passing in the buffer we declared above and the proper offsets */
	ASSERT_CTX_BUF_OFF("v6_wg_pkt_ok", "Ether", ctx, sizeof(__u32),
			   EXPECTED_WG_PACKET_V6, sizeof(BUF(EXPECTED_WG_PACKET_V6)));

	test_finish();
}
