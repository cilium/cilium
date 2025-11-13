// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define NODE_ID 7
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_WIREGUARD 1
#define CLUSTER_IDENTITY 0x5555
#define ENABLE_NODE_ENCRYPTION

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#include "lib/bpf_host.h"

#include "lib/node.h"
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
	/* We need to populate the node ID map because we'll lookup into it on
	 * ingress to validate the source
	 */
	node_v4_add_entry(v4_node_one, NODE_ID, 1);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "ipv4_not_decrypted_wireguard_from_netdev")
int ipv4_not_decrypted_wireguard_from_netdev_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct udphdr *l4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	/* packet goes up the stack for decryption */
	assert(*status_code == CTX_ACT_OK);

	/* we use this mark to skip conntrack for encrypted flows */
	assert((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 proto hasn't been set to ETH_P_IP");

	if (memcmp(l2->h_source, (__u8 *)mac_one, ETH_ALEN) != 0)
		test_fatal("not_decrypted: src mac hasn't been set to source node's mac");

	if (memcmp(l2->h_dest, (__u8 *)mac_two, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to dest node's mac");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != v4_node_one)
		test_fatal("src IP was changed");

	if (l3->daddr != v4_node_two)
		test_fatal("dest IP was changed");

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != bpf_htons(CONFIG(wg_port)) || l4->dest != bpf_htons(CONFIG(wg_port)))
		test_fatal("wrong port. expected src:%u dst:%u, got src:%u dst:%u",
			   bpf_htons(CONFIG(wg_port)), bpf_htons(CONFIG(wg_port)),
			  l4->source, l4->dest);

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
	/* We need to populate the node ID map because we'll lookup into it on
	 * ingress to validate the source
	 */
	node_v6_add_entry((union v6addr *)v6_node_one, NODE_ID, 1);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "ipv6_not_decrypted_wireguard_from_netdev")
int ipv6_not_decrypted_wireguard_from_netdev_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct udphdr *l4;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* packet goes up the stack for decryption */
	assert(*status_code == CTX_ACT_OK);

	/* we use this mark to skip conntrack for encrypted flows */
	assert((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IP");

	if (memcmp(l2->h_source, (__u8 *)mac_one, ETH_ALEN) != 0)
		test_fatal("not_decrypted: src mac hasn't been set to source node's mac");

	if (memcmp(l2->h_dest, (__u8 *)mac_two, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to dest node's mac");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (memcmp((__u8 *)&l3->saddr, (__u8 *)v6_node_one, 16) != 0)
		test_fatal("src IP was changed");

	if (memcmp((__u8 *)&l3->daddr, (__u8 *)v6_node_two, 16) != 0)
		test_fatal("dest IP was changed");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);

	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != bpf_htons(CONFIG(wg_port)) || l4->dest != bpf_htons(CONFIG(wg_port)))
		test_fatal("wrong port. expected src:%u dst:%u, got src:%u dst:%u",
			   bpf_htons(CONFIG(wg_port)), bpf_htons(CONFIG(wg_port)),
			  l4->source, l4->dest);

	test_finish();
}

/* end */

/* these tests below should not match wireguard traffic
 * anything that violates any of the conditions in the
 * block that tests with the real wireguard packets
 * we expect to see mark value not set to MARK_MAGIC_DECRYPT
 */

/* no identity */
PKTGEN("tc", "ipv4_not_decrypted_wireguard_from_netdev_no_identity")
int ipv4_not_decrypted_wireguard_from_netdev_no_identity_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V4_WIREGUARD_NO_ID, v4_wireguard);
	BUILDER_PUSH_BUF(builder, V4_WIREGUARD_NO_ID);

	pktgen__finish(&builder);
	return 0;
}

CHECK("tc", "ipv4_not_decrypted_wireguard_from_netdev_no_identity")
int ipv4_not_decrypted_wireguard_from_netdev_no_identity_check(const struct __ctx_buff *ctx)
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

	assert((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_DECRYPT);

	test_finish();
}

PKTGEN("tc", "ipv6_not_decrypted_wireguard_from_netdev_no_identity")
int ipv6_not_decrypted_wireguard_from_netdev_no_identity_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_WIREGUARD_NO_ID, v6_wireguard);
	BUILDER_PUSH_BUF(builder, V6_WIREGUARD_NO_ID);

	pktgen__finish(&builder);
	return 0;
}

CHECK("tc", "ipv6_not_decrypted_wireguard_from_netdev_no_identity")
int ipv6_not_decrypted_wireguard_from_netdev_no_identity_check(const struct __ctx_buff *ctx)
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

	assert((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_DECRYPT);

	test_finish();
}

/* port mismatch */
PKTGEN("tc", "ipv4_not_decrypted_wireguard_from_netdev_port_mismatch")
int ipv4_not_decrypted_wireguard_from_netdev_port_mismatch_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V4_WIREGUARD_SPORT_MISMATCH, v4_wireguard_sport_mismatch);
	BUILDER_PUSH_BUF(builder, V4_WIREGUARD_SPORT_MISMATCH);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv4_not_decrypted_wireguard_from_netdev_port_mismatch")
int ipv4_not_decrypted_wireguard_from_netdev_port_mismatch_setup(struct __ctx_buff *ctx)
{
	/* We need to populate the node ID map because we'll lookup into it on
	 * ingress to validate the source
	 */
	node_v4_add_entry(v4_node_one, NODE_ID, 1);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "ipv4_not_decrypted_wireguard_from_netdev_port_mismatch")
int ipv4_not_decrypted_wireguard_from_netdev_port_mismatch_check(const struct __ctx_buff *ctx)
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

	assert((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_DECRYPT);

	test_finish();
}

PKTGEN("tc", "ipv6_not_decrypted_wireguard_from_netdev_port_mismatch")
int ipv6_not_decrypted_wireguard_from_netdev_port_mismatch_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_WIREGUARD_SPORT_MISMATCH, v6_wireguard_sport_mismatch);
	BUILDER_PUSH_BUF(builder, V6_WIREGUARD_SPORT_MISMATCH);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv6_not_decrypted_wireguard_from_netdev_port_mismatch")
int ipv6_not_decrypted_wireguard_from_netdev_port_mismatch_setup(struct __ctx_buff *ctx)
{
	/* We need to populate the node ID map because we'll lookup into it on
	 * ingress to validate the source
	 */
	node_v6_add_entry((union v6addr *)v6_node_one, NODE_ID, 1);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "ipv6_not_decrypted_wireguard_from_netdev_port_mismatch")
int ipv6_not_decrypted_wireguard_from_netdev_port_mismatch_check(const struct __ctx_buff *ctx)
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

	assert((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_DECRYPT);

	test_finish();
}

/* protocol mismatch */

PKTGEN("tc", "ipv4_not_decrypted_wireguard_from_netdev_protocol_mismatch")
int ipv4_not_decrypted_wireguard_from_netdev_protocol_mismatch_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V4_WIREGUARD_PROTO_MISMATCH, v4_wireguard_proto_mismatch);
	BUILDER_PUSH_BUF(builder, V4_WIREGUARD_PROTO_MISMATCH);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv4_not_decrypted_wireguard_from_netdev_protocol_mismatch")
int ipv4_not_decrypted_wireguard_from_netdev_protocol_mismatch_setup(struct __ctx_buff *ctx)
{
	/* We need to populate the node ID map because we'll lookup into it on
	 * ingress to validate the source
	 */
	node_v4_add_entry(v4_node_one, NODE_ID, 1);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "ipv4_not_decrypted_wireguard_from_netdev_protocol_mismatch")
int ipv4_not_decrypted_wireguard_from_netdev_protocol_mismatch_check(const struct __ctx_buff *ctx)
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

	assert((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_DECRYPT);

	test_finish();
}

PKTGEN("tc", "ipv6_not_decrypted_wireguard_from_netdev_protocol_mismatch")
int ipv6_not_decrypted_wireguard_from_netdev_protocol_mismatch_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_WIREGUARD_PROTO_MISMATCH, v6_wireguard_proto_mismatch);
	BUILDER_PUSH_BUF(builder, V6_WIREGUARD_PROTO_MISMATCH);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv6_not_decrypted_wireguard_from_netdev_protocol_mismatch")
int ipv6_not_decrypted_wireguard_from_netdev_protocol_mismatch_setup(struct __ctx_buff *ctx)
{
	/* We need to populate the node ID map because we'll lookup into it on
	 * ingress to validate the source
	 */
	node_v6_add_entry((union v6addr *)v6_node_one, NODE_ID, 1);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "ipv6_not_decrypted_wireguard_from_netdev_protocol_mismatch")
int ipv6_not_decrypted_wireguard_from_netdev_protocol_mismatch_check(const struct __ctx_buff *ctx)
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

	assert((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_DECRYPT);

	test_finish();
}

/* end */
